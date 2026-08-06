// Package blob stores attachment bytes on the filesystem.
//
// # Why not in Postgres
//
// docs/BACKEND.md §2.8. Shredding a file is one `unlink`; a deleted `BYTEA`
// persists in table bloat and in the write-ahead log until vacuum and WAL
// rotation catch up, which can be hours. For a service whose central control is
// that deleted data is *gone* (docs/THREAT_MODEL.md §3.1), "eventually
// unreachable through the query planner" is not the same guarantee.
//
// # What the server knows about a blob
//
// Its length. Nothing else. The bytes are encrypted by the client before they
// arrive, the content type is never recorded or trusted, and the id is a random
// capability rather than a name — so there is no filename, no extension, and
// nothing that could be interpreted by anything that later reads this directory.
//
// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
package blob

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/uuid"

	"cipher.relay/internal/logging"
)

// ErrNotFound is returned when no blob exists for an id.
var ErrNotFound = errors.New("blob: not found")

// ErrTooLarge is returned when an upload exceeds the cap.
var ErrTooLarge = errors.New("blob: too large")

// scrub removes the filesystem path from an error before it can be returned.
//
// # The path is the capability
//
// A blob's file name is its id (see [Store.path]), and that id is 122 bits of
// randomness delivered to the recipient inside the end-to-end ciphertext — it is
// the entire authorisation to read or delete the attachment (docs/BACKEND.md
// §2.8). Every error the os package produces here is a *[os.PathError]* or a
// *[os.LinkError] carrying that name, and every caller in internal/api and
// internal/sweep logs the failure as `slog.String("reason", err.Error())`.
//
// `reason` is not on the redaction denylist and must not be: it carries the
// operationally useful half of every error the relay logs, and denying it
// wholesale is how redaction gets switched off again (AUDIT R2). So the fix is
// here, at the only place that knows a path is sensitive, rather than in a
// denylist that would have to guess. AUDIT 5.28.
//
// # What survives
//
// The operation and the underlying syscall error — "unlink: permission denied",
// "open: no space left on device" — which is what an operator acts on. The
// rebuilt error still unwraps to the same errno, so [errors.Is] against
// [os.ErrNotExist] and friends is unaffected; [Store.Delete] and [Store.Open]
// both depend on that.
//
// The blob *root* is configuration rather than a secret, but it is removed too:
// a rule that keeps some paths and drops others is one that has to be reasoned
// about at every new call site, and the syscall error is the part being kept.
func scrub(err error) error {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return &os.PathError{Op: pathErr.Op, Path: logging.Placeholder, Err: pathErr.Err}
	}
	var linkErr *os.LinkError
	if errors.As(err, &linkErr) {
		return &os.LinkError{
			Op:  linkErr.Op,
			Old: logging.Placeholder,
			New: logging.Placeholder,
			Err: linkErr.Err,
		}
	}
	return err
}

// Store is a directory of blobs.
type Store struct {
	root string
	// tmp is on the same filesystem as root so the rename in Put is atomic. A
	// cross-device rename fails, and the fallback everyone writes — copy then
	// delete — is not atomic, which reintroduces exactly the partial-file
	// visibility the rename exists to prevent.
	tmp string
}

// Open prepares the directory, creating it if needed.
func Open(root string) (*Store, error) {
	tmp := filepath.Join(root, "tmp")
	// 0o700: nothing else on the host has any business reading this directory.
	// The bytes are already encrypted, so this is defence in depth rather than
	// the protection — but a permissive mode on a directory full of user data is
	// the kind of thing that is never noticed until it matters.
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return nil, fmt.Errorf("blob store: %w", scrub(err))
	}
	return &Store{root: root, tmp: tmp}, nil
}

// path returns the on-disk location for an id.
//
// Built from the *parsed* UUID's canonical string, never from caller-supplied
// text. That is what makes path traversal structurally impossible here rather
// than a matter of sanitising: a `uuid.UUID` cannot hold "../", so there is no
// input to escape.
//
// Two levels of fan-out from the first four hex digits. A single directory with
// every blob in it degrades on most filesystems and makes any directory listing
// an enumeration of the whole store.
func (s *Store) path(id uuid.UUID) string {
	h := id.String() // canonical 8-4-4-4-12 lowercase hex
	return filepath.Join(s.root, h[0:2], h[2:4], h)
}

// Put streams r into a new blob, stopping at maxBytes.
//
// # Written to a temporary file and renamed
//
// A blob must never be visible in a partial state. Writing in place would mean a
// client that disconnects mid-upload leaves a truncated file at the id the
// database is about to point at, and the recipient would download it and fail to
// decrypt — reporting a corrupt attachment for what was a network error.
//
// # The cap is enforced on the read, not on Content-Length
//
// A chunked upload declares no length, so a header check reads as protection
// while providing none. This reads one byte past the limit and refuses if it
// arrives, which is the only thing a client cannot lie about.
func (s *Store) Put(id uuid.UUID, r io.Reader, maxBytes int64) (int64, error) {
	final := s.path(id)
	if err := os.MkdirAll(filepath.Dir(final), 0o700); err != nil {
		return 0, fmt.Errorf("blob put: %w", scrub(err))
	}

	tmp, err := os.CreateTemp(s.tmp, "upload-*")
	if err != nil {
		return 0, fmt.Errorf("blob put: %w", scrub(err))
	}
	tmpName := tmp.Name()
	// Removed unless the rename below succeeds, so a failed upload leaves
	// nothing behind. os.Remove on a renamed path is a harmless ENOENT.
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	if err := tmp.Chmod(0o600); err != nil {
		return 0, fmt.Errorf("blob put: %w", scrub(err))
	}

	// maxBytes+1: if that many bytes arrive, the upload is over the limit.
	written, err := io.Copy(tmp, io.LimitReader(r, maxBytes+1))
	if err != nil {
		return 0, fmt.Errorf("blob put: %w", scrub(err))
	}
	if written > maxBytes {
		return 0, ErrTooLarge
	}
	if written == 0 {
		return 0, fmt.Errorf("blob put: %w", ErrTooLarge)
	}

	// fsync before rename. Without it the rename can reach the disk before the
	// contents do, so a power loss leaves a correctly-named, empty file — which
	// is worse than no file, because nothing will ever retry it.
	if err := tmp.Sync(); err != nil {
		return 0, fmt.Errorf("blob put: %w", scrub(err))
	}
	if err := tmp.Close(); err != nil {
		return 0, fmt.Errorf("blob put: %w", scrub(err))
	}
	if err := os.Rename(tmpName, final); err != nil {
		return 0, fmt.Errorf("blob put: %w", scrub(err))
	}
	// fsync the *directory* as well as the file. The two are separate durability
	// facts: `tmp.Sync` above makes the contents durable, and this makes the name
	// pointing at them durable. Without it a crash after the rename can leave the
	// bytes on disk with no directory entry — and by then the handler has written
	// an attachment row, so the relay answers a download with a 500 for a blob it
	// believes it has, forever, because nothing retries an upload that succeeded.
	if err := syncDir(filepath.Dir(final)); err != nil {
		return 0, fmt.Errorf("blob put: %w", scrub(err))
	}
	return written, nil
}

// syncDir flushes a directory's own entries to disk.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	// Sync first, then close, and report the Sync error in preference: a close
	// that succeeds says nothing about whether the entries reached the platter.
	err = d.Sync()
	if closeErr := d.Close(); err == nil {
		err = closeErr
	}
	return err
}

// Open returns the blob's contents. The caller closes it.
func (s *Store) Open(id uuid.UUID) (io.ReadSeekCloser, int64, error) {
	f, err := os.Open(s.path(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, ErrNotFound
	}
	if err != nil {
		return nil, 0, fmt.Errorf("blob open: %w", scrub(err))
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, fmt.Errorf("blob open: %w", scrub(err))
	}
	return f, info.Size(), nil
}

// Delete removes a blob. A blob that is already gone deletes successfully.
//
// Idempotent because the sweep and an explicit client delete can race, and
// because the row and the file are removed in two steps — so "already gone" is a
// normal state rather than an error worth reporting.
func (s *Store) Delete(id uuid.UUID) error {
	err := os.Remove(s.path(id))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("blob delete: %w", scrub(err))
	}
	return nil
}

// Exists reports whether the bytes are on disk.
//
// Test and sweep support. It exists so a test can assert a blob is *gone from
// the filesystem* rather than merely unreachable through the API — the same
// distinction that separates deletion from a soft-delete flag for messages.
func (s *Store) Exists(id uuid.UUID) bool {
	_, err := os.Stat(s.path(id))
	return err == nil
}
