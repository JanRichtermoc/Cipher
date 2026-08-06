// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
//
// AUDIT 5.28, the logging half: a blob's file name is its id, and its id is the
// whole capability to read or delete the attachment. Every error the os package
// produces here carries that name, and every caller logs the error text under a
// `reason` field the redactor deliberately does not deny — so an unlink that
// fails writes a live capability into the log of a service whose entire purpose
// is not retaining that kind of record.
//
// These tests are about the *error text*, not about the failure. The failures
// themselves are provoked the same way TestPutFailsWhenTheDirectoryCannotBeFlushed
// provokes its one: with a directory mode the process cannot satisfy.

package blob

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"cipher.relay/internal/logging"
)

// leakyID is deliberately unmistakable in a string: no other value in these
// tests can produce a false negative by accident.
var leakyID = uuid.MustParse("aabb0cde-1111-4000-8000-0123456789ab")

// assertCarriesNoPath fails when an error names the blob id, the store root, or
// any recognisable fragment of the path built from them.
func assertCarriesNoPath(t *testing.T, what string, err error, root string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected an error to inspect, got nil", what)
	}
	text := err.Error()

	for _, forbidden := range []string{
		leakyID.String(), // the capability itself
		root,             // the absolute store path
		"aabb0cde",       // the id's first block, i.e. a partial capability
		"/aa/bb/",        // the fan-out directories, which are derived from it
		"upload-",        // the temporary file prefix
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("%s: the error names %q, which reaches the log as `reason`: %s",
				what, forbidden, text)
		}
	}

	// The placeholder is the same one the logging package substitutes, so an
	// audit of the relay's output can search for one string rather than two.
	if !strings.Contains(text, logging.Placeholder) {
		t.Fatalf("%s: the path was removed but not marked as redacted: %s", what, text)
	}
}

// TestTheUnscrubbedErrorDoesNameTheBlob is the positive control.
//
// Every test below asserts an absence, and an absence is also what a test that
// looks at the wrong string produces. This proves the id really is in the raw os
// error, so "not found in the scrubbed error" is a fact about scrub rather than
// about the assertion (AUDIT R2).
func TestTheUnscrubbedErrorDoesNameTheBlob(t *testing.T) {
	s, root := testStore(t)

	raw := os.Remove(s.path(leakyID) + "/definitely-absent")
	if raw == nil {
		t.Fatal("expected the removal of a nonexistent path to fail")
	}
	if !strings.Contains(raw.Error(), leakyID.String()) {
		t.Fatalf("the premise of this whole file is wrong: a raw os error does "+
			"not name the path (root %s): %v", root, raw)
	}

	scrubbed := scrub(raw)
	if strings.Contains(scrubbed.Error(), leakyID.String()) {
		t.Fatalf("scrub left the id in place: %v", scrubbed)
	}
}

func TestDeleteReportsAFailureWithoutNamingTheBlob(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the directory permission this test relies on")
	}
	s, root := testStore(t)

	if _, err := s.Put(leakyID, strings.NewReader("ciphertext"), 1024); err != nil {
		t.Fatalf("put: %v", err)
	}

	// 0o500 — readable and searchable, not writable — so the file is still
	// visible and only the unlink can fail.
	dir := filepath.Dir(s.path(leakyID))
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	assertCarriesNoPath(t, "Delete", s.Delete(leakyID), root)
}

func TestOpenReportsAFailureWithoutNamingTheBlob(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the file permission this test relies on")
	}
	s, root := testStore(t)

	if _, err := s.Put(leakyID, strings.NewReader("ciphertext"), 1024); err != nil {
		t.Fatalf("put: %v", err)
	}
	// Unreadable file: present, so this is a permission error rather than the
	// ErrNotFound path, which returns a sentinel and never reaches scrub.
	if err := os.Chmod(s.path(leakyID), 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(s.path(leakyID), 0o600) })

	_, _, err := s.Open(leakyID)
	assertCarriesNoPath(t, "Open", err, root)
}

func TestPutReportsAFailureWithoutNamingTheBlob(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the directory permission this test relies on")
	}
	s, root := testStore(t)

	// The same isolating trick as TestPutFailsWhenTheDirectoryCannotBeFlushed:
	// 0o300 lets the rename land and refuses the directory open, so the flush is
	// the only step that can fail — and its error is a *os.PathError naming the
	// fan-out directory, which is derived from the id.
	sibling := uuid.MustParse("aabb0cde-2222-4000-8000-000000000002")
	if _, err := s.Put(sibling, strings.NewReader("one"), 1024); err != nil {
		t.Fatalf("first put: %v", err)
	}
	dir := filepath.Dir(s.path(leakyID))
	if err := os.Chmod(dir, 0o300); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	_, err := s.Put(leakyID, strings.NewReader("ciphertext"), 1024)
	assertCarriesNoPath(t, "Put", err, root)
}

// TestScrubPreservesTheUnderlyingError pins the two things callers depend on.
//
// Store.Open and Store.Delete both branch on errors.Is(err, os.ErrNotExist)
// before wrapping, but the sweep and the download handler branch on sentinels
// derived from what scrub returns — so a scrub that replaced the error instead
// of rebuilding it would turn "already gone" into a 500 and stop the retention
// sweep retrying.
func TestScrubPreservesTheUnderlyingError(t *testing.T) {
	raw := &os.PathError{Op: "unlink", Path: "/var/lib/cipher/blobs/aa/bb/" + leakyID.String(), Err: fs.ErrPermission}

	scrubbed := scrub(raw)
	if !errors.Is(scrubbed, fs.ErrPermission) {
		t.Fatalf("scrub dropped the underlying error: %v", scrubbed)
	}
	if !strings.Contains(scrubbed.Error(), "unlink") {
		t.Fatalf("scrub dropped the operation, which is the half an operator acts on: %v", scrubbed)
	}
	if !strings.Contains(scrubbed.Error(), "permission denied") {
		t.Fatalf("scrub dropped the syscall message: %v", scrubbed)
	}
}

// TestScrubHandlesALinkError covers os.Rename, whose error type is not PathError.
//
// Put renames the temporary file into place, and a *os.LinkError carries two
// paths — the second of which is the blob's final name. A scrub that only knew
// about PathError would pass every test above and leak here.
func TestScrubHandlesALinkError(t *testing.T) {
	raw := &os.LinkError{
		Op:  "rename",
		Old: "/var/lib/cipher/blobs/tmp/upload-123",
		New: "/var/lib/cipher/blobs/aa/bb/" + leakyID.String(),
		Err: fs.ErrPermission,
	}

	scrubbed := scrub(raw)
	if strings.Contains(scrubbed.Error(), leakyID.String()) {
		t.Fatalf("scrub left the id in a rename error: %v", scrubbed)
	}
	if !errors.Is(scrubbed, fs.ErrPermission) {
		t.Fatalf("scrub dropped the underlying error: %v", scrubbed)
	}
}

// TestScrubLeavesAPathlessErrorAlone keeps it from becoming a blanket redactor.
//
// io.Copy can fail with an error from the request body rather than from the
// filesystem, and that one carries no path and every reason to survive intact.
func TestScrubLeavesAPathlessErrorAlone(t *testing.T) {
	raw := errors.New("unexpected EOF reading the request body")
	if got := scrub(raw); got != raw {
		t.Fatalf("scrub rewrote an error that names no path: %v", got)
	}
}
