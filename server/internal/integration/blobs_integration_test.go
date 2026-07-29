//go:build integration

// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
//
// P4.S09's "Done when": the server rejects oversize uploads and stores no
// content type it trusts. Its anti-goal is "content scanning theatre".
//
// The properties worth testing here are mostly absences — no owner recorded, no
// content type echoed, no filename anywhere — and an absence is only
// demonstrable against the real store, because the question is what ended up on
// the disk and in the table rather than what the API said.

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"cipher.relay/internal/api"
	"cipher.relay/internal/blob"
	"cipher.relay/internal/logging"
	"cipher.relay/internal/store"
	"cipher.relay/internal/sweep"
)

func blobStack(t *testing.T) (http.Handler, *store.DB, *blob.Store, string) {
	t.Helper()
	db := testDB(t)
	limiter := testLimiter(t)
	log := logging.New(io.Discard, slog.LevelError)

	// A directory per test, so one test's bytes cannot satisfy another's
	// assertion about absence.
	root := t.TempDir()
	blobs, err := blob.Open(root)
	if err != nil {
		t.Fatalf("blob store: %v", err)
	}

	authHandler := api.NewAuthHandler(db, limiter, log)
	mux := http.NewServeMux()
	authHandler.Routes(mux)
	api.NewInviteHandler(db, limiter, authHandler, log).Routes(mux)
	api.NewBlobsHandler(db, blobs, authHandler, log).Routes(mux)
	return mux, db, blobs, root
}

// upload posts bytes and returns the slot id.
func upload(t *testing.T, h http.Handler, token, from string, body []byte) (uuid.UUID, int64) {
	t.Helper()
	rec := do(h, http.MethodPost, "/v1/blobs", token, from, bytes.NewReader(body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload: status %d: %s", rec.Code, rec.Body.String())
	}
	var got struct {
		ID   string `json:"id"`
		Size int64  `json:"size"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return uuid.MustParse(got.ID), got.Size
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((i*7 + 13) % 251)
	}
	return b
}

// --- Round trip ------------------------------------------------------------

func TestBlobRoundTrip(t *testing.T) {
	h, db, _, _ := blobStack(t)
	_, token := enrol(t, h, db, "198.51.100.130")

	payload := randomBytes(64 * 1024)
	id, size := upload(t, h, token, "198.51.100.130", payload)
	if size != int64(len(payload)) {
		t.Fatalf("recorded size %d, want %d", size, len(payload))
	}

	rec := do(h, http.MethodGet, "/v1/blobs/"+id.String(), token, "198.51.100.130", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("download: status %d", rec.Code)
	}
	// Byte-identical. The relay stores opaque bytes; any difference means
	// something in the path is transforming them.
	if !bytes.Equal(rec.Body.Bytes(), payload) {
		t.Fatal("the downloaded blob differs from the one uploaded")
	}
}

// request builds an authenticated request so a test can set its own headers.
func request(method, path, token, from string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, path, body)
	r.RemoteAddr = from + ":54321"
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

func serve(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// --- Size limits -----------------------------------------------------------

func TestOversizeUploadIsRejected(t *testing.T) {
	// P4.S09's gate. The cap is applied on the read, not on Content-Length: a
	// chunked upload declares no length, so a header check reads as protection
	// while providing none.
	h, db, blobs, root := blobStack(t)
	_, token := enrol(t, h, db, "198.51.100.131")

	oversize := make([]byte, api.MaxBlobBytes+1)
	rec := do(h, http.MethodPost, "/v1/blobs", token, "198.51.100.131", bytes.NewReader(oversize))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413", rec.Code)
	}

	// And it left nothing behind. A rejected upload that keeps its temporary
	// file is a disk-exhaustion primitive with a 413 in front of it.
	if n := countFiles(t, root); n != 0 {
		t.Fatalf("a rejected upload left %d files on disk", n)
	}
	_ = blobs
}

func TestEmptyUploadIsRejected(t *testing.T) {
	h, db, _, root := blobStack(t)
	_, token := enrol(t, h, db, "198.51.100.132")

	rec := do(h, http.MethodPost, "/v1/blobs", token, "198.51.100.132", bytes.NewReader(nil))
	if rec.Code == http.StatusCreated {
		t.Fatal("an empty upload was accepted")
	}
	if n := countFiles(t, root); n != 0 {
		t.Fatalf("a rejected upload left %d files on disk", n)
	}
}

// countFiles counts regular files under root, ignoring the tmp directory's
// existence but not its contents — a leftover temporary file is exactly the
// thing worth catching.
func countFiles(t *testing.T, root string) int {
	t.Helper()
	var n int
	err := filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			n++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return n
}

// --- The server records nothing about the content --------------------------

func TestTheSlotRecordsOnlySizeAndExpiry(t *testing.T) {
	// docs/BACKEND.md §2.8: no owner, no recipient, no content type, no filename.
	// Asserted against information_schema rather than the migration, so a column
	// added later is caught by the same test.
	ctx := context.Background()
	h, db, _, _ := blobStack(t)
	_, token := enrol(t, h, db, "198.51.100.133")
	upload(t, h, token, "198.51.100.133", randomBytes(1024))

	cols, err := db.ColumnsOf(ctx, "attachments")
	if err != nil {
		t.Fatalf("columns: %v", err)
	}
	want := map[string]bool{"id": true, "size_bytes": true, "expires_at": true}
	for _, c := range cols {
		if !want[c] {
			t.Errorf("the attachments table has a %q column — the id is the "+
				"capability and nothing about the uploader, the recipient or the "+
				"content is recorded (BACKEND.md §2.8)", c)
		}
	}
	if len(cols) != len(want) {
		t.Errorf("attachments has %d columns, want %d: %v", len(cols), len(want), cols)
	}
}

func TestContentTypeIsNeverEchoed(t *testing.T) {
	// A content type echoed from upload is an attacker-chosen instruction to
	// whatever eventually renders the bytes. The server cannot know what these
	// are — they are ciphertext — so it says so.
	h, db, _, _ := blobStack(t)
	_, token := enrol(t, h, db, "198.51.100.134")

	req := request(http.MethodPost, "/v1/blobs", token, "198.51.100.134",
		bytes.NewReader(randomBytes(512)))
	req.Header.Set("Content-Type", "text/html; charset=utf-8")
	rec := serve(h, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload: %d", rec.Code)
	}
	var got struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &got)

	dl := do(h, http.MethodGet, "/v1/blobs/"+got.ID, token, "198.51.100.134", nil)
	if ct := dl.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want application/octet-stream", ct)
	}
	if cd := dl.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Errorf("Content-Disposition = %q, want attachment", cd)
	}
}

func TestNoFilenameReachesTheDisk(t *testing.T) {
	// There is no filename parameter and there must be no way to introduce one:
	// a name on disk is metadata the server was not given and cannot verify, and
	// a name derived from client input is a path-traversal surface.
	h, db, _, root := blobStack(t)
	_, token := enrol(t, h, db, "198.51.100.135")
	id, _ := upload(t, h, token, "198.51.100.135", randomBytes(256))

	var names []string
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			names = append(names, filepath.Base(p))
		}
		return nil
	})
	if len(names) != 1 {
		t.Fatalf("expected exactly one file on disk, got %v", names)
	}
	// The only name is the capability itself.
	if names[0] != id.String() {
		t.Fatalf("the file is named %q, want the blob id", names[0])
	}
}

// --- Deletion --------------------------------------------------------------

func TestDeleteRemovesRowAndBytes(t *testing.T) {
	ctx := context.Background()
	h, db, blobs, _ := blobStack(t)
	_, token := enrol(t, h, db, "198.51.100.136")
	id, _ := upload(t, h, token, "198.51.100.136", randomBytes(2048))

	if !blobs.Exists(id) {
		t.Fatal("the bytes are not on disk after upload")
	}

	rec := do(h, http.MethodDelete, "/v1/blobs/"+id.String(), token, "198.51.100.136", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: status %d", rec.Code)
	}

	// Gone from both, not merely unreachable through the API.
	present, err := db.AttachmentExists(ctx, id)
	if err != nil {
		t.Fatalf("exists: %v", err)
	}
	if present {
		t.Fatal("the attachment row survived deletion")
	}
	if blobs.Exists(id) {
		t.Fatal("the blob bytes survived deletion")
	}
}

func TestDeleteIsIdempotent(t *testing.T) {
	h, db, _, _ := blobStack(t)
	_, token := enrol(t, h, db, "198.51.100.137")
	id, _ := upload(t, h, token, "198.51.100.137", randomBytes(128))

	for i := range 2 {
		rec := do(h, http.MethodDelete, "/v1/blobs/"+id.String(), token, "198.51.100.137", nil)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("delete %d: status %d", i, rec.Code)
		}
	}
	rec := do(h, http.MethodDelete, "/v1/blobs/"+uuid.NewString(), token, "198.51.100.137", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("deleting an unknown id: status %d, want 204", rec.Code)
	}
}

// --- Expiry ----------------------------------------------------------------

func TestExpiredSlotIsNotServedEvenBeforeTheSweep(t *testing.T) {
	// The row is consulted before the file, so a lapsed slot is refused
	// immediately rather than staying available for up to one sweep interval.
	ctx := context.Background()
	h, db, _, _ := blobStack(t)
	_, token := enrol(t, h, db, "198.51.100.138")
	id, _ := upload(t, h, token, "198.51.100.138", randomBytes(512))

	if err := db.ExpireAttachmentNow(ctx, id); err != nil {
		t.Fatalf("expire: %v", err)
	}

	rec := do(h, http.MethodGet, "/v1/blobs/"+id.String(), token, "198.51.100.138", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("an expired slot was served: status %d", rec.Code)
	}
}

func TestSweepRemovesExpiredBlobsFromDiskAndTable(t *testing.T) {
	ctx := context.Background()
	h, db, blobs, _ := blobStack(t)
	_, token := enrol(t, h, db, "198.51.100.139")

	stale, _ := upload(t, h, token, "198.51.100.139", randomBytes(1024))
	live, _ := upload(t, h, token, "198.51.100.139", randomBytes(1024))
	if err := db.ExpireAttachmentNow(ctx, stale); err != nil {
		t.Fatalf("expire: %v", err)
	}

	s := sweep.New(db, blobs, logging.New(io.Discard, slog.LevelError), time.Hour)
	runCtx, cancel := context.WithCancel(ctx)
	go s.Run(runCtx)
	defer cancel()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		present, err := db.AttachmentExists(ctx, stale)
		if err != nil {
			t.Fatalf("exists: %v", err)
		}
		if !present && !blobs.Exists(stale) {
			// The live one must survive: a sweep that removes everything passes
			// a naive assertion while destroying the service.
			if !blobs.Exists(live) {
				t.Fatal("the sweep removed a live blob")
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the sweep did not remove the expired blob (row=%v disk=%v)",
		mustExist(t, db, stale), blobs.Exists(stale))
}

func mustExist(t *testing.T, db *store.DB, id uuid.UUID) bool {
	t.Helper()
	present, err := db.AttachmentExists(context.Background(), id)
	if err != nil {
		t.Fatalf("exists: %v", err)
	}
	return present
}

// --- Authentication and probing -------------------------------------------

func TestBlobRoutesRequireAuthentication(t *testing.T) {
	// The id is the capability, but the routes still need a session: without one
	// the download limit is unenforceable and the store is on the open internet,
	// so an id leaked into a proxy log would be fetchable by anyone at any rate.
	h, db, _, _ := blobStack(t)
	_, token := enrol(t, h, db, "198.51.100.140")
	id, _ := upload(t, h, token, "198.51.100.140", randomBytes(128))

	for name, code := range map[string]int{
		"upload":   do(h, http.MethodPost, "/v1/blobs", "", "198.51.100.141", bytes.NewReader(randomBytes(64))).Code,
		"download": do(h, http.MethodGet, "/v1/blobs/"+id.String(), "", "198.51.100.141", nil).Code,
		"delete":   do(h, http.MethodDelete, "/v1/blobs/"+id.String(), "", "198.51.100.141", nil).Code,
	} {
		if code != http.StatusUnauthorized {
			t.Errorf("unauthenticated %s: status %d, want 401", name, code)
		}
	}
}

func TestUnknownAndMalformedIDsAreIndistinguishable(t *testing.T) {
	h, db, _, _ := blobStack(t)
	_, token := enrol(t, h, db, "198.51.100.142")

	unknown := do(h, http.MethodGet, "/v1/blobs/"+uuid.NewString(), token, "198.51.100.142", nil)
	malformed := do(h, http.MethodGet, "/v1/blobs/not-a-uuid", token, "198.51.100.142", nil)
	traversal := do(h, http.MethodGet, "/v1/blobs/..%2F..%2Fetc%2Fpasswd", token, "198.51.100.142", nil)

	for name, rec := range map[string]int{
		"malformed": malformed.Code,
		"traversal": traversal.Code,
	} {
		if rec != unknown.Code {
			t.Errorf("%s gives %d, unknown gives %d — these must match",
				name, rec, unknown.Code)
		}
	}
	if unknown.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", unknown.Code)
	}
}

func TestPathTraversalCannotEscapeTheBlobDirectory(t *testing.T) {
	// The on-disk path is built from a *parsed* UUID, so there is nothing to
	// escape: a uuid.UUID cannot hold "../". This asserts the property rather
	// than any sanitising, because sanitising is exactly what is absent.
	//
	// Not every attempt reaches the handler, and that is worth being precise
	// about rather than asserting a uniform 404. http.ServeMux redirects when a
	// path is not already clean, so "/v1/blobs/..//..//etc/passwd" gets a 301 to
	// path.Clean's result — which is "/etc/passwd", genuinely outside the route
	// prefix. That is harmless: it is a URL with no registered handler, so it
	// 404s, and nothing turns a redirect target into a filesystem read. What
	// matters is that no attempt ever yields 200 or any bytes.
	h, db, _, root := blobStack(t)
	_, token := enrol(t, h, db, "198.51.100.143")

	// Percent-encoded and single-segment: these reach the handler, where
	// uuid.Parse refuses them, and must be indistinguishable from an unknown id.
	for _, attempt := range []string{
		"..%2F..%2F..%2Fetc%2Fpasswd",
		"%2e%2e%2f%2e%2e%2fpasswd",
		"....%2F....%2Fetc%2Fpasswd",
	} {
		rec := do(h, http.MethodGet, "/v1/blobs/"+attempt, token, "198.51.100.143", nil)
		if rec.Code != http.StatusNotFound {
			t.Errorf("traversal %q: status %d, want 404", attempt, rec.Code)
		}
	}

	// Literal separators: the mux may redirect first. Any non-200 is acceptable;
	// content is not.
	for _, attempt := range []string{
		"....//....//etc/passwd",
		"..//..//etc/passwd",
		"../../../etc/passwd",
	} {
		rec := do(h, http.MethodGet, "/v1/blobs/"+attempt, token, "198.51.100.143", nil)
		if rec.Code == http.StatusOK {
			t.Errorf("traversal %q returned 200", attempt)
		}
		if len(rec.Body.Bytes()) > 0 && rec.Header().Get("Content-Type") == "application/octet-stream" {
			t.Errorf("traversal %q returned blob content", attempt)
		}
		// A redirect must stay on this host and must not become a fetch of
		// something else the API serves.
		if loc := rec.Header().Get("Location"); loc != "" {
			if strings.HasPrefix(loc, "http://") || strings.HasPrefix(loc, "https://") ||
				strings.HasPrefix(loc, "//") {
				t.Errorf("traversal %q redirects off-host to %q", attempt, loc)
			}
		}
	}

	// And nothing was created or read outside the store.
	if n := countFiles(t, root); n != 0 {
		t.Fatalf("traversal attempts created %d files", n)
	}
}

func TestUploadIsRateLimited(t *testing.T) {
	h, db, _, _ := blobStack(t)
	_, token := enrol(t, h, db, "198.51.100.144")

	var throttled bool
	for i := range 130 {
		rec := do(h, http.MethodPost, "/v1/blobs", token, "198.51.100.144",
			bytes.NewReader(randomBytes(64)))
		if rec.Code == http.StatusTooManyRequests {
			throttled = true
			if i < 100 {
				t.Errorf("throttled after %d uploads; capacity is 100", i)
			}
			break
		}
		if rec.Code != http.StatusCreated {
			t.Fatalf("upload %d: status %d", i, rec.Code)
		}
	}
	if !throttled {
		t.Fatal("uploading was never throttled")
	}
}
