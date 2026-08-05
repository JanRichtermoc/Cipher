//go:build integration

// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
//
// AUDIT 5.27 — the handler/store boundary, where the API contract and what the
// code actually accepts had drifted apart.
//
// Every test here has a partner that proves the bound does not refuse a
// legitimate request. A bound written from a document rather than from what the
// client mints is a bound that fails correct traffic, and one that fails correct
// traffic gets deleted (AUDIT **R2**).

package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"cipher.relay/internal/api"
	"cipher.relay/internal/blob"
	"cipher.relay/internal/logging"
	"cipher.relay/internal/ratelimit"
	"cipher.relay/internal/store"
)

// boundsStack is fullStack, keeping the limiter and the blob root so a test can
// observe the quota bucket and the filesystem the handler writes to.
func boundsStack(t *testing.T) (http.Handler, *store.DB, *ratelimit.Limiter, string) {
	t.Helper()
	db := testDB(t)
	limiter := testLimiter(t)
	log := logging.New(io.Discard, slog.LevelError)

	root := t.TempDir()
	blobs, err := blob.Open(root)
	if err != nil {
		t.Fatalf("blob store: %v", err)
	}

	authHandler := api.NewAuthHandler(db, limiter, log)
	mux := http.NewServeMux()
	authHandler.Routes(mux)
	api.NewInviteHandler(db, limiter, authHandler, log).Routes(mux)
	api.NewKeysHandler(db, authHandler, log).Routes(mux)
	api.NewMessagesHandler(db, authHandler, log).Routes(mux)
	api.NewBlobsHandler(db, blobs, authHandler, log).Routes(mux)
	return mux, db, limiter, root
}

// --- One JSON value per request ---------------------------------------------

func TestRedeemRefusesATrailingSecondValue(t *testing.T) {
	// The smuggling shape, on the endpoint where it matters most: an invite is
	// single-use, so a body that reads as one code to this decoder and another
	// to anything else is a request whose meaning depends on the reader.
	h, db, _, _ := boundsStack(t)
	code := issue(t, db, time.Hour)
	key := base64.StdEncoding.EncodeToString(make([]byte, 33))

	first, _ := io.ReadAll(redeemBody(code.String(), key, 42))
	second, _ := io.ReadAll(redeemBody(code.String(), key, 43))

	rec := post(h, "203.0.113.90", strings.NewReader(string(first)+string(second)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("two JSON values: status %d, want 400", rec.Code)
	}

	// And the invite must be untouched, which is the reason the refusal matters:
	// a request the server could not read must not have spent anything.
	if rec := post(h, "203.0.113.91", redeemBody(code.String(), key, 42)); rec.Code != http.StatusCreated {
		t.Fatalf("the invite was consumed by a refused request: status %d", rec.Code)
	}
}

func TestAcknowledgeRefusesATrailingSecondValue(t *testing.T) {
	h, db, _, _ := boundsStack(t)
	_, token := enrol(t, h, db, "203.0.113.92")

	body := `{"ids":["` + uuid.NewString() + `"]}{"ids":[]}`
	rec := do(h, http.MethodPost, "/v1/messages/ack", token, "203.0.113.92",
		strings.NewReader(body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("two JSON values: status %d, want 400", rec.Code)
	}
}

func TestAcknowledgeAcceptsOneValue(t *testing.T) {
	// The positive control: the decoder change must not have broken the ordinary
	// request. Acknowledging an id that does not exist succeeds by design.
	h, db, _, _ := boundsStack(t)
	_, token := enrol(t, h, db, "203.0.113.93")

	body := `{"ids":["` + uuid.NewString() + `"]}`
	rec := do(h, http.MethodPost, "/v1/messages/ack", token, "203.0.113.93",
		strings.NewReader(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("one JSON value: status %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

// --- Registration ids are 14 bits -------------------------------------------

func TestRedeemRefusesARegistrationIdOutsideTheProtocolRange(t *testing.T) {
	// 0x4000 stored happily and produced an account no peer could open a session
	// with. 3000000000 exceeds PostgreSQL's INTEGER, so it reached the database
	// and came back as a 500 — a malformed request reported as a server fault.
	h, db, _, _ := boundsStack(t)
	key := base64.StdEncoding.EncodeToString(make([]byte, 33))

	// A distinct source per case: redemption is limited to 5/hour/IP (AUDIT
	// 5.15), so a loop from one address stops testing the bound and starts
	// testing the limiter — which is how the first version of this failed, with
	// a 429 on the sixth id.
	for i, id := range []uint32{0, 0x4000, 65536, 2147483648, 3000000000, 4294967295} {
		code := issue(t, db, time.Hour)
		from := fmt.Sprintf("203.0.113.%d", 140+i)
		rec := post(h, from, redeemBody(code.String(), key, id))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("registration id %d: status %d, want 400", id, rec.Code)
		}
	}
}

func TestRedeemAcceptsTheRegistrationIdBoundaries(t *testing.T) {
	// The positive control, at both ends of the range the client actually mints
	// from (`DeviceIdentity.registrationIdRange` is 1...0x3FFF).
	h, db, _, _ := boundsStack(t)
	key := base64.StdEncoding.EncodeToString(make([]byte, 33))

	for i, id := range []uint32{1, 0x3FFF} {
		code := issue(t, db, time.Hour)
		from := fmt.Sprintf("203.0.113.%d", 150+i)
		rec := post(h, from, redeemBody(code.String(), key, id))
		if rec.Code != http.StatusCreated {
			t.Fatalf("registration id %d: status %d, want 201: %s",
				id, rec.Code, rec.Body.String())
		}
	}
}

// --- Prekey ids are 24 bits --------------------------------------------------

func publishBody(keyID uint32) io.Reader {
	body := map[string]any{
		"signed_prekey": map[string]any{
			"key_id": 1, "public_key": b64(33, 0x05), "signature": b64(64, 0xAA),
		},
		"kyber_last_resort": map[string]any{
			"key_id": 1, "public_key": b64(1568, 0x08), "signature": b64(64, 0xBB),
		},
		"kyber_prekeys": []map[string]any{
			{"key_id": 2, "public_key": b64(1568, 0x09), "signature": b64(64, 0xCC)},
		},
		"one_time_prekeys": []map[string]any{
			{"key_id": keyID, "public_key": b64(33, 0x06)},
		},
	}
	raw, _ := json.Marshal(body)
	return strings.NewReader(string(raw))
}

func TestPublishRefusesAPreKeyIdAboveTheProtocolCeiling(t *testing.T) {
	// Above 2^24 the key is stored and then never usable, because a peer's
	// libsignal will not accept it in a bundle. Above INTEGER it is a 500.
	h, db, _, _ := boundsStack(t)
	_, token := enrol(t, h, db, "203.0.113.96")

	for _, id := range []uint32{0x1000000, 2147483648, 4294967295} {
		rec := do(h, http.MethodPut, "/v1/keys", token, "203.0.113.96", publishBody(id))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("prekey id %d: status %d, want 400", id, rec.Code)
		}
	}
}

func TestPublishAcceptsThePreKeyIdCeiling(t *testing.T) {
	// The positive control, at the exact ceiling the client will not exceed
	// (`CipherProtocolStore.maxPreKeyId` is 0xFFFFFF).
	h, db, _, _ := boundsStack(t)
	_, token := enrol(t, h, db, "203.0.113.97")

	rec := do(h, http.MethodPut, "/v1/keys", token, "203.0.113.97", publishBody(0xFFFFFF))
	if rec.Code != http.StatusOK {
		t.Fatalf("prekey id 0xFFFFFF: status %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

// --- The byte quota counts whole megabytes, rounded up -----------------------

// blobBytesLimitMirror mirrors api.blobBytesLimit, which is unexported.
//
// The assertions below compare a *delta* rather than an absolute remaining
// count, so this only has to agree with the handler about the bucket's shape;
// a capacity change in the handler shows up here as a failing delta rather than
// as a silently different measurement.
var blobBytesLimitMirror = ratelimit.Limit{Capacity: 500, Window: 24 * time.Hour}

func TestBlobQuotaChargesAPartialMegabyteAsAWholeOne(t *testing.T) {
	// `size >> 20` floored, so an upload of 1 MiB + 1 byte charged the single
	// megabyte taken before the write and nothing after it. Against a 500 MiB
	// daily allowance, a client uploading just under 2 MiB at a time spent half
	// of what it actually used.
	h, db, limiter, _ := boundsStack(t)
	aci, token := enrol(t, h, db, "203.0.113.98")

	ctx := context.Background()
	subject := limiter.Subject("blob-bytes", aci.String())

	before, err := limiter.Charge(ctx, subject, blobBytesLimitMirror, 0)
	if err != nil {
		t.Fatalf("probe the quota: %v", err)
	}

	upload(t, h, token, "203.0.113.98", randomBytes(1<<20+1))

	after, err := limiter.Charge(ctx, subject, blobBytesLimitMirror, 0)
	if err != nil {
		t.Fatalf("probe the quota: %v", err)
	}

	if charged := before.Remaining - after.Remaining; charged != 2 {
		t.Fatalf("an upload of 1 MiB + 1 byte charged %d megabytes, want 2", charged)
	}
}

func TestBlobQuotaChargesAWholeMegabyteOnce(t *testing.T) {
	// The positive control: rounding up must not double-charge a size that is
	// already a whole number of megabytes.
	h, db, limiter, _ := boundsStack(t)
	aci, token := enrol(t, h, db, "203.0.113.99")

	ctx := context.Background()
	subject := limiter.Subject("blob-bytes", aci.String())

	before, err := limiter.Charge(ctx, subject, blobBytesLimitMirror, 0)
	if err != nil {
		t.Fatalf("probe the quota: %v", err)
	}

	upload(t, h, token, "203.0.113.99", randomBytes(2<<20))

	after, err := limiter.Charge(ctx, subject, blobBytesLimitMirror, 0)
	if err != nil {
		t.Fatalf("probe the quota: %v", err)
	}

	if charged := before.Remaining - after.Remaining; charged != 2 {
		t.Fatalf("an upload of exactly 2 MiB charged %d megabytes, want 2", charged)
	}
}

// --- Deletion removes the bytes before the record of them --------------------

// blobFile finds the on-disk path of a stored blob by name.
//
// Walked rather than computed, so the store's fan-out layout stays its own
// business and this test does not encode a second copy of it.
func blobFile(t *testing.T, root string, id uuid.UUID) string {
	t.Helper()
	var found string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && d.Name() == id.String() {
			found = path
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk the blob root: %v", err)
	}
	if found == "" {
		t.Fatalf("no file named %s under %s", id, root)
	}
	return found
}

func TestBlobDeleteKeepsTheRowWhenTheBytesCannotBeRemoved(t *testing.T) {
	// The finding. With the row removed first, a failed unlink left ciphertext
	// on a host the threat model assumes is seizable, with nothing left that
	// could ever find it — not the sweep, not an operator, not a query.
	//
	// The unlink is made to fail by replacing the blob with a non-empty
	// directory: `os.Remove` refuses that with ENOTEMPTY for every user,
	// including root, which a permission bit would not.
	h, db, _, root := boundsStack(t)
	_, token := enrol(t, h, db, "203.0.113.100")

	id, _ := upload(t, h, token, "203.0.113.100", randomBytes(64))
	path := blobFile(t, root, id)

	if err := os.Remove(path); err != nil {
		t.Fatalf("clear the blob file: %v", err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("obstruct the blob path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(path, "occupant"), []byte("x"), 0o600); err != nil {
		t.Fatalf("obstruct the blob path: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(path) })

	rec := do(h, http.MethodDelete, "/v1/blobs/"+id.String(), token, "203.0.113.100", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("delete with an unremovable blob: status %d, want 500", rec.Code)
	}

	// The row must still be there, so the retention sweep retries at the TTL.
	// With the old ordering this reports false: the row was already gone and the
	// bytes were orphaned for good.
	deleted, err := db.DeleteAttachment(context.Background(), id)
	if err != nil {
		t.Fatalf("delete attachment row: %v", err)
	}
	if !deleted {
		t.Fatal("the row was removed even though the bytes could not be, orphaning them")
	}
}

func TestBlobDeleteRemovesBothWhenItSucceeds(t *testing.T) {
	// The positive control: the ordinary delete must still remove everything, or
	// the test above is passing against an endpoint that never works.
	h, db, _, root := boundsStack(t)
	_, token := enrol(t, h, db, "203.0.113.101")

	id, _ := upload(t, h, token, "203.0.113.101", randomBytes(64))
	path := blobFile(t, root, id)

	rec := do(h, http.MethodDelete, "/v1/blobs/"+id.String(), token, "203.0.113.101", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: status %d, want 204", rec.Code)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the bytes survived a successful delete: %v", err)
	}
	deleted, err := db.DeleteAttachment(context.Background(), id)
	if err != nil {
		t.Fatalf("delete attachment row: %v", err)
	}
	if deleted {
		t.Fatal("the row survived a successful delete")
	}
}
