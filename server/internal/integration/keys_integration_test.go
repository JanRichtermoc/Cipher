//go:build integration

// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
//
// P4.S05's "Done when": a non-PQ bundle is rejected by the server.
// P4.S06's "Done when": a fetch flood is throttled.
//
// The second is the one that needs arguing. A rate limit usually protects
// capacity; this one protects a cryptographic property. Every fetch consumes one
// of the target's one-time prekeys, so an unthrottled directory lets any
// authenticated caller drain any peer's pool by asking — no message sent, no
// interaction with the victim. AUDIT 3.1.

package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"cipher.relay/internal/api"
	"cipher.relay/internal/logging"
	"cipher.relay/internal/store"
)

func keysStack(t *testing.T) (http.Handler, *store.DB, *api.AuthHandler) {
	t.Helper()
	return keysStackWithCeiling(t, api.DefaultMaxPreKeysPerAccount)
}

// keysStackWithCeiling is keysStack with an explicit per-account one-time pool
// ceiling (AUDIT 5.40).
//
// The production ceiling is 1,000 per pool and MaxPreKeysPerUpload is 200, so
// reaching it honestly costs five publications against a limit of six a day — a
// test that did it would be measuring the rate limiter as much as the ceiling.
// A small ceiling measures the mechanism instead.
func keysStackWithCeiling(t *testing.T, maxPerPool int) (http.Handler, *store.DB, *api.AuthHandler) {
	t.Helper()
	db := testDB(t)
	limiter := testLimiter(t)
	log := logging.New(io.Discard, slog.LevelError)

	authHandler := api.NewAuthHandler(db, limiter, log)
	mux := http.NewServeMux()
	authHandler.Routes(mux)
	api.NewInviteHandler(db, limiter, authHandler, log).Routes(mux)
	api.NewKeysHandler(db, authHandler, log, api.WithPreKeyCeiling(maxPerPool)).Routes(mux)
	return mux, db, authHandler
}

func b64(n int, fill byte) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = fill
	}
	return base64.StdEncoding.EncodeToString(b)
}

// uploadBody builds a well-formed publish request with `count` keys in each pool.
func uploadBody(count int, withKyber bool) io.Reader {
	return uploadBodyPools(count, count, withKyber)
}

// uploadBodyPools sizes the two one-time pools independently.
//
// They are separate pools with different exhaustion behaviour, and a fixture that
// fills them equally cannot exercise either boundary: draining the Kyber pool to
// test the last-resort fallback also drains the curve pool, and the curve pool has
// no fallback — DispenseBundle refuses outright, because the client's
// PeerKeyBundle requires a one-time prekey. The first version of these tests did
// exactly that and failed with "no prekey bundle available", which is the code
// being right about a constraint the fixture had ignored.
func uploadBodyPools(curveCount, kyberCount int, withKyber bool) io.Reader {
	body := map[string]any{
		"signed_prekey": map[string]any{
			"key_id": 1, "public_key": b64(33, 0x05), "signature": b64(64, 0xAA),
		},
	}
	if withKyber {
		body["kyber_last_resort"] = map[string]any{
			"key_id": 1, "public_key": b64(1568, 0x08), "signature": b64(64, 0xBB),
		}
	}

	var onetime []map[string]any
	for i := range curveCount {
		onetime = append(onetime, map[string]any{
			"key_id": 100 + i, "public_key": b64(33, byte(i%251)),
		})
	}
	body["one_time_prekeys"] = onetime

	var kyberOneTime []map[string]any
	for i := range kyberCount {
		kyberOneTime = append(kyberOneTime, map[string]any{
			"key_id": 200 + i, "public_key": b64(1568, byte(i%251)), "signature": b64(64, 0xCC),
		})
	}
	body["kyber_prekeys"] = kyberOneTime

	raw, _ := json.Marshal(body)
	return strings.NewReader(string(raw))
}

// poolUpload builds a publish request with explicit ids.
//
// uploadBodyPools numbers its keys from a fixed base, so publishing it twice
// sends the *same* ids and `ON CONFLICT DO NOTHING` stores nothing the second
// time — which would make a pool look bounded when nothing was bounding it. Any
// test about accumulation has to mint fresh ids, and rotation tests need to name
// the two long-lived ids to see them change.
func poolUpload(curveCount, kyberCount, idBase, signedID, lastResortID int) io.Reader {
	body := map[string]any{
		"signed_prekey": map[string]any{
			"key_id": signedID, "public_key": b64(33, 0x05), "signature": b64(64, 0xAA),
		},
		"kyber_last_resort": map[string]any{
			"key_id": lastResortID, "public_key": b64(1568, 0x08), "signature": b64(64, 0xBB),
		},
	}

	var onetime []map[string]any
	for i := range curveCount {
		onetime = append(onetime, map[string]any{
			"key_id": idBase + i, "public_key": b64(33, byte(i%251)),
		})
	}
	body["one_time_prekeys"] = onetime

	var kyberOneTime []map[string]any
	for i := range kyberCount {
		kyberOneTime = append(kyberOneTime, map[string]any{
			"key_id": idBase + 5000 + i, "public_key": b64(1568, byte(i%251)),
			"signature": b64(64, 0xCC),
		})
	}
	body["kyber_prekeys"] = kyberOneTime

	raw, _ := json.Marshal(body)
	return strings.NewReader(string(raw))
}

// publishedCounts is the pool sizes the relay reports back to the owner.
type publishedCounts struct {
	OneTimePreKeys int `json:"one_time_prekeys"`
	KyberPreKeys   int `json:"kyber_prekeys"`
}

func publishPool(t *testing.T, h http.Handler, token, from string, body io.Reader) publishedCounts {
	t.Helper()
	rec := do(h, http.MethodPut, "/v1/keys", token, from, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("publish: status %d: %s", rec.Code, rec.Body.String())
	}
	var got publishedCounts
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode publish response: %v", err)
	}
	return got
}

func fetchBundle(t *testing.T, h http.Handler, token, from string, target uuid.UUID) map[string]any {
	t.Helper()
	rec := do(h, http.MethodGet, "/v1/keys/"+target.String(), token, from, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("fetch bundle: status %d: %s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode bundle: %v", err)
	}
	return got
}

// --- AUDIT 5.40: the cumulative one-time pool ceiling ----------------------

func TestAPreKeyPoolStopsGrowingAtItsCeiling(t *testing.T) {
	// One-time keys are ADDED and nothing removes them except being dispensed or
	// the account being deleted, so MaxPreKeysPerUpload bounded a request while
	// storage per account was bounded by nothing: 6 publications a day of 200 keys
	// accumulated ≈5 MiB/day/account of ML-KEM rows nobody would ever fetch.
	ctx := context.Background()
	h, db, _ := keysStackWithCeiling(t, 5)
	aci, token := enrol(t, h, db, "198.51.100.200")

	// Fresh ids each time. Republishing the same ids conflicts and stores nothing,
	// which would look like a ceiling that is not there.
	first := publishPool(t, h, token, "198.51.100.200", poolUpload(3, 3, 1000, 1, 1))
	if first.OneTimePreKeys != 3 || first.KyberPreKeys != 3 {
		t.Fatalf("after the first publication: curve %d, kyber %d, want 3 and 3",
			first.OneTimePreKeys, first.KyberPreKeys)
	}

	// Four more of each against a ceiling of five: two of each fit.
	second := publishPool(t, h, token, "198.51.100.200", poolUpload(4, 4, 2000, 1, 1))
	if second.OneTimePreKeys != 5 || second.KyberPreKeys != 5 {
		t.Fatalf("after the second publication: curve %d, kyber %d, want 5 and 5 — "+
			"the pools grew past their ceiling", second.OneTimePreKeys, second.KyberPreKeys)
	}

	// The response is the owner's feedback channel, so it has to agree with the
	// database rather than merely look right.
	curve, err := db.CountOneTimePreKeys(ctx, aci)
	if err != nil {
		t.Fatalf("count curve: %v", err)
	}
	kyber, err := db.CountKyberOneTimePreKeys(ctx, aci)
	if err != nil {
		t.Fatalf("count kyber: %v", err)
	}
	if curve != 5 || kyber != 5 {
		t.Fatalf("stored curve %d, kyber %d, want 5 and 5", curve, kyber)
	}
}

func TestAFullPoolStillRotatesTheLongLivedKeys(t *testing.T) {
	// The property that makes the ceiling safe to have at all. Refusing a whole
	// publication because a pool was full would stop rotation (AUDIT 2.4) and
	// would be a lockout: the client retries a publication that never succeeded,
	// six times a day, while every peer's session setup fails. That is AUDIT
	// 5.32's shape. So the ceiling clips the one-time lists and never the signed
	// prekey or the last-resort Kyber key.
	//
	// A ceiling of one, because the last-resort key is only observable in a bundle
	// once the one-time Kyber pool is empty — and the curve pool has no fallback,
	// so each fetch needs a curve key present.
	h, db, _ := keysStackWithCeiling(t, 1)
	owner, ownerToken := enrol(t, h, db, "198.51.100.201")
	_, peerToken := enrol(t, h, db, "198.51.100.202")

	publishPool(t, h, ownerToken, "198.51.100.201", poolUpload(1, 1, 1000, 1, 1))

	// Both pools are now full. This publication's one-time keys are all clipped,
	// and its long-lived keys must land anyway.
	full := publishPool(t, h, ownerToken, "198.51.100.201", poolUpload(1, 1, 2000, 7, 7))
	if full.OneTimePreKeys != 1 || full.KyberPreKeys != 1 {
		t.Fatalf("pools are curve %d, kyber %d against a ceiling of 1",
			full.OneTimePreKeys, full.KyberPreKeys)
	}

	bundle := fetchBundle(t, h, peerToken, "198.51.100.202", owner)
	if got := bundle["signed_prekey_id"]; got != float64(7) {
		t.Fatalf("signed_prekey_id is %v, want 7 — a full pool blocked the rotation "+
			"of a long-lived key (AUDIT 5.40)", got)
	}

	// That fetch consumed the one-time key from each pool, so the next bundle must
	// fall back to the last-resort Kyber key — which is how its id becomes visible.
	// One curve key is published so the fetch can be served at all.
	publishPool(t, h, ownerToken, "198.51.100.201", poolUpload(1, 0, 3000, 9, 9))

	bundle = fetchBundle(t, h, peerToken, "198.51.100.202", owner)
	if got := bundle["signed_prekey_id"]; got != float64(9) {
		t.Fatalf("signed_prekey_id is %v, want 9", got)
	}
	if got := bundle["kyber_prekey_id"]; got != float64(9) {
		t.Fatalf("kyber_prekey_id is %v, want the rotated last-resort id 9 — the "+
			"last-resort key did not rotate", got)
	}
}

func TestDispensingMakesRoomUnderThePreKeyCeiling(t *testing.T) {
	// The ceiling is a live count of what is held, not a tally that only rises. A
	// pool that could never refill after being drained would hand an attacker a
	// permanent version of the AUDIT 3.1 drain instead of a temporary one.
	h, db, _ := keysStackWithCeiling(t, 2)
	owner, ownerToken := enrol(t, h, db, "198.51.100.203")
	_, peerToken := enrol(t, h, db, "198.51.100.204")

	publishPool(t, h, ownerToken, "198.51.100.203", poolUpload(2, 2, 1000, 1, 1))
	fetchBundle(t, h, peerToken, "198.51.100.204", owner) // consumes one of each

	after := publishPool(t, h, ownerToken, "198.51.100.203", poolUpload(2, 2, 2000, 1, 1))
	if after.OneTimePreKeys != 2 || after.KyberPreKeys != 2 {
		t.Fatalf("curve %d, kyber %d after refilling a drained pool, want 2 and 2 — "+
			"dispensing did not return the allowance", after.OneTimePreKeys, after.KyberPreKeys)
	}
}

func TestThePreKeyPoolsAreCountedSeparately(t *testing.T) {
	// One shared allowance would let whichever list is stored first consume the
	// other's, so an account with one full pool could never top up the other —
	// and if the Kyber pool is the one starved, every new session falls back to
	// the reused last-resort key, which is the exact cost AUDIT 3.1 is about.
	//
	// **Both directions, on separate accounts.** The first version of this test
	// filled the curve pool and checked the Kyber pool, which is the direction the
	// code does not store first — so a deliberately shared allowance passed it.
	// The defect was caught only because the negative test was actually run, which
	// is AUDIT R2 in miniature. A test written against one order stops testing
	// anything the day the loops are swapped.
	h, db, _ := keysStackWithCeiling(t, 3)

	for _, tc := range []struct {
		name              string
		from              string
		curveFirst        int
		kyberFirst        int
		wantCurve, wantKy int
	}{
		{"kyber pool filled first", "198.51.100.205", 0, 3, 3, 3},
		{"curve pool filled first", "198.51.100.206", 3, 0, 3, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, token := enrol(t, h, db, tc.from)
			publishPool(t, h, token, tc.from, poolUpload(tc.curveFirst, tc.kyberFirst, 1000, 1, 1))
			both := publishPool(t, h, token, tc.from, poolUpload(3, 3, 2000, 1, 1))

			if both.OneTimePreKeys != tc.wantCurve || both.KyberPreKeys != tc.wantKy {
				t.Fatalf("curve %d, kyber %d, want %d and %d — one pool consumed the "+
					"other's allowance", both.OneTimePreKeys, both.KyberPreKeys,
					tc.wantCurve, tc.wantKy)
			}
		})
	}
}

// enrolWithKeys creates an account and publishes a pool of `count` prekeys.
func enrolWithKeys(t *testing.T, h http.Handler, db *store.DB, from string, count int) (uuid.UUID, string) {
	t.Helper()
	aci, token := enrol(t, h, db, from)
	rec := do(h, http.MethodPut, "/v1/keys", token, from, uploadBody(count, true))
	if rec.Code != http.StatusOK {
		t.Fatalf("publish: status %d: %s", rec.Code, rec.Body.String())
	}
	return aci, token
}

// --- P4.S05: a non-PQ bundle is refused -----------------------------------

func TestUploadWithoutKyberIsRejected(t *testing.T) {
	// The step's gate, and the locked decision behind it: PQXDH is mandatory and
	// Kyber is never optional. Rejected at upload rather than stored, so the
	// omission cannot surface later as a bundle served without its KEM half —
	// which would be a silent downgrade to classical X3DH.
	h, db, _ := keysStack(t)
	_, token := enrol(t, h, db, "198.51.100.50")

	rec := do(h, http.MethodPut, "/v1/keys", token, "198.51.100.50", uploadBody(4, false))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a classic-only bundle was accepted: status %d", rec.Code)
	}
}

func TestUploadWithoutKyberStoresNothing(t *testing.T) {
	// A rejection that had already written the classical half would leave an
	// account whose bundle can never be assembled, and whose failure appears at
	// the peer trying to start a session rather than at the upload.
	ctx := context.Background()
	h, db, _ := keysStack(t)
	aci, token := enrol(t, h, db, "198.51.100.51")

	do(h, http.MethodPut, "/v1/keys", token, "198.51.100.51", uploadBody(4, false))

	n, err := db.CountOneTimePreKeys(ctx, aci)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("a rejected upload stored %d one-time prekeys", n)
	}
}

func TestUploadRejectsMalformedKeyMaterial(t *testing.T) {
	h, db, _ := keysStack(t)
	_, token := enrol(t, h, db, "198.51.100.52")

	cases := map[string]string{
		"signed prekey too short": `{"signed_prekey":{"key_id":1,"public_key":"` + b64(8, 1) +
			`","signature":"` + b64(64, 2) + `"},"kyber_last_resort":{"key_id":1,"public_key":"` +
			b64(1568, 3) + `","signature":"` + b64(64, 4) + `"}}`,
		"signature too short": `{"signed_prekey":{"key_id":1,"public_key":"` + b64(33, 1) +
			`","signature":"` + b64(8, 2) + `"},"kyber_last_resort":{"key_id":1,"public_key":"` +
			b64(1568, 3) + `","signature":"` + b64(64, 4) + `"}}`,
		"kyber key not base64": `{"signed_prekey":{"key_id":1,"public_key":"` + b64(33, 1) +
			`","signature":"` + b64(64, 2) + `"},"kyber_last_resort":{"key_id":1,"public_key":"!!!!","signature":"` +
			b64(64, 4) + `"}}`,
		"unknown field": `{"signedPreKey":{}}`,
		"not json":      `{`,
	}
	for name, body := range cases {
		rec := do(h, http.MethodPut, "/v1/keys", token, "198.51.100.52", strings.NewReader(body))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, rec.Code)
		}
	}
}

// --- Publish and dispense --------------------------------------------------

func TestPublishThenFetchRoundTrips(t *testing.T) {
	h, db, _ := keysStack(t)
	target, _ := enrolWithKeys(t, h, db, "198.51.100.53", 5)
	_, caller := enrol(t, h, db, "198.51.100.54")

	rec := do(h, http.MethodGet, "/v1/keys/"+target.String(), caller, "198.51.100.54", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("fetch: status %d: %s", rec.Code, rec.Body.String())
	}

	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Every field the client's PeerKeyBundle needs must be present, or
	// processPreKeyBundle cannot run.
	for _, field := range []string{
		"registration_id", "identity_key", "prekey_id", "prekey",
		"signed_prekey_id", "signed_prekey", "signed_prekey_signature",
		"kyber_prekey_id", "kyber_prekey", "kyber_prekey_signature",
	} {
		if v, ok := got[field]; !ok || v == "" {
			t.Errorf("the bundle is missing %q", field)
		}
	}
}

func TestFetchConsumesExactlyOneOneTimePreKey(t *testing.T) {
	ctx := context.Background()
	h, db, _ := keysStack(t)
	target, _ := enrolWithKeys(t, h, db, "198.51.100.55", 5)
	_, caller := enrol(t, h, db, "198.51.100.56")

	before, err := db.CountOneTimePreKeys(ctx, target)
	if err != nil {
		t.Fatalf("count: %v", err)
	}

	if rec := do(h, http.MethodGet, "/v1/keys/"+target.String(), caller, "198.51.100.56", nil); rec.Code != http.StatusOK {
		t.Fatalf("fetch: %d", rec.Code)
	}

	after, err := db.CountOneTimePreKeys(ctx, target)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if before-after != 1 {
		t.Fatalf("one fetch consumed %d one-time prekeys, want 1", before-after)
	}
}

func TestOneTimePreKeysAreNeverServedTwice(t *testing.T) {
	// If they were, the forward secrecy the one-time key exists to provide is
	// gone for both sessions that received it.
	h, db, _ := keysStack(t)
	target, _ := enrolWithKeys(t, h, db, "198.51.100.57", 8)
	_, caller := enrol(t, h, db, "198.51.100.58")

	seen := map[float64]bool{}
	for i := range 5 {
		rec := do(h, http.MethodGet, "/v1/keys/"+target.String(), caller, "198.51.100.58", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("fetch %d: %d", i, rec.Code)
		}
		var got map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		id := got["prekey_id"].(float64)
		if seen[id] {
			t.Fatalf("prekey %v was served twice", id)
		}
		seen[id] = true
	}
}

func TestConcurrentFetchesNeverShareAPreKey(t *testing.T) {
	// The reason dispense is one DELETE ... RETURNING with FOR UPDATE SKIP
	// LOCKED. A read-then-delete lets two concurrent fetches hand out the same
	// one-time key, which is the property this whole table exists to prevent.
	ctx := context.Background()
	h, db, _ := keysStack(t)
	target, _ := enrolWithKeys(t, h, db, "198.51.100.59", 20)

	const attempts = 12
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		ids  []uint32
		errs []error
	)
	start := make(chan struct{})
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			// Straight to the store: the HTTP rate limit would refuse most of
			// these before they contended.
			b, err := db.DispenseBundle(ctx, target)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			ids = append(ids, b.PreKey.KeyID)
		}()
	}
	close(start)
	wg.Wait()

	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	seen := map[uint32]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("prekey %d was dispensed to two concurrent callers", id)
		}
		seen[id] = true
	}
	if len(ids) != attempts {
		t.Fatalf("%d of %d concurrent fetches succeeded against a pool of 20", len(ids), attempts)
	}
}

func TestPublishAddsRatherThanReplaces(t *testing.T) {
	// Replacing would discard unused keys on every replenish, silently shrinking
	// a healthy pool to whatever the last upload happened to contain.
	ctx := context.Background()
	h, db, _ := keysStack(t)
	aci, token := enrolWithKeys(t, h, db, "198.51.100.60", 4)

	first, err := db.CountOneTimePreKeys(ctx, aci)
	if err != nil {
		t.Fatalf("count: %v", err)
	}

	// A second upload with different key ids.
	body := map[string]any{
		"signed_prekey": map[string]any{
			"key_id": 2, "public_key": b64(33, 0x06), "signature": b64(64, 0xAA),
		},
		"kyber_last_resort": map[string]any{
			"key_id": 2, "public_key": b64(1568, 0x09), "signature": b64(64, 0xBB),
		},
		"one_time_prekeys": []map[string]any{
			{"key_id": 900, "public_key": b64(33, 0x11)},
			{"key_id": 901, "public_key": b64(33, 0x12)},
		},
	}
	raw, _ := json.Marshal(body)
	if rec := do(h, http.MethodPut, "/v1/keys", token, "198.51.100.60", strings.NewReader(string(raw))); rec.Code != http.StatusOK {
		t.Fatalf("second publish: %d: %s", rec.Code, rec.Body.String())
	}

	second, err := db.CountOneTimePreKeys(ctx, aci)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if second != first+2 {
		t.Fatalf("pool went from %d to %d; the upload replaced rather than added", first, second)
	}
}

func TestPublishReplacesTheSignedAndLastResortKeys(t *testing.T) {
	// Exactly one of each per account. The schema enforces it — a primary key
	// and a partial unique index — and this checks the upload path agrees rather
	// than failing on a constraint.
	ctx := context.Background()
	h, db, _ := keysStack(t)
	aci, token := enrolWithKeys(t, h, db, "198.51.100.61", 2)

	for range 3 {
		if rec := do(h, http.MethodPut, "/v1/keys", token, "198.51.100.61", uploadBody(1, true)); rec.Code != http.StatusOK {
			t.Fatalf("republish: %d", rec.Code)
		}
	}

	cols, err := db.ColumnsOf(ctx, "signed_prekeys")
	if err != nil || len(cols) == 0 {
		t.Fatalf("columns: %v", err)
	}
	// One dispense must still succeed, which it cannot if the constraints were
	// violated or duplicated rows accumulated.
	if _, err := db.DispenseBundle(ctx, aci); err != nil {
		t.Fatalf("dispense after repeated publishes: %v", err)
	}
}

// --- Kyber fallback --------------------------------------------------------

func TestKyberFallsBackToLastResortWhenTheOneTimePoolEmpties(t *testing.T) {
	// PQXDH must keep running. The cost is that the KEM contribution is shared
	// with every other session that also fell back — classical X25519 forward
	// secrecy is unaffected — and that degradation is what an attacker draining
	// the pool is buying.
	ctx := context.Background()
	h, db, _ := keysStack(t)
	// Twenty curve keys, three Kyber: the Kyber pool empties first, with curve
	// keys left, which is the only way to reach the fallback at all.
	target, token := enrol(t, h, db, "198.51.100.62")
	if rec := do(h, http.MethodPut, "/v1/keys", token, "198.51.100.62",
		uploadBodyPools(20, 3, true)); rec.Code != http.StatusOK {
		t.Fatalf("publish: %d", rec.Code)
	}

	kyberCount, err := db.CountKyberOneTimePreKeys(ctx, target)
	if err != nil {
		t.Fatalf("count: %v", err)
	}

	var lastResortSeen bool
	for i := range kyberCount + 1 {
		b, err := db.DispenseBundle(ctx, target)
		if err != nil {
			t.Fatalf("dispense %d: %v", i, err)
		}
		if b.KyberWasLastResort {
			lastResortSeen = true
			if i < kyberCount {
				t.Errorf("fell back to last resort at dispense %d, with %d one-time "+
					"kyber keys still in the pool", i, kyberCount-i)
			}
			// The bundle must still carry Kyber material — falling back must not
			// mean serving nothing.
			if len(b.KyberPreKey.PublicKey) == 0 {
				t.Fatal("the fallback bundle carries no kyber key")
			}
			break
		}
	}
	if !lastResortSeen {
		t.Fatal("the one-time kyber pool never exhausted, so the fallback was not exercised")
	}
	_ = ctx
}

func TestLastResortKyberKeyIsNotConsumed(t *testing.T) {
	ctx := context.Background()
	h, db, _ := keysStack(t)
	target, token := enrol(t, h, db, "198.51.100.63")
	if rec := do(h, http.MethodPut, "/v1/keys", token, "198.51.100.63",
		uploadBodyPools(20, 2, true)); rec.Code != http.StatusOK {
		t.Fatalf("publish: %d", rec.Code)
	}

	// Exhaust the one-time kyber pool, leaving curve keys.
	kyberCount, err := db.CountKyberOneTimePreKeys(ctx, target)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	for range kyberCount {
		if _, err := db.DispenseBundle(ctx, target); err != nil {
			t.Fatalf("dispense: %v", err)
		}
	}

	// Two more must both succeed on the last-resort key: it is reusable, and a
	// dispense that consumed it would break every subsequent session setup.
	for i := range 2 {
		b, err := db.DispenseBundle(ctx, target)
		if err != nil {
			t.Fatalf("fallback dispense %d: %v", i, err)
		}
		if !b.KyberWasLastResort {
			t.Fatalf("fallback dispense %d did not use the last-resort key", i)
		}
	}
}

// --- Exhaustion ------------------------------------------------------------

func TestAnEmptyOneTimePoolYieldsTheSameAnswerAsAnUnknownAccount(t *testing.T) {
	// docs/BACKEND.md §8 forbids account enumeration. For a five-person circle,
	// "does this account exist" is most of the metadata worth having, so a
	// drained pool and a stranger must be indistinguishable.
	ctx := context.Background()
	h, db, _ := keysStack(t)
	target, _ := enrolWithKeys(t, h, db, "198.51.100.64", 2)
	_, caller := enrol(t, h, db, "198.51.100.65")

	// Drain it.
	n, err := db.CountOneTimePreKeys(ctx, target)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	for range n {
		if _, err := db.DispenseBundle(ctx, target); err != nil {
			t.Fatalf("drain: %v", err)
		}
	}

	drained := do(h, http.MethodGet, "/v1/keys/"+target.String(), caller, "198.51.100.65", nil)
	unknown := do(h, http.MethodGet, "/v1/keys/"+uuid.NewString(), caller, "198.51.100.65", nil)
	// An account that exists but never published.
	silent, _ := enrol(t, h, db, "198.51.100.66")
	never := do(h, http.MethodGet, "/v1/keys/"+silent.String(), caller, "198.51.100.65", nil)
	malformed := do(h, http.MethodGet, "/v1/keys/not-a-uuid", caller, "198.51.100.65", nil)

	want := fmt.Sprintf("%d|%s", drained.Code, strings.TrimSpace(drained.Body.String()))
	for name, rec := range map[string]*httptestRecorder{
		"unknown account":  {unknown.Code, unknown.Body.String()},
		"never published":  {never.Code, never.Body.String()},
		"malformed target": {malformed.Code, malformed.Body.String()},
	} {
		got := fmt.Sprintf("%d|%s", rec.code, strings.TrimSpace(rec.body))
		if got != want {
			t.Errorf("%s is distinguishable from a drained pool:\n  drained: %s\n  %s: %s",
				name, want, name, got)
		}
	}
	if drained.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", drained.Code)
	}
}

type httptestRecorder struct {
	code int
	body string
}

// --- P4.S06: the fetch flood is throttled ----------------------------------

func TestFetchFloodIsThrottled(t *testing.T) {
	// The step's gate. Without this, one authenticated account drains any peer's
	// pool at request speed.
	h, db, _ := keysStack(t)
	target, _ := enrolWithKeys(t, h, db, "198.51.100.67", 100)
	_, caller := enrol(t, h, db, "198.51.100.68")

	var throttled bool
	for i := range 20 {
		rec := do(h, http.MethodGet, "/v1/keys/"+target.String(), caller, "198.51.100.68", nil)
		if rec.Code == http.StatusTooManyRequests {
			throttled = true
			if rec.Header().Get("Retry-After") == "" {
				t.Error("a 429 must carry Retry-After")
			}
			if i < 10 {
				t.Errorf("throttled after %d fetches; the burst capacity is 10", i)
			}
			break
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("fetch %d: status %d", i, rec.Code)
		}
	}
	if !throttled {
		t.Fatal("twenty consecutive fetches were never throttled — a pool can be drained at will")
	}
}

func TestFetchLimitBoundsPoolDrain(t *testing.T) {
	// The property that actually matters, stated as an outcome rather than as a
	// count of 429s: after a sustained flood, the victim's pool still has keys.
	ctx := context.Background()
	h, db, _ := keysStack(t)
	target, _ := enrolWithKeys(t, h, db, "198.51.100.69", 100)
	_, caller := enrol(t, h, db, "198.51.100.70")

	before, err := db.CountOneTimePreKeys(ctx, target)
	if err != nil {
		t.Fatalf("count: %v", err)
	}

	for range 60 {
		do(h, http.MethodGet, "/v1/keys/"+target.String(), caller, "198.51.100.70", nil)
	}

	after, err := db.CountOneTimePreKeys(ctx, target)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	consumed := before - after
	if consumed > 10 {
		t.Fatalf("60 fetch attempts consumed %d prekeys; the burst limit is 10", consumed)
	}
	if after == 0 {
		t.Fatal("the pool was drained despite the rate limit")
	}
}

func TestFetchLimitIsKeyedByCallerNotTarget(t *testing.T) {
	// Keying by target would let several attacker accounts drain a pool at N
	// times the rate while every bucket looked healthy, and would let anyone
	// deny service to a peer by exhausting the bucket that peer's fetches share.
	h, db, _ := keysStack(t)
	target, _ := enrolWithKeys(t, h, db, "198.51.100.71", 100)
	_, first := enrol(t, h, db, "198.51.100.72")
	_, second := enrol(t, h, db, "198.51.100.73")

	// Exhaust the first caller's burst allowance.
	for range 12 {
		do(h, http.MethodGet, "/v1/keys/"+target.String(), first, "198.51.100.72", nil)
	}
	if rec := do(h, http.MethodGet, "/v1/keys/"+target.String(), first, "198.51.100.72", nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the first caller was not throttled: %d", rec.Code)
	}

	// A different caller fetching the same target is unaffected.
	if rec := do(h, http.MethodGet, "/v1/keys/"+target.String(), second, "198.51.100.73", nil); rec.Code != http.StatusOK {
		t.Fatalf("one caller's limit blocked another against the same target: %d", rec.Code)
	}
}

func TestFetchLimitSurvivesAChangeOfAddress(t *testing.T) {
	// Keyed by account, so moving to another network does not reset it.
	h, db, _ := keysStack(t)
	target, _ := enrolWithKeys(t, h, db, "198.51.100.74", 100)
	_, caller := enrol(t, h, db, "198.51.100.75")

	for range 12 {
		do(h, http.MethodGet, "/v1/keys/"+target.String(), caller, "198.51.100.75", nil)
	}
	if rec := do(h, http.MethodGet, "/v1/keys/"+target.String(), caller, "203.0.113.99", nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("changing address reset the per-account fetch limit: %d", rec.Code)
	}
}

// --- Authentication --------------------------------------------------------

func TestKeyRoutesRequireAuthentication(t *testing.T) {
	// An unauthenticated directory makes the per-account limit unenforceable and
	// turns the relay into a membership oracle for the whole circle.
	h, db, _ := keysStack(t)
	target, _ := enrolWithKeys(t, h, db, "198.51.100.76", 2)

	for name, rec := range map[string]int{
		"fetch":   do(h, http.MethodGet, "/v1/keys/"+target.String(), "", "198.51.100.77", nil).Code,
		"publish": do(h, http.MethodPut, "/v1/keys", "", "198.51.100.77", uploadBody(1, true)).Code,
	} {
		if rec != http.StatusUnauthorized {
			t.Errorf("unauthenticated %s: status %d, want 401", name, rec)
		}
	}
}

func TestAnAccountCanOnlyPublishItsOwnKeys(t *testing.T) {
	// The target is the authenticated account and is never taken from the path
	// or the body. If it were, anyone could replace anyone's prekeys, and every
	// new session with the victim would run against keys the attacker chose.
	ctx := context.Background()
	h, db, _ := keysStack(t)
	victim, _ := enrolWithKeys(t, h, db, "198.51.100.78", 3)
	attacker, attackerToken := enrol(t, h, db, "198.51.100.79")

	before, err := db.CountOneTimePreKeys(ctx, victim)
	if err != nil {
		t.Fatalf("count: %v", err)
	}

	// There is no parameter through which to name the victim, which is the
	// point; this publishes as the attacker and asserts the victim is untouched.
	if rec := do(h, http.MethodPut, "/v1/keys", attackerToken, "198.51.100.79", uploadBody(5, true)); rec.Code != http.StatusOK {
		t.Fatalf("publish: %d", rec.Code)
	}

	after, err := db.CountOneTimePreKeys(ctx, victim)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if after != before {
		t.Fatalf("the victim's pool changed from %d to %d", before, after)
	}
	attackerCount, err := db.CountOneTimePreKeys(ctx, attacker)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if attackerCount != 5 {
		t.Fatalf("the attacker's own pool holds %d keys, want 5", attackerCount)
	}
}

func TestPublishIsRateLimited(t *testing.T) {
	h, db, _ := keysStack(t)
	_, token := enrol(t, h, db, "198.51.100.80")

	var throttled bool
	for i := range 10 {
		rec := do(h, http.MethodPut, "/v1/keys", token, "198.51.100.80", uploadBody(1, true))
		if rec.Code == http.StatusTooManyRequests {
			throttled = true
			if i < 6 {
				t.Errorf("throttled after %d publishes; capacity is 6", i)
			}
			break
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("publish %d: %d", i, rec.Code)
		}
	}
	if !throttled {
		t.Fatal("publishing was never throttled")
	}
}

// --- The relay does not verify signatures ---------------------------------

func TestTheRelayDoesNotVerifySignatures(t *testing.T) {
	// Deliberate, and worth pinning so nobody "fixes" it. processPreKeyBundle
	// verifies on the client, on every use, against the identity key in the same
	// bundle. A check here would be a second unreviewed copy — and a client that
	// trusted the server's verdict would have no protection from a hostile relay,
	// which is the whole threat model.
	//
	// The signatures in these fixtures are constant bytes and could not verify
	// against anything. The relay stores and serves them regardless.
	h, db, _ := keysStack(t)
	target, _ := enrolWithKeys(t, h, db, "198.51.100.81", 2)
	_, caller := enrol(t, h, db, "198.51.100.82")

	rec := do(h, http.MethodGet, "/v1/keys/"+target.String(), caller, "198.51.100.82", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("the relay rejected a bundle it should not be judging: %d", rec.Code)
	}

	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["signed_prekey_signature"] != b64(64, 0xAA) {
		t.Error("the relay altered the signature it was given")
	}
}

func TestTimingOfAnUnknownAccountResemblesAKnownOne(t *testing.T) {
	// A weak but worthwhile check: the enumeration defence is about the response
	// being identical, and a wildly different code path would show up here. Not
	// a constant-time assertion — that is not achievable against a database, and
	// claiming it would be worse than not testing it.
	h, db, _ := keysStack(t)
	target, _ := enrolWithKeys(t, h, db, "198.51.100.83", 50)
	_, caller := enrol(t, h, db, "198.51.100.84")

	known := time.Now()
	do(h, http.MethodGet, "/v1/keys/"+target.String(), caller, "198.51.100.84", nil)
	knownElapsed := time.Since(known)

	unknown := time.Now()
	do(h, http.MethodGet, "/v1/keys/"+uuid.NewString(), caller, "198.51.100.84", nil)
	unknownElapsed := time.Since(unknown)

	// Two orders of magnitude apart would mean an entirely different path, such
	// as a lookup that short-circuits before touching the database at all.
	if unknownElapsed > knownElapsed*100 || knownElapsed > unknownElapsed*100 {
		t.Errorf("known %v vs unknown %v — the paths differ enough to be a signal",
			knownElapsed, unknownElapsed)
	}
}
