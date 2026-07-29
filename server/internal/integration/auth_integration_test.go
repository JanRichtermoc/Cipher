//go:build integration

// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
//
// P4.S04's "Done when": the token is never stored in plaintext, and revocation
// works. Both need a real database — the first because it is a claim about what
// is on disk, and the second because rotation's atomicity is a property of one
// transaction rather than of the Go around it.

package integration

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"cipher.relay/internal/api"
	"cipher.relay/internal/auth"
	"cipher.relay/internal/logging"
	"cipher.relay/internal/store"
)

// authStack builds a router with both handlers over the live datastores.
func authStack(t *testing.T) (http.Handler, *store.DB, *api.AuthHandler) {
	t.Helper()
	db := testDB(t)
	limiter := testLimiter(t)
	log := logging.New(io.Discard, slog.LevelError)

	authHandler := api.NewAuthHandler(db, limiter, log)
	mux := http.NewServeMux()
	authHandler.Routes(mux)
	api.NewInviteHandler(db, limiter, authHandler, log).Routes(mux)
	return mux, db, authHandler
}

// enrol redeems a fresh invite and returns the account and its session token.
func enrol(t *testing.T, h http.Handler, db *store.DB, from string) (uuid.UUID, string) {
	t.Helper()
	code := issue(t, db, time.Hour)
	key := base64.StdEncoding.EncodeToString(make([]byte, 33))

	rec := post(h, from, redeemBody(code.String(), key, 42))
	if rec.Code != http.StatusCreated {
		t.Fatalf("redeem: status %d: %s", rec.Code, rec.Body.String())
	}

	var got struct {
		ACI   string `json:"aci"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Token == "" {
		t.Fatal("redemption returned no session token; the new account cannot authenticate")
	}
	aci, err := uuid.Parse(got.ACI)
	if err != nil {
		t.Fatalf("aci: %v", err)
	}
	return aci, got.Token
}

func do(h http.Handler, method, path, token, from string, body io.Reader) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, body)
	r.RemoteAddr = from + ":54321"
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// --- The token is never stored in plaintext --------------------------------

func TestTokenIsNotStoredInPlaintext(t *testing.T) {
	// The single most important property of this table. A database dump must not
	// yield a credential that authenticates as anyone.
	ctx := context.Background()
	h, db := newHandler(t)
	_ = h
	authHandler := api.NewAuthHandler(db, testLimiter(t), logging.New(io.Discard, slog.LevelError))

	aci := uuid.New()
	if err := db.RedeemInvite(ctx, issue(t, db, time.Hour).Hash(), store.Account{
		ACI: aci, IdentityKey: make([]byte, 33), RegistrationID: 7,
	}); err != nil {
		t.Fatalf("create account: %v", err)
	}

	token, err := authHandler.Issue(ctx, aci)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Scan every text-ish value in the table for the token. Looking it up by
	// hash would only prove the hash works; this asks whether the raw value is
	// anywhere at all.
	found, err := db.SessionTokenAppearsInPlaintext(ctx, token.String())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if found {
		t.Fatal("the raw session token is present in the database")
	}

	// And the hash *is* there, so the scan above is not passing because nothing
	// was written at all.
	got, err := db.LookupSession(ctx, token.Hash())
	if err != nil {
		t.Fatalf("lookup by hash: %v", err)
	}
	if got != aci {
		t.Fatalf("lookup returned %s, want %s", got, aci)
	}
}

func TestPlaintextScanCanActuallyFindSomething(t *testing.T) {
	// Positive control for the test above. `SessionTokenAppearsInPlaintext`
	// returning false is only evidence if it is capable of returning true —
	// otherwise a typo in the query, a column list that came back empty, or a
	// cast that silently failed would all read as "the token is not stored",
	// which is the most reassuring possible way for the check to be broken.
	//
	// This searches for a value that IS in the table: the stored hash, rendered
	// the way Postgres renders a BYTEA as text.
	ctx := context.Background()
	h, db, authHandler := authStack(t)
	aci, _ := enrol(t, h, db, "198.51.100.29")

	token, err := authHandler.Issue(ctx, aci)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	stored := "\\x" + hex.EncodeToString(token.Hash())
	found, err := db.SessionTokenAppearsInPlaintext(ctx, stored)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !found {
		t.Fatal("the scan could not find a value that is definitely stored — " +
			"it cannot be trusted to report that the raw token is absent")
	}
}

// --- Revocation ------------------------------------------------------------

func TestRevokeEndsTheSession(t *testing.T) {
	h, db, _ := authStack(t)
	_, token := enrol(t, h, db, "198.51.100.30")

	// It works before.
	if rec := do(h, http.MethodPost, "/v1/invite", token, "198.51.100.30", nil); rec.Code != http.StatusCreated {
		t.Fatalf("pre-revoke request: status %d", rec.Code)
	}

	if rec := do(h, http.MethodDelete, "/v1/auth", token, "198.51.100.30", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke: status %d", rec.Code)
	}

	// And not after. Immediately — no cache, no grace window.
	if rec := do(h, http.MethodPost, "/v1/invite", token, "198.51.100.30", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("post-revoke request: status %d, want 401", rec.Code)
	}
}

func TestRevokeIsIdempotent(t *testing.T) {
	h, db, _ := authStack(t)
	_, token := enrol(t, h, db, "198.51.100.31")

	if rec := do(h, http.MethodDelete, "/v1/auth", token, "198.51.100.31", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("first revoke: %d", rec.Code)
	}
	// The second attempt presents a token that no longer resolves, so Require
	// rejects it — 401, not an error. Signing out twice must not look like a
	// failure to the user.
	if rec := do(h, http.MethodDelete, "/v1/auth", token, "198.51.100.31", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("second revoke: %d, want 401", rec.Code)
	}
}

func TestRevokeAllEndsEverySession(t *testing.T) {
	ctx := context.Background()
	h, db, authHandler := authStack(t)
	aci, first := enrol(t, h, db, "198.51.100.32")

	// A second and third session for the same account, as other devices.
	second, err := authHandler.Issue(ctx, aci)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	third, err := authHandler.Issue(ctx, aci)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	n, err := db.CountSessionsForAccount(ctx, aci)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 3 {
		t.Fatalf("account holds %d sessions, want 3", n)
	}

	if rec := do(h, http.MethodDelete, "/v1/auth/all", second.String(), "198.51.100.32", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke all: %d", rec.Code)
	}

	n, err = db.CountSessionsForAccount(ctx, aci)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("%d sessions survived revoke-all", n)
	}
	// Including the one that issued the request. "Sign out everywhere" that
	// leaves the calling device signed in is not what it says.
	for name, tok := range map[string]string{"first": first, "second": second.String(), "third": third.String()} {
		if rec := do(h, http.MethodPost, "/v1/invite", tok, "198.51.100.32", nil); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s session still works after revoke-all: %d", name, rec.Code)
		}
	}
}

func TestRevokedTokenCannotBeRotated(t *testing.T) {
	// Otherwise revocation would be bypassable by anyone holding the old value:
	// present it to /rotate and walk away with a fresh, live credential.
	h, db, _ := authStack(t)
	_, token := enrol(t, h, db, "198.51.100.33")

	if rec := do(h, http.MethodDelete, "/v1/auth", token, "198.51.100.33", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d", rec.Code)
	}
	if rec := do(h, http.MethodPost, "/v1/auth/rotate", token, "198.51.100.33", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("rotate after revoke: %d, want 401", rec.Code)
	}
}

// --- Rotation --------------------------------------------------------------

func TestRotateIssuesAWorkingTokenAndKillsTheOld(t *testing.T) {
	h, db, _ := authStack(t)
	_, old := enrol(t, h, db, "198.51.100.34")

	rec := do(h, http.MethodPost, "/v1/auth/rotate", old, "198.51.100.34", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate: status %d: %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Token == old {
		t.Fatal("rotation returned the same token")
	}

	if rec := do(h, http.MethodPost, "/v1/invite", got.Token, "198.51.100.34", nil); rec.Code != http.StatusCreated {
		t.Fatalf("new token does not work: %d", rec.Code)
	}
	// Immediately, not eventually. A grace window on the old value is the window
	// an attacker who stole it wants.
	if rec := do(h, http.MethodPost, "/v1/invite", old, "198.51.100.34", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the old token still works after rotation: %d", rec.Code)
	}
}

func TestRotationLeavesExactlyOneSession(t *testing.T) {
	ctx := context.Background()
	h, db, _ := authStack(t)
	aci, token := enrol(t, h, db, "198.51.100.35")

	for range 3 {
		rec := do(h, http.MethodPost, "/v1/auth/rotate", token, "198.51.100.35", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("rotate: %d", rec.Code)
		}
		var got struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		token = got.Token
	}

	// A rotation that inserts without deleting looks correct from the client's
	// side and accumulates a live credential per rotation, each one a valid
	// bearer token nobody is tracking.
	n, err := db.CountSessionsForAccount(ctx, aci)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("after three rotations the account holds %d sessions, want 1", n)
	}
}

func TestConcurrentRotationYieldsExactlyOneNewToken(t *testing.T) {
	// The same argument as concurrent invite redemption. Two clients racing to
	// rotate one token must not both succeed, or one rotation silently
	// invalidates the other's brand-new credential.
	ctx := context.Background()
	h, db, _ := authStack(t)
	aci, token := enrol(t, h, db, "198.51.100.36")

	const attempts = 8
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		accepted int
	)
	start := make(chan struct{})
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			// Straight to the store: the HTTP layer's rate limit would refuse
			// most of these before they ever contended.
			fresh, err := auth.Generate()
			if err != nil {
				return
			}
			old, err := auth.Parse(token)
			if err != nil {
				return
			}
			if _, err := db.RotateSession(ctx, old.Hash(), fresh.Hash(),
				time.Now().Add(time.Hour)); err == nil {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	if accepted != 1 {
		t.Fatalf("%d of %d concurrent rotations succeeded, want exactly 1", accepted, attempts)
	}
	n, err := db.CountSessionsForAccount(ctx, aci)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("account holds %d sessions after a rotation race, want 1", n)
	}
}

// --- Expiry ----------------------------------------------------------------

func TestExpiredTokenIsRefused(t *testing.T) {
	ctx := context.Background()
	h, db, _ := authStack(t)
	aci, _ := enrol(t, h, db, "198.51.100.37")

	dead, err := auth.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := db.CreateSession(ctx, dead.Hash(), aci, time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("create session: %v", err)
	}

	if _, err := db.LookupSession(ctx, dead.Hash()); err != store.ErrSessionNotFound {
		t.Fatalf("expired lookup returned %v, want ErrSessionNotFound", err)
	}
	if rec := do(h, http.MethodPost, "/v1/invite", dead.String(), "198.51.100.37", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired token accepted: %d", rec.Code)
	}
}

func TestSweepRemovesExpiredSessions(t *testing.T) {
	ctx := context.Background()
	h, db, _ := authStack(t)
	aci, live := enrol(t, h, db, "198.51.100.38")

	dead, err := auth.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := db.CreateSession(ctx, dead.Hash(), aci, time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("create session: %v", err)
	}

	if _, err := db.DeleteExpiredSessions(ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	// The live session must survive — a sweep that removes everything passes a
	// naive assertion while signing everyone out.
	if rec := do(h, http.MethodPost, "/v1/invite", live, "198.51.100.38", nil); rec.Code != http.StatusCreated {
		t.Fatalf("the sweep revoked a live session: %d", rec.Code)
	}
	n, err := db.CountSessionsForAccount(ctx, aci)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("account holds %d sessions after the sweep, want 1", n)
	}
}

// --- Authentication surface ------------------------------------------------

func TestEveryRejectionLooksIdentical(t *testing.T) {
	// Missing, wrong scheme, malformed, unknown, expired — one response. Each
	// distinction is an oracle: a 400 for "malformed" confirms which guesses had
	// the right shape.
	ctx := context.Background()
	h, db, _ := authStack(t)
	aci, _ := enrol(t, h, db, "198.51.100.39")

	expired, err := auth.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := db.CreateSession(ctx, expired.Hash(), aci, time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("create session: %v", err)
	}
	unknown, err := auth.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	headers := map[string]string{
		"missing":      "",
		"empty bearer": "Bearer ",
		"wrong scheme": "Basic abcdef",
		"malformed":    "Bearer !!!!!!",
		"unknown":      "Bearer " + unknown.String(),
		"expired":      "Bearer " + expired.String(),
	}

	var reference string
	for name, header := range headers {
		r := httptest.NewRequest(http.MethodPost, "/v1/invite", nil)
		r.RemoteAddr = "198.51.100.39:1"
		if header != "" {
			r.Header.Set("Authorization", header)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)

		// Status line and body together: a difference in either is observable.
		signature := rec.Result().Status + "|" + strings.TrimSpace(rec.Body.String())
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, rec.Code)
			continue
		}
		if reference == "" {
			reference = signature
			continue
		}
		if signature != reference {
			t.Errorf("%s produced a distinguishable response:\n  %s\n  %s",
				name, reference, signature)
		}
	}
}

func TestUnauthenticatedIssuanceIsRefused(t *testing.T) {
	// POST /v1/invite must never be reachable without a session. If it were,
	// the invite-only property — the entire access-control model — would be
	// decorative.
	h, _, _ := authStack(t)
	if rec := do(h, http.MethodPost, "/v1/invite", "", "198.51.100.40", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated issuance: status %d, want 401", rec.Code)
	}
}

func TestIssuedInviteIsRedeemableAndUnattributed(t *testing.T) {
	ctx := context.Background()
	h, db, _ := authStack(t)
	_, token := enrol(t, h, db, "198.51.100.41")

	rec := do(h, http.MethodPost, "/v1/invite", token, "198.51.100.41", nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue: status %d: %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// It works.
	key := base64.StdEncoding.EncodeToString(make([]byte, 33))
	if rec := post(h, "198.51.100.42", redeemBody(got.Code, key, 9)); rec.Code != http.StatusCreated {
		t.Fatalf("redeeming an issued invite: %d: %s", rec.Code, rec.Body.String())
	}

	// And the database holds no column that could say who issued it. Asserted
	// against information_schema rather than by reading the migration, so a
	// column added by a later migration is caught too.
	cols, err := db.ColumnsOf(ctx, "invites")
	if err != nil {
		t.Fatalf("columns: %v", err)
	}
	for _, c := range cols {
		if c != "code_hash" && c != "expires_at" {
			t.Errorf("the invites table gained a %q column; the invite graph is "+
				"deliberately not stored (BACKEND.md §2.2)", c)
		}
	}
}

func TestIssuanceIsRateLimitedPerAccount(t *testing.T) {
	// docs/BACKEND.md §5: 3 per day. This is what replaces the created_by column
	// the schema refuses to store — without it, one account could mint invites
	// without bound.
	h, db, _ := authStack(t)
	_, token := enrol(t, h, db, "198.51.100.43")

	var throttled bool
	for i := range 6 {
		rec := do(h, http.MethodPost, "/v1/invite", token, "198.51.100.43", nil)
		if rec.Code == http.StatusTooManyRequests {
			throttled = true
			if i < 3 {
				t.Errorf("throttled after only %d issuances; capacity is 3", i)
			}
			break
		}
		if rec.Code != http.StatusCreated {
			t.Fatalf("issue %d: status %d", i, rec.Code)
		}
	}
	if !throttled {
		t.Fatal("invite issuance was never throttled")
	}
}

func TestIssuanceLimitIsPerAccountNotPerAddress(t *testing.T) {
	// Keyed by account so moving to another network does not reset it, and so
	// one account on a shared address cannot exhaust another's allowance.
	h, db, _ := authStack(t)
	_, token := enrol(t, h, db, "198.51.100.44")

	for range 3 {
		do(h, http.MethodPost, "/v1/invite", token, "198.51.100.44", nil)
	}
	// Same account, different address: still throttled.
	rec := do(h, http.MethodPost, "/v1/invite", token, "203.0.113.77", nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("changing address reset the per-account limit: %d", rec.Code)
	}

	// Different account, same address: unaffected.
	_, other := enrol(t, h, db, "203.0.113.78")
	if rec := do(h, http.MethodPost, "/v1/invite", other, "203.0.113.77", nil); rec.Code != http.StatusCreated {
		t.Fatalf("one account's limit blocked another: %d", rec.Code)
	}
}
