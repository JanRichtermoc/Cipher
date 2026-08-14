//go:build integration

// AUDIT 5.41 — re-authentication against a published account key.
//
// These need the live datastores: single use is a property of a Redis script
// under real concurrency, and "the relay stores only the public half" is a claim
// about what a real column contains.
//
// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only

package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/google/uuid"

	"cipher.relay/internal/api"
	"cipher.relay/internal/cache"
	"cipher.relay/internal/logging"
	"cipher.relay/internal/reauth"
	"cipher.relay/internal/store"
)

// reauthStack builds a router carrying the auth, invite and reauth handlers.
func reauthStack(t *testing.T) (http.Handler, *store.DB) {
	t.Helper()
	db := testDB(t)
	limiter := testLimiter(t)
	log := logging.New(io.Discard, slog.LevelError)

	rc, err := cache.Open(context.Background(),
		os.Getenv("RELAY_REDIS_ADDR"), os.Getenv("RELAY_REDIS_PASSWORD"))
	if err != nil {
		t.Fatalf("open redis: %v", err)
	}
	t.Cleanup(func() { _ = rc.Close() })

	authHandler := api.NewAuthHandler(db, limiter, log)
	mux := http.NewServeMux()
	authHandler.Routes(mux)
	api.NewInviteHandler(db, limiter, authHandler, log).Routes(mux)
	api.NewReauthHandler(db, limiter, reauth.NewStore(rc.KV()), authHandler, log).Routes(mux)
	return mux, db
}

func jsonPost(h http.Handler, path, from, body, bearer string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = from + ":40000"
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func jsonPut(h http.Handler, path, from, body, bearer string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPut, path, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = from + ":40000"
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// publishKey mints a keypair, publishes the public half, and returns both.
func publishKey(
	t *testing.T, h http.Handler, from, token string,
) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	body := `{"key":"` + base64.StdEncoding.EncodeToString(pub) + `"}`
	if rec := jsonPut(h, "/v1/auth/key", from, body, token); rec.Code != http.StatusNoContent {
		t.Fatalf("publish key: status %d: %s", rec.Code, rec.Body.String())
	}
	return pub, priv
}

func requestChallenge(t *testing.T, h http.Handler, from string, aci uuid.UUID) string {
	t.Helper()
	rec := jsonPost(h, "/v1/auth/challenge", from, `{"aci":"`+aci.String()+`"}`, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge: status %d: %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	return got.Challenge
}

func signedReauth(aci uuid.UUID, challenge string, priv ed25519.PrivateKey) string {
	sig := ed25519.Sign(priv, api.SigningPayload(aci, challenge))
	return `{"aci":"` + aci.String() + `","challenge":"` + challenge +
		`","signature":"` + base64.StdEncoding.EncodeToString(sig) + `"}`
}

// TestReauthenticationIssuesAWorkingSession is the whole point of 5.41: an
// account whose session tokens are all gone can get a new one.
func TestReauthenticationIssuesAWorkingSession(t *testing.T) {
	h, db := reauthStack(t)
	aci, token := enrol(t, h, db, "198.51.100.140")
	_, priv := publishKey(t, h, "198.51.100.140", token)

	// Destroy every session this account has, which before 5.41's fix left the
	// account permanently unreachable.
	if _, err := db.DeleteSessionsForAccount(context.Background(), aci); err != nil {
		t.Fatalf("revoke all: %v", err)
	}

	challenge := requestChallenge(t, h, "198.51.100.141", aci)
	rec := jsonPost(h, "/v1/auth/reauth", "198.51.100.141",
		signedReauth(aci, challenge, priv), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("reauth: status %d: %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Token == "" {
		t.Fatal("re-authentication returned no token")
	}

	// The token must actually authenticate, not merely exist.
	rec = jsonPost(h, "/v1/auth/rotate", "198.51.100.141", "", got.Token)
	if rec.Code != http.StatusOK {
		t.Fatalf("the re-authenticated token does not work: status %d", rec.Code)
	}
}

// TestFailedSignaturesCannotSpendAnotherAccountsBudget is AUDIT 5.42's
// invariant. The aci is unauthenticated input until a signature verifies, so a
// failure may spend its address bucket but must not touch the named account's
// recovery allowance.
func TestFailedSignaturesCannotSpendAnotherAccountsBudget(t *testing.T) {
	h, db := reauthStack(t)
	aci, token := enrol(t, h, db, "198.51.100.155")
	_, ownerPriv := publishKey(t, h, "198.51.100.155", token)
	_, attackerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate attacker key: %v", err)
	}

	// This is the entire per-account capacity. The old ordering charged every
	// one of these failures to the victim and made the valid attempt below 429.
	for i := range 10 {
		challenge := requestChallenge(t, h, "198.51.100.156", aci)
		body := signedReauth(aci, challenge, attackerPriv)
		if rec := jsonPost(h, "/v1/auth/reauth", "198.51.100.156", body, ""); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attacker attempt %d: status %d, want 401", i+1, rec.Code)
		}
	}

	challenge := requestChallenge(t, h, "198.51.100.155", aci)
	body := signedReauth(aci, challenge, ownerPriv)
	if rec := jsonPost(h, "/v1/auth/reauth", "198.51.100.155", body, ""); rec.Code != http.StatusOK {
		t.Fatalf("attacker spent the account recovery budget: status %d", rec.Code)
	}
}

// TestSuccessfulReauthenticationsAreRateLimitedPerAccount is the positive
// control for the limit moved by 5.42: fixing the denial must not quietly delete
// the account bucket. Only signatures proving control spend its ten-token
// allowance, and the next valid attempt is refused even from another address.
func TestSuccessfulReauthenticationsAreRateLimitedPerAccount(t *testing.T) {
	h, db := reauthStack(t)
	aci, token := enrol(t, h, db, "198.51.100.157")
	_, priv := publishKey(t, h, "198.51.100.157", token)

	for i := range 10 {
		challenge := requestChallenge(t, h, "198.51.100.157", aci)
		body := signedReauth(aci, challenge, priv)
		if rec := jsonPost(h, "/v1/auth/reauth", "198.51.100.157", body, ""); rec.Code != http.StatusOK {
			t.Fatalf("valid attempt %d: status %d, want 200", i+1, rec.Code)
		}
	}

	challenge := requestChallenge(t, h, "203.0.113.157", aci)
	body := signedReauth(aci, challenge, priv)
	rec := jsonPost(h, "/v1/auth/reauth", "203.0.113.157", body, "")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("account limit did not refuse an eleventh valid attempt: status %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("account-limit refusal has no Retry-After")
	}
}

// TestAChallengeIsSingleUse pins the replay protection.
func TestAChallengeIsSingleUse(t *testing.T) {
	h, db := reauthStack(t)
	aci, token := enrol(t, h, db, "198.51.100.142")
	_, priv := publishKey(t, h, "198.51.100.142", token)

	challenge := requestChallenge(t, h, "198.51.100.143", aci)
	body := signedReauth(aci, challenge, priv)

	if rec := jsonPost(h, "/v1/auth/reauth", "198.51.100.143", body, ""); rec.Code != http.StatusOK {
		t.Fatalf("first use: status %d", rec.Code)
	}
	// Byte-identical replay of a signature that was valid a moment ago.
	if rec := jsonPost(h, "/v1/auth/reauth", "198.51.100.143", body, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a replayed challenge was accepted: status %d", rec.Code)
	}
}

// TestAWrongSignatureBurnsTheChallenge — otherwise one challenge could be
// attacked repeatedly, which is the point of it being single use.
func TestAWrongSignatureBurnsTheChallenge(t *testing.T) {
	h, db := reauthStack(t)
	aci, token := enrol(t, h, db, "198.51.100.144")
	_, priv := publishKey(t, h, "198.51.100.144", token)

	challenge := requestChallenge(t, h, "198.51.100.145", aci)
	_, wrong, _ := ed25519.GenerateKey(nil)
	bad := signedReauth(aci, challenge, wrong)
	if rec := jsonPost(h, "/v1/auth/reauth", "198.51.100.145", bad, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong signature was accepted: status %d", rec.Code)
	}
	// The correct signature over the same challenge must now fail too.
	good := signedReauth(aci, challenge, priv)
	if rec := jsonPost(h, "/v1/auth/reauth", "198.51.100.145", good, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a burned challenge was reusable: status %d", rec.Code)
	}
}

// TestAnotherAccountsKeyCannotReauthenticate — the signature must verify against
// the named account's key, not merely be a valid signature.
func TestAnotherAccountsKeyCannotReauthenticate(t *testing.T) {
	h, db := reauthStack(t)
	victim, victimToken := enrol(t, h, db, "198.51.100.146")
	publishKey(t, h, "198.51.100.146", victimToken)
	_, attackerToken := enrol(t, h, db, "198.51.100.147")
	_, attackerPriv := publishKey(t, h, "198.51.100.147", attackerToken)

	challenge := requestChallenge(t, h, "198.51.100.147", victim)
	body := signedReauth(victim, challenge, attackerPriv)
	if rec := jsonPost(h, "/v1/auth/reauth", "198.51.100.147", body, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("another account's key authenticated: status %d", rec.Code)
	}
}

// TestAChallengeForAnUnknownAccountLooksIdentical — the endpoint must not be a
// membership oracle for a five-person circle.
func TestAChallengeForAnUnknownAccountLooksIdentical(t *testing.T) {
	h, db := reauthStack(t)
	known, _ := enrol(t, h, db, "198.51.100.148")
	unknown := uuid.New()

	a := jsonPost(h, "/v1/auth/challenge", "198.51.100.149", `{"aci":"`+known.String()+`"}`, "")
	b := jsonPost(h, "/v1/auth/challenge", "198.51.100.149", `{"aci":"`+unknown.String()+`"}`, "")
	if a.Code != b.Code {
		t.Fatalf("status differs by account existence: known %d, unknown %d", a.Code, b.Code)
	}
	var ga, gb struct {
		Challenge string `json:"challenge"`
		ExpiresIn int    `json:"expires_in"`
	}
	_ = json.Unmarshal(a.Body.Bytes(), &ga)
	_ = json.Unmarshal(b.Body.Bytes(), &gb)
	if len(ga.Challenge) != len(gb.Challenge) || ga.ExpiresIn != gb.ExpiresIn {
		t.Fatal("the challenge response shape differs by account existence")
	}
}

// TestAnAccountWithNoKeyCannotReauthenticate covers installations that predate
// migration 0003 — they fail exactly as before, and identically to everything
// else.
func TestAnAccountWithNoKeyCannotReauthenticate(t *testing.T) {
	h, db := reauthStack(t)
	aci, _ := enrol(t, h, db, "198.51.100.150")

	_, priv, _ := ed25519.GenerateKey(nil)
	challenge := requestChallenge(t, h, "198.51.100.151", aci)
	body := signedReauth(aci, challenge, priv)
	if rec := jsonPost(h, "/v1/auth/reauth", "198.51.100.151", body, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("an account with no published key re-authenticated: status %d", rec.Code)
	}
}

// TestTheAccountKeyIsWriteOnce — replacing it would convert a stolen session
// into permanent access and lock the real owner out.
func TestTheAccountKeyIsWriteOnce(t *testing.T) {
	h, db := reauthStack(t)
	_, token := enrol(t, h, db, "198.51.100.152")
	pub, _ := publishKey(t, h, "198.51.100.152", token)

	// Re-publishing the same value stays a success, so the client's
	// publish-if-absent path is safe to retry.
	same := `{"key":"` + base64.StdEncoding.EncodeToString(pub) + `"}`
	if rec := jsonPut(h, "/v1/auth/key", "198.51.100.152", same, token); rec.Code != http.StatusNoContent {
		t.Fatalf("republishing the identical key failed: status %d", rec.Code)
	}

	other, _, _ := ed25519.GenerateKey(nil)
	body := `{"key":"` + base64.StdEncoding.EncodeToString(other) + `"}`
	if rec := jsonPut(h, "/v1/auth/key", "198.51.100.152", body, token); rec.Code != http.StatusConflict {
		t.Fatalf("the account key was replaceable: status %d", rec.Code)
	}
}

// TestOnlyThePublicHalfIsStored reads the column rather than the API, because
// the claim is about what a seized database holds.
func TestOnlyThePublicHalfIsStored(t *testing.T) {
	h, db := reauthStack(t)
	aci, token := enrol(t, h, db, "198.51.100.153")
	pub, priv := publishKey(t, h, "198.51.100.153", token)

	stored, err := db.AccountKey(context.Background(), aci)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if !bytes.Equal(stored, pub) {
		t.Fatal("the stored key is not the published public key")
	}
	if len(stored) != ed25519.PublicKeySize {
		t.Fatalf("stored key is %d bytes, want %d", len(stored), ed25519.PublicKeySize)
	}
	if bytes.Contains(priv.Seed(), stored) && len(stored) == ed25519.SeedSize {
		t.Fatal("the stored value looks like private key material")
	}
}

// TestPublishingAKeyRequiresAuthentication — the route names no account, so an
// unauthenticated caller must not reach it at all.
func TestPublishingAKeyRequiresAuthentication(t *testing.T) {
	h, _ := reauthStack(t)
	pub, _, _ := ed25519.GenerateKey(nil)
	body := `{"key":"` + base64.StdEncoding.EncodeToString(pub) + `"}`
	if rec := jsonPut(h, "/v1/auth/key", "198.51.100.154", body, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("publishing a key without a session: status %d", rec.Code)
	}
}
