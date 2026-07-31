//go:build integration

// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
//
// P4.S03's "Done when": reuse rejected, expiry enforced, brute force throttled —
// against a real Postgres and a real Redis, not against fakes.
//
// The distinction matters more than usual here. Single-use is enforced by
// `DELETE ... RETURNING` being atomic, and expiry by a predicate evaluated
// against the *database's* clock. A fake store would satisfy both by construction
// and prove nothing about either. So these run inside the compose network, where
// postgres and redis are reachable by service name and remain unpublished to the
// host — see docker-compose.test.yml.
//
// Guarded by a build tag so `go test ./...` on a developer machine stays fast and
// dependency-free. Scripts/verify-relay-integration.sh is what runs them.

package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"cipher.relay/internal/api"
	"cipher.relay/internal/auth"
	"cipher.relay/internal/cache"
	"cipher.relay/internal/httpx"
	"cipher.relay/internal/invite"
	"cipher.relay/internal/logging"
	"cipher.relay/internal/ratelimit"
	"cipher.relay/internal/store"
	"net/netip"
)

func testDB(t *testing.T) *store.DB {
	t.Helper()
	url := os.Getenv("RELAY_DATABASE_URL")
	if url == "" {
		t.Fatal("RELAY_DATABASE_URL is not set; run via Scripts/verify-relay-integration.sh")
	}

	db, err := store.Open(context.Background(), url)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(db.Close)

	if _, err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func testLimiter(t *testing.T) *ratelimit.Limiter {
	t.Helper()
	addr := os.Getenv("RELAY_REDIS_ADDR")
	if addr == "" {
		t.Fatal("RELAY_REDIS_ADDR is not set")
	}

	rc, err := cache.Open(context.Background(), addr, os.Getenv("RELAY_REDIS_PASSWORD"))
	if err != nil {
		t.Fatalf("open redis: %v", err)
	}
	t.Cleanup(func() { _ = rc.Close() })

	// A per-test pepper keys the buckets, so tests cannot collide with each
	// other or with a previous run's leftovers.
	pepper := []byte(t.Name() + uuid.NewString())
	return ratelimit.New(rc.Scripter(), pepper)
}

func newAccount() store.Account {
	return store.Account{
		ACI:            uuid.New(),
		IdentityKey:    make([]byte, 33),
		RegistrationID: 1234,
	}
}

func issue(t *testing.T, db *store.DB, ttl time.Duration) invite.Code {
	t.Helper()
	code, err := api.IssueInvite(context.Background(), db, ttl)
	if err != nil {
		t.Fatalf("issue invite: %v", err)
	}
	return code
}

func redeem(t *testing.T, db *store.DB, code invite.Code, account store.Account) error {
	t.Helper()
	token, err := auth.Generate()
	if err != nil {
		t.Fatalf("generate initial session: %v", err)
	}
	return db.RedeemInvite(context.Background(), code.Hash(), account, store.InitialSession{
		TokenHash: token.Hash(), ExpiresAt: time.Now().Add(api.SessionTTL),
	})
}

// --- Single use ------------------------------------------------------------

func TestRedeemConsumesTheInvite(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	code := issue(t, db, time.Hour)

	account := newAccount()
	if err := redeem(t, db, code, account); err != nil {
		t.Fatalf("first redemption failed: %v", err)
	}

	exists, err := db.AccountExists(ctx, account.ACI)
	if err != nil {
		t.Fatalf("account exists: %v", err)
	}
	if !exists {
		t.Fatal("redemption reported success but created no account")
	}
}

func TestSessionInsertFailureRollsBackAccountAndInvite(t *testing.T) {
	// The account, first session, and invite consumption are one operation. A
	// one-byte hash deliberately violates session_tokens' 32-byte CHECK after
	// the account insert has run. The same invite must then still redeem: merely
	// checking that the first call errored would pass against the orphaning bug.
	ctx := context.Background()
	db := testDB(t)
	code := issue(t, db, time.Hour)
	account := newAccount()

	err := db.RedeemInvite(ctx, code.Hash(), account, store.InitialSession{
		TokenHash: []byte{0x01}, ExpiresAt: time.Now().Add(api.SessionTTL),
	})
	if err == nil {
		t.Fatal("an invalid session hash unexpectedly committed")
	}

	exists, lookupErr := db.AccountExists(ctx, account.ACI)
	if lookupErr != nil {
		t.Fatalf("account exists: %v", lookupErr)
	}
	if exists {
		t.Fatal("the account survived a failed initial-session insert")
	}

	if err := redeem(t, db, code, account); err != nil {
		t.Fatalf("the failed transaction still spent its invite: %v", err)
	}
	if sessions, err := db.CountSessionsForAccount(ctx, account.ACI); err != nil {
		t.Fatalf("count sessions: %v", err)
	} else if sessions != 1 {
		t.Fatalf("successful redemption created %d sessions, want exactly 1", sessions)
	}
}

func TestReuseIsRejected(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	code := issue(t, db, time.Hour)

	if err := redeem(t, db, code, newAccount()); err != nil {
		t.Fatalf("first redemption failed: %v", err)
	}

	second := newAccount()
	err := redeem(t, db, code, second)
	if err != store.ErrInviteNotRedeemable {
		t.Fatalf("second redemption returned %v, want ErrInviteNotRedeemable", err)
	}

	// And it must not have created the account as a side effect before failing.
	exists, err := db.AccountExists(ctx, second.ACI)
	if err != nil {
		t.Fatalf("account exists: %v", err)
	}
	if exists {
		t.Fatal("a rejected redemption still created an account")
	}
}

func TestRedeemedInviteIsDeletedNotFlagged(t *testing.T) {
	// docs/BACKEND.md §2.2 and §4: a flag is a record that outlives the thing it
	// describes. This asserts the row is *gone*, which is also what makes an
	// already-used code indistinguishable from one that never existed.
	ctx := context.Background()
	db := testDB(t)

	before, err := db.CountInvites(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}

	code := issue(t, db, time.Hour)

	during, err := db.CountInvites(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if during != before+1 {
		t.Fatalf("issuing added %d rows, want 1", during-before)
	}

	if err := redeem(t, db, code, newAccount()); err != nil {
		t.Fatalf("redeem: %v", err)
	}

	after, err := db.CountInvites(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if after != before {
		t.Fatalf("after redemption there are %d invites, want %d — the row was "+
			"flagged rather than deleted", after, before)
	}
}

func TestConcurrentRedemptionYieldsExactlyOneAccount(t *testing.T) {
	// The reason RedeemInvite is `DELETE ... RETURNING` and not SELECT-then-
	// DELETE. With the read-then-write version, every one of these goroutines
	// passes the existence check before any of them deletes, and a single-use
	// code creates N accounts. The window is narrow and trivially reachable by
	// sending the same request twice at once.
	db := testDB(t)
	code := issue(t, db, time.Hour)

	const attempts = 16
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		successes int
		other     []error
	)

	start := make(chan struct{})
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // release them together, to actually contend
			err := redeem(t, db, code, newAccount())

			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				successes++
			case err == store.ErrInviteNotRedeemable:
				// expected for the losers
			default:
				other = append(other, err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if len(other) > 0 {
		t.Fatalf("unexpected errors: %v", other)
	}
	if successes != 1 {
		t.Fatalf("%d of %d concurrent redemptions succeeded, want exactly 1",
			successes, attempts)
	}
}

// --- Expiry ----------------------------------------------------------------

func TestExpiredInviteIsRejected(t *testing.T) {
	db := testDB(t)

	// Issued already expired. The predicate lives in the SQL and is evaluated
	// against now() — the database's clock, not this process's.
	code := issue(t, db, -time.Minute)

	err := redeem(t, db, code, newAccount())
	if err != store.ErrInviteNotRedeemable {
		t.Fatalf("expired invite returned %v, want ErrInviteNotRedeemable", err)
	}
}

func TestExpiryIsIndistinguishableFromUnknown(t *testing.T) {
	// An attacker who could tell "this code expired" from "this code never
	// existed" would learn that a guess had once been real.
	db := testDB(t)

	expired := issue(t, db, -time.Minute)
	unknown, err := invite.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	errExpired := redeem(t, db, expired, newAccount())
	errUnknown := redeem(t, db, unknown, newAccount())

	if errExpired != errUnknown {
		t.Fatalf("expired gave %v, unknown gave %v — these must be identical",
			errExpired, errUnknown)
	}
}

func TestSweepRemovesExpiredInvites(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)

	issue(t, db, -time.Hour)
	live := issue(t, db, time.Hour)

	if _, err := db.DeleteExpiredInvites(ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	// The live one must survive: a sweep that deletes everything passes a naive
	// "the expired one is gone" assertion while breaking the feature.
	if err := redeem(t, db, live, newAccount()); err != nil {
		t.Fatalf("the sweep removed a live invite: %v", err)
	}
}

// --- Brute force -----------------------------------------------------------

func TestBruteForceIsThrottled(t *testing.T) {
	ctx := context.Background()
	limiter := testLimiter(t)
	limit := ratelimit.Limit{Capacity: 5, Window: time.Hour}
	subject := limiter.Subject("test", "198.51.100.7")

	for i := range limit.Capacity {
		d, err := limiter.Allow(ctx, subject, limit)
		if err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
		if !d.OK {
			t.Fatalf("attempt %d of %d was refused; the bucket should hold %d",
				i+1, limit.Capacity, limit.Capacity)
		}
	}

	d, err := limiter.Allow(ctx, subject, limit)
	if err != nil {
		t.Fatalf("allow: %v", err)
	}
	if d.OK {
		t.Fatal("the attempt past capacity was allowed; the bucket does not throttle")
	}
	if d.RetryAfter <= 0 {
		t.Fatal("a refusal must say how long to wait")
	}
}

func TestThrottlingIsPerSubject(t *testing.T) {
	// A limiter that shares one bucket across all callers is a denial-of-service
	// primitive: one attacker exhausts it and nobody can redeem an invite.
	ctx := context.Background()
	limiter := testLimiter(t)
	limit := ratelimit.Limit{Capacity: 2, Window: time.Hour}

	attacker := limiter.Subject("test", "198.51.100.7")
	bystander := limiter.Subject("test", "203.0.113.9")

	for range limit.Capacity + 2 {
		if _, err := limiter.Allow(ctx, attacker, limit); err != nil {
			t.Fatalf("allow: %v", err)
		}
	}

	d, err := limiter.Allow(ctx, bystander, limit)
	if err != nil {
		t.Fatalf("allow: %v", err)
	}
	if !d.OK {
		t.Fatal("one subject exhausting its bucket blocked another")
	}
}

func TestBucketRefills(t *testing.T) {
	// A bucket that empties and never refills is a permanent lockout rather than
	// a rate limit. Short window so the test does not sleep meaningfully.
	ctx := context.Background()
	limiter := testLimiter(t)
	limit := ratelimit.Limit{Capacity: 2, Window: 400 * time.Millisecond}
	subject := limiter.Subject("test", "198.51.100.7")

	for range limit.Capacity {
		if _, err := limiter.Allow(ctx, subject, limit); err != nil {
			t.Fatalf("allow: %v", err)
		}
	}
	if d, _ := limiter.Allow(ctx, subject, limit); d.OK {
		t.Fatal("bucket did not empty")
	}

	// One token is earned after Window/Capacity; sleep past that.
	time.Sleep(300 * time.Millisecond)

	d, err := limiter.Allow(ctx, subject, limit)
	if err != nil {
		t.Fatalf("allow: %v", err)
	}
	if !d.OK {
		t.Fatal("bucket did not refill")
	}
}

func TestSubjectKeyDoesNotContainTheRawValue(t *testing.T) {
	// A Redis key is a log with a TTL. `KEYS *` on a dump must not enumerate the
	// addresses that recently spoke to the relay (docs/BACKEND.md §7).
	limiter := testLimiter(t)
	const addr = "198.51.100.7"

	key := limiter.Subject("invite-redeem", addr)
	if strings.Contains(key, addr) {
		t.Fatalf("the bucket key contains the raw address: %s", key)
	}
}

// --- End to end through the handler ---------------------------------------

func redeemBody(code, identityKey string, registrationID uint32) io.Reader {
	b, _ := json.Marshal(map[string]any{
		"code":            code,
		"identity_key":    identityKey,
		"registration_id": registrationID,
	})
	return strings.NewReader(string(b))
}

func newHandler(t *testing.T) (http.Handler, *store.DB) {
	t.Helper()
	db := testDB(t)
	limiter := testLimiter(t)
	log := logging.New(io.Discard, slog.LevelError)
	mux := http.NewServeMux()
	// The invite handler needs the auth handler because redemption issues a
	// session: an account created without one could authenticate only through
	// the invite it just consumed.
	api.NewInviteHandler(db, limiter, api.NewAuthHandler(db, limiter, log), log).Routes(mux)
	return mux, db
}

func post(h http.Handler, from string, body io.Reader) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/v1/invite/redeem", body)
	r.RemoteAddr = from + ":54321"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestRedeemEndpointCreatesAnAccount(t *testing.T) {
	h, db := newHandler(t)
	code := issue(t, db, time.Hour)
	key := base64.StdEncoding.EncodeToString(make([]byte, 33))

	rec := post(h, "198.51.100.10", redeemBody(code.String(), key, 42))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body.String())
	}

	var got struct {
		ACI string `json:"aci"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	aci, err := uuid.Parse(got.ACI)
	if err != nil {
		t.Fatalf("aci is not a uuid: %v", err)
	}

	exists, err := db.AccountExists(context.Background(), aci)
	if err != nil || !exists {
		t.Fatalf("account %s was not created (err=%v)", aci, err)
	}
}

func TestRedeemEndpointRejectsReuseWithoutDetail(t *testing.T) {
	h, db := newHandler(t)
	code := issue(t, db, time.Hour)
	key := base64.StdEncoding.EncodeToString(make([]byte, 33))

	if rec := post(h, "198.51.100.11", redeemBody(code.String(), key, 42)); rec.Code != http.StatusCreated {
		t.Fatalf("first redemption: %d", rec.Code)
	}

	rec := post(h, "198.51.100.11", redeemBody(code.String(), key, 42))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("reuse status = %d, want 401", rec.Code)
	}

	// The body must not hint at *why*. "already redeemed" would confirm the code
	// had been real.
	body := strings.ToLower(rec.Body.String())
	for _, leak := range []string{"redeem", "expired", "used", "exist", "found"} {
		if strings.Contains(body, leak) {
			t.Errorf("the response leaks %q: %s", leak, rec.Body.String())
		}
	}
}

func TestRedeemEndpointResponseIsIdenticalForUnknownAndUsed(t *testing.T) {
	h, db := newHandler(t)
	key := base64.StdEncoding.EncodeToString(make([]byte, 33))

	used := issue(t, db, time.Hour)
	if rec := post(h, "198.51.100.12", redeemBody(used.String(), key, 42)); rec.Code != http.StatusCreated {
		t.Fatalf("setup redemption: %d", rec.Code)
	}
	unknown, err := invite.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	expired := issue(t, db, -time.Minute)

	var seen []string
	for _, c := range []invite.Code{used, unknown, expired} {
		rec := post(h, "198.51.100.12", redeemBody(c.String(), key, 42))
		seen = append(seen, fmt.Sprintf("%d|%s", rec.Code, strings.TrimSpace(rec.Body.String())))
	}
	for i := 1; i < len(seen); i++ {
		if seen[i] != seen[0] {
			t.Fatalf("responses differ:\n  %s\n  %s", seen[0], seen[i])
		}
	}
}

func TestRedeemEndpointThrottlesBruteForce(t *testing.T) {
	// The plan's third "Done when". 5 per hour per address (docs/BACKEND.md §5).
	h, _ := newHandler(t)
	key := base64.StdEncoding.EncodeToString(make([]byte, 33))

	unknown, err := invite.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	var throttled bool
	for i := range 10 {
		rec := post(h, "198.51.100.13", redeemBody(unknown.String(), key, 42))
		if rec.Code == http.StatusTooManyRequests {
			throttled = true
			if rec.Header().Get("Retry-After") == "" {
				t.Error("a 429 must carry Retry-After")
			}
			if i < 5 {
				t.Errorf("throttled after only %d attempts; capacity is 5", i)
			}
			break
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status %d, want 401", i, rec.Code)
		}
	}
	if !throttled {
		t.Fatal("ten wrong guesses were never throttled")
	}
}

func TestRedeemEndpointRateLimitsBeforeParsing(t *testing.T) {
	// Parsing first would let an attacker spend the server's CPU at whatever
	// rate they liked and consume no token when the body was junk.
	h, _ := newHandler(t)

	var throttled bool
	for range 10 {
		rec := post(h, "198.51.100.14", strings.NewReader("{not json"))
		if rec.Code == http.StatusTooManyRequests {
			throttled = true
			break
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status %d, want 400", rec.Code)
		}
	}
	if !throttled {
		t.Fatal("malformed bodies consumed no rate-limit tokens")
	}
}

func TestRedeemEndpointRejectsBadInput(t *testing.T) {
	h, db := newHandler(t)
	key := base64.StdEncoding.EncodeToString(make([]byte, 33))

	cases := map[string]io.Reader{
		"malformed code": redeemBody("not-a-code", key, 42),
		"empty code":     redeemBody("", key, 42),
		"identity key too short": redeemBody(issue(t, db, time.Hour).String(),
			base64.StdEncoding.EncodeToString(make([]byte, 8)), 42),
		"identity key not base64": redeemBody(issue(t, db, time.Hour).String(), "!!!!", 42),
		"zero registration id":    redeemBody(issue(t, db, time.Hour).String(), key, 0),
		"unknown field":           strings.NewReader(`{"code":"x","registrationId":1}`),
	}

	// A distinct address per case so the rate limit does not mask a wrong status.
	i := 20
	for name, body := range cases {
		i++
		rec := post(h, fmt.Sprintf("198.51.100.%d", i), body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", name, rec.Code)
		}
	}
}

// ---------------------------------------------------------------------------
// P5.S05 — the relay behind a reverse proxy.
//
// These run against a real Redis because the property is about bucket identity,
// and bucket identity is a Redis key. A fake limiter would prove only that the
// middleware sets a field.
// ---------------------------------------------------------------------------

// behindProxy wraps a handler as it is deployed in P5: requests arrive from the
// proxy, and the real client is named in X-Real-IP. trusted is the set of peers
// permitted to make that claim — empty means nobody is.
func behindProxy(t *testing.T, h http.Handler, trusted ...string) http.Handler {
	t.Helper()
	var prefixes []netip.Prefix
	for _, s := range trusted {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatalf("bad prefix %q: %v", s, err)
		}
		prefixes = append(prefixes, p)
	}
	return httpx.RealIP(prefixes)(h)
}

func postVia(h http.Handler, proxyAddr, realIP string, body io.Reader) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/v1/invite/redeem", body)
	r.RemoteAddr = proxyAddr + ":54321"
	if realIP != "" {
		r.Header.Set("X-Real-IP", realIP)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestRedeemRateLimitIsPerRealClientBehindAProxy(t *testing.T) {
	// The defect this exists to prevent: with every request arriving from the
	// proxy, all callers share one bucket, so the first attacker to spend the
	// 5/hour budget denies invite redemption to everyone. That is a global
	// onboarding outage triggered by any single IP.
	//
	// Against the pre-P5.S05 relay this test fails on the second client.
	mux, _ := newHandler(t)
	h := behindProxy(t, mux, "172.18.0.0/16")
	key := base64.StdEncoding.EncodeToString(make([]byte, 33))

	unknown, err := invite.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Exhaust the first client's budget entirely.
	var exhausted bool
	for range 10 {
		rec := postVia(h, "172.18.0.1", "198.51.100.21", redeemBody(unknown.String(), key, 42))
		if rec.Code == http.StatusTooManyRequests {
			exhausted = true
			break
		}
	}
	if !exhausted {
		t.Fatal("first client was never throttled; the limit is not being applied at all")
	}

	// A different real client, same proxy, must be unaffected.
	rec := postVia(h, "172.18.0.1", "198.51.100.22", redeemBody(unknown.String(), key, 42))
	if rec.Code == http.StatusTooManyRequests {
		t.Fatal("a second client behind the same proxy inherited the first client's " +
			"exhausted budget — the per-IP limit has collapsed into one global bucket")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for an unknown code", rec.Code)
	}
}

func TestSpoofedRealIPCannotEscapeTheRateLimitWhenUntrusted(t *testing.T) {
	// The opposite failure, and the worse one: if the header were believed from
	// an untrusted peer, a client would mint a fresh bucket per request and the
	// limit would not exist. Here nothing is trusted, so the header is inert.
	mux, _ := newHandler(t)
	h := behindProxy(t, mux) // no trusted prefixes at all
	key := base64.StdEncoding.EncodeToString(make([]byte, 33))

	unknown, err := invite.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	var throttled bool
	for i := range 10 {
		// A new spoofed identity every single request.
		spoof := fmt.Sprintf("203.0.113.%d", i+1)
		rec := postVia(h, "198.51.100.30", spoof, redeemBody(unknown.String(), key, 42))
		if rec.Code == http.StatusTooManyRequests {
			throttled = true
			break
		}
	}
	if !throttled {
		t.Fatal("rotating X-Real-IP defeated the rate limit — the header is being " +
			"believed from an untrusted peer")
	}
}
