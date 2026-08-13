//go:build integration

// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
//
// P4.S10 — the adversarial pass.
//
// Most of what the step lists is already covered by the per-step suites, and
// re-testing it here would be volume rather than coverage. What this file is for
// is the cases **no single step owned**, which are the cross-cutting ones:
//
//   - Every route, swept for authentication, from a table checked against the
//     source so a new route cannot be added without appearing here.
//   - One account acting against another's data through every route that takes
//     an identifier.
//   - Replay, in the three forms this API can express.
//   - Retention end to end: after an exchange completes, what is left.

package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"cipher.relay/internal/api"
	"cipher.relay/internal/auth"
	"cipher.relay/internal/blob"
	"cipher.relay/internal/cache"
	"cipher.relay/internal/logging"
	"cipher.relay/internal/reauth"
	"cipher.relay/internal/store"
)

// fullStack wires every handler, as main does.
func fullStack(t *testing.T) (http.Handler, *store.DB, *blob.Store) {
	t.Helper()
	db := testDB(t)
	limiter := testLimiter(t)
	log := logging.New(io.Discard, slog.LevelError)

	blobs, err := blob.Open(t.TempDir())
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
	// Re-authentication (AUDIT 5.41). Registered here so the authentication
	// sweep below actually reaches PUT /v1/auth/key: a route the harness does
	// not mount answers 404, and a sweep that accepts 404 as "refused" would
	// pass against an endpoint that was never guarded at all.
	rc, err := cache.Open(context.Background(),
		os.Getenv("RELAY_REDIS_ADDR"), os.Getenv("RELAY_REDIS_PASSWORD"))
	if err != nil {
		t.Fatalf("open redis: %v", err)
	}
	t.Cleanup(func() { _ = rc.Close() })
	api.NewReauthHandler(db, limiter, reauth.NewStore(rc.KV()), authHandler, log).Routes(mux)
	return mux, db, blobs
}

// authenticatedRoutes is every route that must refuse an unauthenticated caller.
//
// TestEveryRouteIsAccountedFor checks this table against the source, so a route
// added to any handler and forgotten here fails the build rather than shipping
// unguarded.
var authenticatedRoutes = []struct{ method, path string }{
	{http.MethodPost, "/v1/invite"},
	{http.MethodPost, "/v1/auth/rotate"},
	{http.MethodPut, "/v1/auth/key"},
	{http.MethodDelete, "/v1/auth"},
	{http.MethodDelete, "/v1/auth/all"},
	{http.MethodPut, "/v1/keys"},
	{http.MethodGet, "/v1/keys/{aci}"},
	{http.MethodPost, "/v1/messages"},
	{http.MethodGet, "/v1/messages"},
	{http.MethodPost, "/v1/messages/ack"},
	{http.MethodPost, "/v1/blobs"},
	{http.MethodGet, "/v1/blobs/{id}"},
	{http.MethodDelete, "/v1/blobs/{id}"},
}

// publicRoutes are deliberately reachable without a session.
//
// Exactly one, and it has to be: redemption is how an account comes into
// existence, so requiring a session for it would be a bootstrap paradox. It is
// rate-limited by source address instead.
var publicRoutes = map[string]bool{
	"POST /v1/invite/redeem": true,
	// Re-authentication (AUDIT 5.41). Unauthenticated by necessity: having no
	// usable session token is the situation these two exist for. What guards
	// them instead is a signature over a server-chosen challenge, plus rate
	// limits on both the address and the account — see internal/api/reauth.go.
	"POST /v1/auth/challenge": true,
	"POST /v1/auth/reauth":    true,
}

var routeRE = regexp.MustCompile(`"(GET|POST|PUT|DELETE) (/v1[^"]*)"`)

func TestEveryRouteIsAccountedFor(t *testing.T) {
	// Reads the handler source rather than trusting the table. A route that
	// exists in the code and not here would otherwise be exempt from the
	// authentication sweep below simply by having been forgotten — which is
	// precisely how an unguarded endpoint ships.
	declared := map[string]bool{}
	for _, r := range authenticatedRoutes {
		declared[r.method+" "+r.path] = true
	}

	files, err := filepath.Glob("../api/*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("could not read the api package source: %v", err)
	}

	found := map[string]bool{}
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, m := range routeRE.FindAllStringSubmatch(string(src), -1) {
			found[m[1]+" "+m[2]] = true
		}
	}
	if len(found) == 0 {
		t.Fatal("no routes found in the api source — this check is not checking anything")
	}

	var missing []string
	for route := range found {
		if !declared[route] && !publicRoutes[route] {
			missing = append(missing, route)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("routes exist in internal/api but are in neither authenticatedRoutes "+
			"nor publicRoutes, so nothing checks that they require a session: %v", missing)
	}

	for route := range declared {
		if !found[route] {
			t.Errorf("authenticatedRoutes lists %q, which no handler registers", route)
		}
	}
}

// populate fills a path template with values that would be valid.
func populate(path string) string {
	path = strings.ReplaceAll(path, "{aci}", uuid.NewString())
	return strings.ReplaceAll(path, "{id}", uuid.NewString())
}

func TestEveryAuthenticatedRouteRefusesEveryBadCredential(t *testing.T) {
	ctx := context.Background()
	h, db, _ := fullStack(t)
	aci, live := enrol(t, h, db, "198.51.100.150")

	revoked, err := auth.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := db.CreateSession(ctx, revoked.Hash(), aci, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := db.DeleteSession(ctx, revoked.Hash()); err != nil {
		t.Fatalf("revoke: %v", err)
	}

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

	credentials := map[string]string{
		"none":         "",
		"garbage":      "not-a-token",
		"unknown":      unknown.String(),
		"revoked":      revoked.String(),
		"expired":      expired.String(),
		"wrong scheme": "",
	}

	for _, route := range authenticatedRoutes {
		for name, token := range credentials {
			r := httptestNewRequest(route.method, populate(route.path), bytes.NewReader(nil))
			r.RemoteAddr = "198.51.100.151:1"
			switch {
			case name == "wrong scheme":
				r.Header.Set("Authorization", "Basic "+live)
			case token != "":
				r.Header.Set("Authorization", "Bearer "+token)
			}

			rec := serve(h, r)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("%s %s with a %s credential: status %d, want 401",
					route.method, route.path, name, rec.Code)
			}
		}
	}
}

// httptestNewRequest is a thin alias so the sweep above reads clearly.
func httptestNewRequest(method, path string, body io.Reader) *http.Request {
	return request(method, path, "", "", body)
}

// --- One account against another ------------------------------------------

func TestOneAccountCannotReachAnothersData(t *testing.T) {
	// Every route that takes an identifier, driven by an account that is not the
	// owner. The prekey directory is deliberately absent: fetching a peer's
	// bundle is the entire point of it, and it is guarded by a rate limit rather
	// than by ownership.
	ctx := context.Background()
	h, db, blobs := fullStack(t)

	victim, victimToken := enrol(t, h, db, "198.51.100.152")
	_, attacker := enrol(t, h, db, "198.51.100.153")
	_, senderToken := enrol(t, h, db, "198.51.100.154")

	// The victim has a message waiting and an attachment uploaded.
	if rec := do(h, http.MethodPost, "/v1/messages", senderToken, "198.51.100.154",
		sendBody(victim, envelope(96, 0x5A))); rec.Code != http.StatusAccepted {
		t.Fatalf("send: %d", rec.Code)
	}
	msgs, _ := fetchMessages(t, h, victimToken, "198.51.100.152")
	if len(msgs) != 1 {
		t.Fatalf("setup: %d messages", len(msgs))
	}
	blobID, _ := upload(t, h, victimToken, "198.51.100.152", randomBytes(1024))

	t.Run("cannot read the victim's queue", func(t *testing.T) {
		got, _ := fetchMessages(t, h, attacker, "198.51.100.153")
		if len(got) != 0 {
			t.Fatalf("the attacker sees %d of the victim's messages", len(got))
		}
	})

	t.Run("cannot acknowledge the victim's message", func(t *testing.T) {
		rec := do(h, http.MethodPost, "/v1/messages/ack", attacker, "198.51.100.153",
			ackBody(msgs[0].ID))
		if rec.Code != http.StatusOK {
			t.Fatalf("ack: %d", rec.Code)
		}
		present, err := db.MessageExists(ctx, uuid.MustParse(msgs[0].ID))
		if err != nil {
			t.Fatalf("exists: %v", err)
		}
		if !present {
			t.Fatal("the attacker deleted the victim's undelivered message")
		}
	})

	t.Run("cannot replace the victim's prekeys", func(t *testing.T) {
		// There is no parameter through which to name another account, which is
		// the defence; this confirms publishing as the attacker leaves the
		// victim untouched.
		before, err := db.CountOneTimePreKeys(ctx, victim)
		if err != nil {
			t.Fatalf("count: %v", err)
		}
		if rec := do(h, http.MethodPut, "/v1/keys", attacker, "198.51.100.153",
			uploadBody(3, true)); rec.Code != http.StatusOK {
			t.Fatalf("publish: %d", rec.Code)
		}
		after, err := db.CountOneTimePreKeys(ctx, victim)
		if err != nil {
			t.Fatalf("count: %v", err)
		}
		if after != before {
			t.Fatalf("the victim's pool changed from %d to %d", before, after)
		}
	})

	t.Run("cannot revoke the victim's sessions", func(t *testing.T) {
		// Its own throwaway account, not the shared attacker. revoke-all
		// deliberately includes the caller's own session (that is what "sign out
		// everywhere" means), so running it with the shared token would leave
		// every later subtest holding a revoked credential — which is exactly
		// how the first version of this test failed, with a 401 that looked like
		// a defect in the blob capability rather than in the fixture.
		_, throwaway := enrol(t, h, db, "198.51.100.159")

		if rec := do(h, http.MethodDelete, "/v1/auth/all", throwaway, "198.51.100.159",
			nil); rec.Code != http.StatusNoContent {
			t.Fatalf("revoke all: %d", rec.Code)
		}
		if rec := do(h, http.MethodGet, "/v1/messages", victimToken, "198.51.100.152",
			nil); rec.Code != http.StatusOK {
			t.Fatal("one account's revoke-all ended another's session")
		}
		// And it did end its own, which is the other half of the promise.
		if rec := do(h, http.MethodGet, "/v1/messages", throwaway, "198.51.100.159",
			nil); rec.Code != http.StatusUnauthorized {
			t.Fatal("revoke-all left the calling session alive")
		}
	})

	t.Run("a blob is a capability, and the attacker holding it may use it", func(t *testing.T) {
		// Stated as an expectation rather than discovered as a surprise. The id
		// IS the authorisation (docs/BACKEND.md §2.8), so an account that has
		// obtained one can fetch and delete the bytes — which is why it travels
		// only inside the end-to-end ciphertext, and why the bytes are encrypted
		// with a key that travels with it.
		if rec := do(h, http.MethodGet, "/v1/blobs/"+blobID.String(), attacker,
			"198.51.100.153", nil); rec.Code != http.StatusOK {
			t.Fatalf("holding the capability did not grant access: %d", rec.Code)
		}
		// And without the id, nothing.
		if rec := do(h, http.MethodGet, "/v1/blobs/"+uuid.NewString(), attacker,
			"198.51.100.153", nil); rec.Code != http.StatusNotFound {
			t.Fatalf("a guessed capability was accepted: %d", rec.Code)
		}
		_ = blobs
	})
}

// --- Replay ----------------------------------------------------------------

func TestReplay(t *testing.T) {
	ctx := context.Background()
	h, db, _ := fullStack(t)
	_, senderToken := enrol(t, h, db, "198.51.100.155")
	recipient, recipientToken := enrol(t, h, db, "198.51.100.156")

	t.Run("a resent envelope is a second message, not a duplicate of the first", func(t *testing.T) {
		// The relay cannot deduplicate opaque bytes without parsing them, and it
		// must not parse them. Replay protection is the ratchet's job, on the
		// client, which rejects a repeated message key. What the relay owes is
		// that the two are distinct rows with distinct ids, so acknowledging one
		// does not silently destroy the other.
		payload := envelope(96, 0x6B)
		for range 2 {
			if rec := do(h, http.MethodPost, "/v1/messages", senderToken, "198.51.100.155",
				sendBody(recipient, payload)); rec.Code != http.StatusAccepted {
				t.Fatalf("send: %d", rec.Code)
			}
		}
		msgs, _ := fetchMessages(t, h, recipientToken, "198.51.100.156")
		if len(msgs) != 2 {
			t.Fatalf("got %d messages, want 2", len(msgs))
		}
		if msgs[0].ID == msgs[1].ID {
			t.Fatal("two sends produced one id")
		}

		if rec := do(h, http.MethodPost, "/v1/messages/ack", recipientToken, "198.51.100.156",
			ackBody(msgs[0].ID)); rec.Code != http.StatusOK {
			t.Fatalf("ack: %d", rec.Code)
		}
		rest, _ := fetchMessages(t, h, recipientToken, "198.51.100.156")
		if len(rest) != 1 {
			t.Fatalf("acknowledging one of two left %d", len(rest))
		}
	})

	t.Run("a replayed acknowledgement cannot resurrect or destroy anything", func(t *testing.T) {
		msgs, _ := fetchMessages(t, h, recipientToken, "198.51.100.156")
		if len(msgs) != 1 {
			t.Fatalf("setup: %d", len(msgs))
		}
		id := msgs[0].ID

		for range 3 {
			if rec := do(h, http.MethodPost, "/v1/messages/ack", recipientToken,
				"198.51.100.156", ackBody(id)); rec.Code != http.StatusOK {
				t.Fatalf("ack: %d", rec.Code)
			}
		}
		present, err := db.MessageExists(ctx, uuid.MustParse(id))
		if err != nil {
			t.Fatalf("exists: %v", err)
		}
		if present {
			t.Fatal("the message came back")
		}
	})

	t.Run("a redeemed invite cannot be replayed", func(t *testing.T) {
		code := issue(t, db, time.Hour)
		key := base64.StdEncoding.EncodeToString(make([]byte, 33))
		if rec := post(h, "198.51.100.157", redeemBody(code.String(), key, 11)); rec.Code != http.StatusCreated {
			t.Fatalf("first redemption: %d", rec.Code)
		}
		if rec := post(h, "198.51.100.157", redeemBody(code.String(), key, 11)); rec.Code != http.StatusUnauthorized {
			t.Fatalf("replayed redemption: %d, want 401", rec.Code)
		}
	})

	t.Run("a rotated token cannot be replayed", func(t *testing.T) {
		_, token := enrol(t, h, db, "198.51.100.158")
		rec := do(h, http.MethodPost, "/v1/auth/rotate", token, "198.51.100.158", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("rotate: %d", rec.Code)
		}
		if rec := do(h, http.MethodGet, "/v1/messages", token, "198.51.100.158", nil); rec.Code != http.StatusUnauthorized {
			t.Fatalf("the pre-rotation token still works: %d", rec.Code)
		}
	})
}

// --- Retention, end to end -------------------------------------------------

func TestAfterAnExchangeTheRelayHoldsNothingAboutIt(t *testing.T) {
	// The claim docs/THREAT_MODEL.md §3.1 makes, asserted against the database
	// rather than the API. What may remain is the accounts and their live
	// sessions — the participants exist and are signed in, which is not
	// something delivery was supposed to erase. What must not remain is any
	// record of the exchange.
	ctx := context.Background()
	h, db, blobs := fullStack(t)

	_, aliceToken := enrol(t, h, db, "198.51.100.160")
	bob, bobToken := enrol(t, h, db, "198.51.100.161")

	blobID, _ := upload(t, h, aliceToken, "198.51.100.160", randomBytes(2048))
	if rec := do(h, http.MethodPost, "/v1/messages", aliceToken, "198.51.100.160",
		sendBody(bob, envelope(256, 0x7C))); rec.Code != http.StatusAccepted {
		t.Fatalf("send: %d", rec.Code)
	}

	msgs, _ := fetchMessages(t, h, bobToken, "198.51.100.161")
	if len(msgs) != 1 {
		t.Fatalf("setup: %d messages", len(msgs))
	}
	if rec := do(h, http.MethodPost, "/v1/messages/ack", bobToken, "198.51.100.161",
		ackBody(msgs[0].ID)); rec.Code != http.StatusOK {
		t.Fatalf("ack: %d", rec.Code)
	}
	if rec := do(h, http.MethodDelete, "/v1/blobs/"+blobID.String(), bobToken,
		"198.51.100.161", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("blob delete: %d", rec.Code)
	}

	pending, err := db.CountPendingMessages(ctx, bob)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if pending != 0 {
		t.Errorf("%d messages remain", pending)
	}
	present, err := db.AttachmentExists(ctx, blobID)
	if err != nil {
		t.Fatalf("exists: %v", err)
	}
	if present {
		t.Error("the attachment row remains")
	}
	if blobs.Exists(blobID) {
		t.Error("the attachment bytes remain on disk")
	}

	// And nothing anywhere records that these two accounts exchanged anything.
	// The invite that created bob is gone, so not even the introduction is on
	// disk.
	n, err := db.CountInvites(ctx)
	if err != nil {
		t.Fatalf("count invites: %v", err)
	}
	if n != 0 {
		t.Errorf("%d invites remain after both were redeemed", n)
	}
}

func TestNoTableAccumulatesRowsAcrossACompletedExchange(t *testing.T) {
	// A structural version of the above: count every table before and after, and
	// require that only the tables that describe *participants* grew. A new
	// table quietly recording deliveries would show up here even if nobody
	// thought to write a test for it.
	ctx := context.Background()
	h, db, _ := fullStack(t)

	tables, err := db.TableNames(ctx)
	if err != nil {
		t.Fatalf("tables: %v", err)
	}
	before := map[string]int{}
	for _, name := range tables {
		before[name] = mustCount(t, db, name)
	}

	_, aliceToken := enrol(t, h, db, "198.51.100.162")
	bob, bobToken := enrol(t, h, db, "198.51.100.163")
	do(h, http.MethodPost, "/v1/messages", aliceToken, "198.51.100.162",
		sendBody(bob, envelope(96, 0x8D)))
	msgs, _ := fetchMessages(t, h, bobToken, "198.51.100.163")
	do(h, http.MethodPost, "/v1/messages/ack", bobToken, "198.51.100.163", ackBody(msgs[0].ID))

	// Accounts and their sessions are expected to grow: two people signed up.
	expected := map[string]bool{"accounts": true, "session_tokens": true, "schema_migrations": true}
	for _, name := range tables {
		after := mustCount(t, db, name)
		if after != before[name] && !expected[name] {
			t.Errorf("table %q grew from %d to %d across a completed exchange — "+
				"delivery should leave no trace (THREAT_MODEL.md §3.1)",
				name, before[name], after)
		}
	}
}

func mustCount(t *testing.T, db *store.DB, table string) int {
	t.Helper()
	n, err := db.CountRows(context.Background(), table)
	if err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// --- Rate limits are not optional -----------------------------------------

func TestEveryMutatingRouteIsRateLimited(t *testing.T) {
	// Not that a particular number is enforced — the per-step suites do that —
	// but that a limit exists at all on each route where its absence is a
	// resource or a security problem. A route added without one would otherwise
	// be discovered by whoever exploited it.
	h, db, _ := fullStack(t)
	_, token := enrol(t, h, db, "198.51.100.164")
	peer, _ := enrol(t, h, db, "198.51.100.165")

	cases := []struct {
		name    string
		attempt func() int
		ceiling int
	}{
		{"POST /v1/invite", func() int {
			return do(h, http.MethodPost, "/v1/invite", token, "198.51.100.164", nil).Code
		}, 40},
		{"PUT /v1/keys", func() int {
			return do(h, http.MethodPut, "/v1/keys", token, "198.51.100.164", uploadBody(1, true)).Code
		}, 40},
		{"POST /v1/blobs", func() int {
			return do(h, http.MethodPost, "/v1/blobs", token, "198.51.100.164",
				bytes.NewReader(randomBytes(64))).Code
		}, 200},
		{"GET /v1/keys/{aci}", func() int {
			return do(h, http.MethodGet, "/v1/keys/"+peer.String(), token, "198.51.100.164", nil).Code
		}, 60},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for i := range c.ceiling {
				if c.attempt() == http.StatusTooManyRequests {
					return
				}
				_ = i
			}
			t.Errorf("%s accepted %d consecutive requests without throttling",
				c.name, c.ceiling)
		})
	}
}

// --- The relay never alters what it stores ---------------------------------

func TestRelayedBytesAreReturnedExactly(t *testing.T) {
	// A hostile relay rewriting an envelope is the client's problem and the
	// client's tests cover it (CipherCryptoTests testRewrittenEnvelopeSender...).
	// What is testable here is that OUR relay has no path that alters bytes in
	// transit — across the size range, including the boundaries.
	h, db, _ := fullStack(t)
	_, senderToken := enrol(t, h, db, "198.51.100.166")
	recipient, recipientToken := enrol(t, h, db, "198.51.100.167")

	sizes := []int{store.MinEnvelopeBytes, 33, 1024, 65535, store.MaxEnvelopeBytes}
	sent := map[string][]byte{}
	for i, size := range sizes {
		e := envelope(size, byte(i*37+11))
		if rec := do(h, http.MethodPost, "/v1/messages", senderToken, "198.51.100.166",
			sendBody(recipient, e)); rec.Code != http.StatusAccepted {
			t.Fatalf("send %d bytes: %d", size, rec.Code)
		}
		sent[base64.StdEncoding.EncodeToString(e)] = e
	}

	msgs, _ := fetchMessages(t, h, recipientToken, "198.51.100.167")
	if len(msgs) != len(sizes) {
		t.Fatalf("relayed %d of %d", len(msgs), len(sizes))
	}
	for _, m := range msgs {
		if _, ok := sent[m.Envelope]; !ok {
			got, _ := base64.StdEncoding.DecodeString(m.Envelope)
			t.Errorf("an envelope came back altered (%d bytes)", len(got))
		}
	}
}

func TestJSONResponsesNeverEchoRequestContent(t *testing.T) {
	// A response that reflects input is how an error message becomes an
	// injection vector for whatever renders it. httpx.WriteError derives its
	// body from the status alone; this checks that holds at the edges.
	h, db, _ := fullStack(t)
	_, token := enrol(t, h, db, "198.51.100.168")

	marker := "CANARY-9f3a2b71"
	probes := []*http.Request{
		request(http.MethodPost, "/v1/messages", token, "198.51.100.168",
			strings.NewReader(`{"recipient":"`+marker+`","envelope":"AAAA"}`)),
		request(http.MethodPost, "/v1/messages/ack", token, "198.51.100.168",
			strings.NewReader(`{"ids":["`+marker+`"]}`)),
		request(http.MethodGet, "/v1/keys/"+marker, token, "198.51.100.168", nil),
		request(http.MethodGet, "/v1/blobs/"+marker, token, "198.51.100.168", nil),
		request(http.MethodPut, "/v1/keys", token, "198.51.100.168",
			strings.NewReader(`{"signed_prekey":{"key_id":1,"public_key":"`+marker+`"}}`)),
	}
	for _, r := range probes {
		rec := serve(h, r)
		if strings.Contains(rec.Body.String(), marker) {
			t.Errorf("%s %s echoed request content: %s", r.Method, r.URL.Path, rec.Body.String())
		}
	}
}

func TestErrorBodiesAreDerivedFromTheStatusAlone(t *testing.T) {
	h, db, _ := fullStack(t)
	_, token := enrol(t, h, db, "198.51.100.169")

	// Two different 404s from two different subsystems must be byte-identical.
	a := do(h, http.MethodGet, "/v1/keys/"+uuid.NewString(), token, "198.51.100.169", nil)
	b := do(h, http.MethodGet, "/v1/blobs/"+uuid.NewString(), token, "198.51.100.169", nil)
	if a.Code != b.Code || strings.TrimSpace(a.Body.String()) != strings.TrimSpace(b.Body.String()) {
		t.Errorf("two 404s differ:\n  keys:  %d %q\n  blobs: %d %q",
			a.Code, a.Body.String(), b.Code, b.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(a.Body.Bytes(), &body); err != nil {
		t.Fatalf("error body is not JSON: %v", err)
	}
	if len(body) != 1 || body["error"] == nil {
		t.Errorf("error body has unexpected shape: %v", body)
	}
}
