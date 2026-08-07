//go:build integration

// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
//
// P4.S11 — "log review finds no token, invite code, push token, or IP".
//
// Done by *running* the relay rather than by reading it. The logging package
// already redacts by type and by key denylist and has unit tests for both, but
// those test the mechanism; this tests the outcome. It drives a complete flow —
// invite, redeem, publish keys, fetch a bundle, send, fetch, acknowledge, upload,
// download, rotate, revoke, plus a panic and a batch of malformed requests —
// captures everything the process emits at DEBUG, and searches it for the actual
// secret values that flow was known to contain.
//
// The distinction matters because the mechanism can be correct and still be
// bypassed: one `slog.String("detail", token)` under a key nobody thought to
// deny, or one error wrapped with a value in its text, and the unit tests stay
// green while the credential is on disk.

package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"cipher.relay/internal/api"
	"cipher.relay/internal/blob"
	"cipher.relay/internal/httpx"
	"cipher.relay/internal/logging"
	"cipher.relay/internal/store"
)

// syncBuffer collects log output from concurrent handlers.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestAFullFlowLeaksNothingIntoTheLog drives the whole API and audits the output.
func TestAFullFlowLeaksNothingIntoTheLog(t *testing.T) {
	ctx := context.Background()

	logs := &syncBuffer{}
	// DEBUG deliberately: the level a developer raises it to during an incident,
	// which is exactly when a leak matters most and when nobody is reviewing
	// what the extra lines contain.
	log := logging.New(logs, slog.LevelDebug)

	db := testDB(t)
	limiter := testLimiter(t)
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

	// A route that panics, so the recovery path — which handles a value chosen
	// by whatever failed — is exercised too.
	const panicSecret = "PANIC-VALUE-8c1d55e2"
	mux.HandleFunc("GET /v1/panic", func(http.ResponseWriter, *http.Request) {
		panic("boom: " + panicSecret)
	})

	// The same middleware stack main uses.
	h := httpx.Chain(mux,
		httpx.Log(log, httpx.MuxRoute(mux)),
		httpx.Recover(log, httpx.MuxRoute(mux)),
		httpx.SecurityHeaders,
		httpx.LimitBody(128*1024, api.BlobPathPrefix),
	)

	// --- drive a complete flow, remembering every secret it produces ---------

	const clientIP = "203.0.113.211"

	code, err := api.IssueInvite(ctx, db, time.Hour)
	if err != nil {
		t.Fatalf("issue invite: %v", err)
	}

	key := base64.StdEncoding.EncodeToString(make([]byte, 33))
	rec := post(h, clientIP, redeemBody(code.String(), key, 4242))
	if rec.Code != http.StatusCreated {
		t.Fatalf("redeem: %d: %s", rec.Code, rec.Body.String())
	}
	var enrolled struct {
		ACI   string `json:"aci"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &enrolled); err != nil {
		t.Fatalf("decode: %v", err)
	}

	peer, peerToken := enrol(t, h, db, "203.0.113.212")

	do(h, http.MethodPut, "/v1/keys", peerToken, "203.0.113.212", uploadBody(4, true))
	do(h, http.MethodGet, "/v1/keys/"+peer.String(), enrolled.Token, clientIP, nil)

	envBytes := envelope(512, 0x9E)
	do(h, http.MethodPost, "/v1/messages", enrolled.Token, clientIP, sendBody(peer, envBytes))
	msgs, _ := fetchMessages(t, h, peerToken, "203.0.113.212")
	if len(msgs) > 0 {
		do(h, http.MethodPost, "/v1/messages/ack", peerToken, "203.0.113.212", ackBody(msgs[0].ID))
	}

	blobBytes := randomBytes(4096)
	blobID, _ := upload(t, h, enrolled.Token, clientIP, blobBytes)
	do(h, http.MethodGet, "/v1/blobs/"+blobID.String(), enrolled.Token, clientIP, nil)
	do(h, http.MethodDelete, "/v1/blobs/"+blobID.String(), enrolled.Token, clientIP, nil)

	// A new invite issued by an authenticated account.
	issued := do(h, http.MethodPost, "/v1/invite", enrolled.Token, clientIP, nil)
	var issuedInvite struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(issued.Body.Bytes(), &issuedInvite)

	// Rotation and revocation.
	rot := do(h, http.MethodPost, "/v1/auth/rotate", enrolled.Token, clientIP, nil)
	var rotated struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rot.Body.Bytes(), &rotated)
	do(h, http.MethodDelete, "/v1/auth", rotated.Token, clientIP, nil)

	// Failure paths, which are where detail tends to escape.
	do(h, http.MethodGet, "/v1/messages", "Bearer-nonsense", clientIP, nil)
	post(h, clientIP, redeemBody("WRONG-CODE-AAAAA-AAAAA-AAAAAA", key, 1))
	do(h, http.MethodPost, "/v1/messages", enrolled.Token, clientIP,
		strings.NewReader(`{"recipient":"nope","envelope":"!!!"}`))
	do(h, http.MethodGet, "/v1/panic", enrolled.Token, clientIP, nil)

	output := logs.String()
	if len(output) == 0 {
		t.Fatal("the flow produced no log output at all — this check is not checking anything")
	}

	// --- the audit -----------------------------------------------------------

	secrets := map[string]string{
		"session token":         enrolled.Token,
		"rotated session token": rotated.Token,
		"peer session token":    peerToken,
		"bootstrap invite code": code.String(),
		"issued invite code":    issuedInvite.Code,
		"client IP":             clientIP,
		"peer IP":               "203.0.113.212",
		"panic value":           panicSecret,
		"envelope (base64)":     base64.StdEncoding.EncodeToString(envBytes),
		"blob bytes (base64)":   base64.StdEncoding.EncodeToString(blobBytes),
		"account identifier":    enrolled.ACI,
		"peer identifier":       peer.String(),
		"blob identifier":       blobID.String(),
	}
	for name, secret := range secrets {
		if secret == "" {
			t.Errorf("the %s was empty, so searching for it proves nothing", name)
			continue
		}
		if strings.Contains(output, secret) {
			t.Errorf("the %s appears in the log", name)
		}
	}

	// The canonical form of an invite code is grouped for display; its ungrouped
	// form is what gets hashed. Search for both, or a change to String() would
	// silently narrow this check.
	if ungrouped := strings.ReplaceAll(code.String(), "-", ""); strings.Contains(output, ungrouped) {
		t.Error("the ungrouped invite code appears in the log")
	}

	// Envelope bytes might be logged raw rather than base64.
	if bytes.Contains([]byte(output), envBytes[31:]) {
		t.Error("raw envelope bytes appear in the log")
	}

	// Every line must still be valid JSON: a handler that wrote to the same
	// stream by another route would show up as an unparseable line.
	for i, line := range strings.Split(strings.TrimSpace(output), "\n") {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("log line %d is not JSON, so something bypassed the handler: %q", i, line)
		}
	}
}

func TestTheAccessLogRecordsNoAddressAndNoPopulatedPath(t *testing.T) {
	// docs/BACKEND.md §7: method, route *pattern*, status, duration. No client
	// address at all — §3.6 allows 24h retention for triage, and that belongs in
	// the reverse proxy's log with its own lifetime, not correlated with
	// application events here. A populated path is a metadata record hiding in a
	// log line, and it survives every deletion the retention policy performs.
	logs := &syncBuffer{}
	log := logging.New(logs, slog.LevelDebug)

	db := testDB(t)
	limiter := testLimiter(t)
	authHandler := api.NewAuthHandler(db, limiter, log)
	mux := http.NewServeMux()
	authHandler.Routes(mux)
	api.NewInviteHandler(db, limiter, authHandler, log).Routes(mux)
	api.NewKeysHandler(db, authHandler, log).Routes(mux)
	h := httpx.Chain(mux, httpx.Log(log, httpx.MuxRoute(mux)), httpx.Recover(log, httpx.MuxRoute(mux)))

	target, token := enrol(t, h, db, "203.0.113.213")
	do(h, http.MethodGet, "/v1/keys/"+target.String(), token, "203.0.113.213", nil)

	output := logs.String()
	if !strings.Contains(output, "/v1/keys/{aci}") {
		t.Fatalf("the route pattern is missing, so the access log is not useful: %s", output)
	}
	if strings.Contains(output, target.String()) {
		t.Error("the populated path reached the access log")
	}
	if strings.Contains(output, "203.0.113.213") {
		t.Error("a client address reached the application log")
	}
}

func TestRateLimitBucketKeysNeverReachTheLog(t *testing.T) {
	// Bucket keys are HMACs of an address or an account id. They are not secret,
	// but logging them would let anyone with log access confirm a guess by
	// recomputing — which is the property Subject exists to deny.
	logs := &syncBuffer{}
	log := logging.New(logs, slog.LevelDebug)

	db := testDB(t)
	limiter := testLimiter(t)
	subject := limiter.Subject("invite-redeem", "203.0.113.214")

	authHandler := api.NewAuthHandler(db, limiter, log)
	mux := http.NewServeMux()
	api.NewInviteHandler(db, limiter, authHandler, log).Routes(mux)
	h := httpx.Chain(mux, httpx.Log(log, httpx.MuxRoute(mux)))

	key := base64.StdEncoding.EncodeToString(make([]byte, 33))
	for range 8 {
		post(h, "203.0.113.214", redeemBody("AAAAA-AAAAA-AAAAA-AAAAA-AAAAAA", key, 1))
	}

	if strings.Contains(logs.String(), subject) {
		t.Error("a rate-limit bucket key appears in the log")
	}
}

func TestDatabaseErrorsDoNotCarryTheConnectionString(t *testing.T) {
	// store.Open deliberately does not wrap ping failures with the URL, because
	// the URL contains the password. This drives that path with a bad password
	// and checks the error text.
	ctx := context.Background()

	url := "postgres://relay:wrong-password-9f2a@postgres:5432/cipher_relay?sslmode=disable"
	_, err := store.Open(ctx, url)
	if err == nil {
		t.Skip("the database accepted a wrong password; nothing to check")
	}
	if strings.Contains(err.Error(), "wrong-password-9f2a") {
		t.Errorf("the connection error carries the password: %v", err)
	}
}

func TestSecretTypeSurvivesEveryFormattingPath(t *testing.T) {
	// logging.Secret redacts under slog and under %v. This confirms the same
	// holds when it is carried inside an error, which is the path a value takes
	// when something has already gone wrong and detail is most tempting.
	logs := &syncBuffer{}
	log := logging.New(logs, slog.LevelDebug)

	const secret = "SECRET-VALUE-4d7f0091"
	wrapped := logging.NewSecret(secret)

	log.Info("carrying a secret", slog.Any("detail", wrapped))
	log.Error("in a message", slog.String("reason", "failed: "+wrapped.String()))

	if strings.Contains(logs.String(), secret) {
		t.Errorf("a wrapped secret reached the log: %s", logs.String())
	}
	if !strings.Contains(logs.String(), logging.Placeholder) {
		t.Errorf("the placeholder is missing, so redaction may not have run: %s", logs.String())
	}
}

func TestNoLogLineIsEmittedPerDeliveredMessage(t *testing.T) {
	// Log volume is itself metadata. A line per delivery is a delivery record
	// with a timestamp, and it survives the deletion of the message it describes
	// — which would quietly undo docs/THREAT_MODEL.md §3.1 in a different file.
	logs := &syncBuffer{}
	log := logging.New(logs, slog.LevelDebug)

	db := testDB(t)
	limiter := testLimiter(t)
	authHandler := api.NewAuthHandler(db, limiter, log)
	mux := http.NewServeMux()
	authHandler.Routes(mux)
	api.NewInviteHandler(db, limiter, authHandler, log).Routes(mux)
	api.NewMessagesHandler(db, authHandler, log).Routes(mux)
	// No httpx.Log: the access log legitimately emits one line per request. What
	// is under test is whether the *handlers* add their own per-message line.
	h := mux

	_, sender := enrol(t, h, db, "203.0.113.215")
	recipient, _ := enrol(t, h, db, "203.0.113.216")

	before := strings.Count(logs.String(), "\n")
	for range 5 {
		do(h, http.MethodPost, "/v1/messages", sender, "203.0.113.215",
			sendBody(recipient, envelope(96, 0xAF)))
	}
	after := strings.Count(logs.String(), "\n")

	if after-before >= 5 {
		t.Errorf("five sends produced %d log lines; the relay is keeping a delivery "+
			"record in its log: %s", after-before, logs.String())
	}
}
