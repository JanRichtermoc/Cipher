//go:build integration

// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
//
// AUDIT 5.32: the relay refused every real prekey publication, and nothing here
// could have noticed.
//
// Two independent gaps let it through, and both are closed in this file.
//
// **The stack under test was not the stack that runs.** keysStack builds a bare
// ServeMux, so httpx.LimitBody — the middleware that actually rejected the
// request — was never in the path. Every publish test proved the handler agreed
// with itself.
//
// **The fixtures were not the client.** uploadBody fills a pool of four keys with
// 1568-byte placeholders. The shipped client publishes a hundred, and an ML-KEM
// public key serializes to 1569 bytes, so the body a real device sends is around
// 229 KB against a global limit of 128 KiB. A fixture that models the client
// smaller than the client is a test that agrees with the test.
//
// So these run the production middleware chain, with the production exemption
// list, against bodies sized the way the client and the validator define them
// rather than the way a fixture author guessed.

package integration

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"cipher.relay/internal/api"
	"cipher.relay/internal/config"
	"cipher.relay/internal/httpx"
	"cipher.relay/internal/logging"
	"cipher.relay/internal/store"
)

// Sizes a real client actually sends.
//
// Not assumed — pinned on the client side by
// `MessageRepositoryTests.testSerializedKeyAndSignatureSizesAreWhatTheRelayBoundsAssume`,
// which measures them out of a real publication and fails if a dependency bump
// changes one. An ML-KEM-1024 public key is a type byte and 1568 key bytes; a
// Curve25519 public key is 0x05 and 32; signatures are 64.
const (
	realKyberKeyBytes  = 1569
	realCurveKeyBytes  = 33
	realSignatureBytes = 64

	// CryptoEngine.defaultOneTimePreKeyCount — the pool the shipped app mints on
	// registration, which is the publication that was being refused.
	shippedOneTimePoolSize = 100
)

// productionKeysStack is keysStack plus the middleware main actually wraps it in.
//
// The two couplings that make this worth having: the body limit comes from
// config.Load, so it is the value a deployment gets rather than a literal that
// can drift below it, and the exemptions come from api.BodyLimitExemptPrefixes,
// so removing one in production removes it here. A test that spelled either out
// itself would keep passing after production stopped doing it — AUDIT **R2**.
func productionKeysStack(t *testing.T) (http.Handler, *store.DB) {
	t.Helper()

	db := testDB(t)
	limiter := testLimiter(t)
	log := logging.New(io.Discard, slog.LevelError)

	authHandler := api.NewAuthHandler(db, limiter, log)
	mux := http.NewServeMux()
	authHandler.Routes(mux)
	api.NewInviteHandler(db, limiter, authHandler, log).Routes(mux)
	api.NewKeysHandler(db, authHandler, log).Routes(mux)

	// The real defaults. Load requires these three and nothing here depends on
	// their values, so they are placeholders — MaxRequestBytes is the field under
	// test and it comes from the same code path a deployment runs.
	t.Setenv("RELAY_DATABASE_URL", "postgres://unused")
	t.Setenv("RELAY_REDIS_ADDR", "127.0.0.1:6379")
	t.Setenv("RELAY_REDIS_PASSWORD", "unused-in-this-test")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	return httpx.Chain(mux,
		httpx.Log(log, httpx.MuxRoute(mux)),
		httpx.Recover(log, httpx.MuxRoute(mux)),
		httpx.SecurityHeaders,
		httpx.LimitBody(cfg.MaxRequestBytes, api.BodyLimitExemptPrefixes()...),
	), db
}

// sizedUploadBody builds a well-formed publication with keys of a stated size.
//
// uploadBody exists for the validator's behaviour and deliberately keeps the
// bodies small; this one exists for the body's *size*, which is the property
// that was wrong. Every field is well-formed, so a refusal can only be about
// length.
func sizedUploadBody(curveCount, kyberCount, curveKeyLen, kyberKeyLen, sigLen int) io.Reader {
	body := map[string]any{
		"signed_prekey": map[string]any{
			"key_id": 1, "public_key": b64(curveKeyLen, 0x05), "signature": b64(sigLen, 0xAA),
		},
		"kyber_last_resort": map[string]any{
			"key_id": 2, "public_key": b64(kyberKeyLen, 0x08), "signature": b64(sigLen, 0xBB),
		},
	}

	onetime := make([]map[string]any, 0, curveCount)
	for i := range curveCount {
		onetime = append(onetime, map[string]any{
			"key_id": 1000 + i, "public_key": b64(curveKeyLen, byte(i%251)),
		})
	}
	body["one_time_prekeys"] = onetime

	kyber := make([]map[string]any, 0, kyberCount)
	for i := range kyberCount {
		kyber = append(kyber, map[string]any{
			"key_id": 5000 + i, "public_key": b64(kyberKeyLen, byte(i%251)),
			"signature": b64(sigLen, 0xCC),
		})
	}
	body["kyber_prekeys"] = kyber

	raw, _ := json.Marshal(body)
	return strings.NewReader(string(raw))
}

// --- The regression: the publication the shipped client sends ---------------

func TestTheShippedClientsPublicationIsAccepted(t *testing.T) {
	// AUDIT 5.32 in one assertion. This body is the shape a real device produces
	// at CryptoEngine.defaultOneTimePreKeyCount, run through the middleware chain
	// main builds. Before the fix it was a 400 — and, because auth.allow runs
	// before the body is read, six of them exhausted the account's publication
	// budget for the day and the seventh became a 429.
	h, db := productionKeysStack(t)
	_, token := enrol(t, h, db, "198.51.100.70")

	rec := do(h, http.MethodPut, "/v1/keys", token, "198.51.100.70",
		sizedUploadBody(shippedOneTimePoolSize, shippedOneTimePoolSize,
			realCurveKeyBytes, realKyberKeyBytes, realSignatureBytes))

	if rec.Code != http.StatusOK {
		t.Fatalf("the shipped client's own publication was refused: status %d: %s",
			rec.Code, rec.Body.String())
	}

	// And it was stored, not merely accepted: a 200 over an upload the transport
	// truncated would be the same failure wearing a better status code.
	var got struct {
		OneTimePreKeys int `json:"one_time_prekeys"`
		KyberPreKeys   int `json:"kyber_prekeys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.OneTimePreKeys != shippedOneTimePoolSize {
		t.Errorf("stored %d one-time prekeys, published %d",
			got.OneTimePreKeys, shippedOneTimePoolSize)
	}
	// The pool plus the last-resort key.
	if got.KyberPreKeys != shippedOneTimePoolSize {
		t.Errorf("stored %d one-time kyber prekeys, published %d",
			got.KyberPreKeys, shippedOneTimePoolSize)
	}
}

// --- The invariant: the reader never refuses what the validator accepts ------

func TestABodyAtTheValidatorsMaximumIsReadable(t *testing.T) {
	// The general form of the defect, and the reason MaxPublishBytes is computed
	// from the validator's own bounds instead of chosen. Every dimension is at
	// its documented ceiling at once: MaxPreKeysPerUpload keys in both pools, each
	// key and signature at its longest accepted length.
	//
	// If this ever fails, two numbers in one file have disagreed again — a body
	// the relay declares legal is one it will not read.
	h, db := productionKeysStack(t)
	_, token := enrol(t, h, db, "198.51.100.71")

	// The largest values decodeKey accepts, mirroring api's maxCurveKeyBytes,
	// maxKyberKeyBytes and maxSignatureLen. Deliberately literals: deriving the
	// case from the code under test is how a self-test stops testing anything
	// (AUDIT **R5**).
	const maxCurve, maxKyber, maxSig = 64, 4096, 128

	rec := do(h, http.MethodPut, "/v1/keys", token, "198.51.100.71",
		sizedUploadBody(api.MaxPreKeysPerUpload, api.MaxPreKeysPerUpload,
			maxCurve, maxKyber, maxSig))

	if rec.Code != http.StatusOK {
		t.Fatalf("a body the validator accepts was refused before it reached the validator: "+
			"status %d: %s", rec.Code, rec.Body.String())
	}
}

// --- An exemption is not "no limit" -----------------------------------------

func TestAnOversizePublicationIsRefusedAsTooLarge(t *testing.T) {
	// The route owns its limit; it does not lack one. And the status is the point:
	// 413 says "smaller pool", 400 says "your JSON is broken". Collapsing them is
	// what left the app retrying a body that could never be accepted, six times a
	// day, with nothing in the log to say which failure it was.
	h, db := productionKeysStack(t)
	_, token := enrol(t, h, db, "198.51.100.72")

	// Comfortably past MaxPublishBytes while every individual field stays
	// well-formed, so length is the only thing wrong with it.
	rec := do(h, http.MethodPut, "/v1/keys", token, "198.51.100.72",
		sizedUploadBody(api.MaxPreKeysPerUpload, 4*api.MaxPreKeysPerUpload, 64, 4096, 128))

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("an oversize publication answered %d, want 413", rec.Code)
	}
}

func TestTheBodyLimitExemptionsCoverOnlyTheirOwnRoutes(t *testing.T) {
	// The exemption list is matched by prefix, so a broadened entry would silently
	// lift the global limit off routes that must keep it. Checked against the
	// paths that must stay covered rather than by eyeballing the list.
	mustStayLimited := []string{
		"/v1/messages", "/v1/messages/ack", "/v1/invite/redeem", "/v1/auth/token", "/health/ready",
	}
	for _, prefix := range api.BodyLimitExemptPrefixes() {
		if prefix == "" || prefix == "/" {
			t.Fatalf("exemption %q lifts the global body limit from every route", prefix)
		}
		for _, path := range mustStayLimited {
			if strings.HasPrefix(path, prefix) {
				t.Errorf("exemption %q also exempts %s, which owns no limit of its own",
					prefix, path)
			}
		}
	}
}
