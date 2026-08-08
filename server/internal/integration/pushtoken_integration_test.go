//go:build integration

// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
//
// P7.S03 — push-token hardening (docs/THREAT_MODEL.md §3.3, BACKEND.md §2.9).
//
// These need a real database, because the three properties the step is about are
// all properties of PostgreSQL rather than of Go: what is actually in the column,
// that ON DELETE CASCADE takes the row with the account, and that the sweep
// compares against the database's own CURRENT_DATE. The cipher itself is covered
// without a database in internal/pushtoken.

package integration

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"cipher.relay/internal/store"
)

// A realistic APNs device token: 32 bytes as 64 hex characters.
const deviceToken = "740f4707bebcf74f9b7c25d48e3358945f6aa01da5ddb387462c7eaf61bb78ad"

// keyedDB opens a second handle to the same database, with a push-token key.
//
// A second handle rather than a parameter on testDB: every other suite opens a
// relay that has no key, which is the current deployment, and none of them should
// have to say so.
func keyedDB(t *testing.T) *store.DB {
	t.Helper()
	url := envOrSkip(t)

	db, err := store.Open(context.Background(), url,
		store.WithPushTokenKey([]byte(strings.Repeat("p", 32))))
	if err != nil {
		t.Fatalf("open keyed database: %v", err)
	}
	t.Cleanup(db.Close)

	if !db.HasPushTokenKey() {
		t.Fatal("the keyed handle has no cipher; every assertion below would be void")
	}
	return db
}

func envOrSkip(t *testing.T) string {
	t.Helper()
	url := os.Getenv("RELAY_DATABASE_URL")
	if url == "" {
		t.Fatal("RELAY_DATABASE_URL is not set; run via Scripts/verify-relay-integration.sh")
	}
	return url
}

// TestAPushTokenIsStoredEncrypted is the step's `Done when`, against the column.
//
// Read back through `PushTokenCiphertext`, which does not decrypt: asserting
// through `PushToken` would prove only that the round trip works, which a
// plaintext column would also pass.
func TestAPushTokenIsStoredEncrypted(t *testing.T) {
	ctx := context.Background()
	h, db, _ := authStack(t)
	aci, _ := enrol(t, h, db, "198.51.100.71")

	keyed := keyedDB(t)
	if err := keyed.UpsertPushToken(ctx, aci, deviceToken); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	ciphertext, nonce, err := keyed.PushTokenCiphertext(ctx, aci)
	if err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}

	if bytes.Contains(ciphertext, []byte(deviceToken)) {
		t.Fatal("the device token is in token_ciphertext verbatim")
	}
	// Positive control: the search finds the token when it is present, so the
	// assertion above cannot pass because the check is broken (AUDIT R2).
	if !bytes.Contains(append(ciphertext, deviceToken...), []byte(deviceToken)) {
		t.Fatal("the containment check cannot find a token that is there; the check above is void")
	}

	if len(nonce) != 12 {
		t.Fatalf("nonce is %d bytes; migration 0002 constrains the column to 12", len(nonce))
	}

	got, err := keyed.PushToken(ctx, aci)
	if err != nil {
		t.Fatalf("read token: %v", err)
	}
	if got != deviceToken {
		t.Fatalf("round trip returned %q", got)
	}
}

// A relay with no key must refuse rather than fall back to plaintext. This is
// the current deployment: push does not exist until P8, so no key is configured.
func TestARelayWithNoKeyRefusesToStoreAToken(t *testing.T) {
	ctx := context.Background()
	h, db, _ := authStack(t)
	aci, _ := enrol(t, h, db, "198.51.100.72")

	if db.HasPushTokenKey() {
		t.Fatal("the unkeyed handle has a cipher; this test proves nothing")
	}

	if err := db.UpsertPushToken(ctx, aci, deviceToken); !errors.Is(err, store.ErrNoPushTokenKey) {
		t.Fatalf("an unkeyed relay stored a token, or failed wrongly: %v", err)
	}

	// And nothing was written: a refusal that left a row would be the worst of
	// both outcomes.
	if _, _, err := keyedDB(t).PushTokenCiphertext(ctx, aci); !errors.Is(err, store.ErrNoPushToken) {
		t.Fatalf("a row exists after the refusal: %v", err)
	}
}

// Re-registration is the relay's half of rotation: the row is rewritten under a
// fresh nonce, so one ciphertext does not sit under one nonce for the life of an
// account.
func TestReRegisteringRewritesTheRowUnderAFreshNonce(t *testing.T) {
	ctx := context.Background()
	h, db, _ := authStack(t)
	aci, _ := enrol(t, h, db, "198.51.100.73")
	keyed := keyedDB(t)

	if err := keyed.UpsertPushToken(ctx, aci, deviceToken); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	firstCiphertext, firstNonce, err := keyed.PushTokenCiphertext(ctx, aci)
	if err != nil {
		t.Fatalf("read first: %v", err)
	}

	if err := keyed.UpsertPushToken(ctx, aci, deviceToken); err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	secondCiphertext, secondNonce, err := keyed.PushTokenCiphertext(ctx, aci)
	if err != nil {
		t.Fatalf("read second: %v", err)
	}

	if bytes.Equal(firstNonce, secondNonce) {
		t.Fatal("the nonce was reused across a re-registration")
	}
	if bytes.Equal(firstCiphertext, secondCiphertext) {
		t.Fatal("the same token re-registered produced identical ciphertext")
	}

	// Still the same token, so the rewrite did not lose the registration.
	if got, err := keyed.PushToken(ctx, aci); err != nil || got != deviceToken {
		t.Fatalf("after re-registration the token reads back as %q, %v", got, err)
	}
}

// §3.3's "delete it with the account", which is the schema's cascade rather than
// any Go — and therefore exactly the kind of claim that is only true if someone
// checks.
func TestDeletingTheAccountTakesItsPushToken(t *testing.T) {
	ctx := context.Background()
	h, db, _ := authStack(t)
	aci, _ := enrol(t, h, db, "198.51.100.74")
	keyed := keyedDB(t)

	if err := keyed.UpsertPushToken(ctx, aci, deviceToken); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := db.BackdateLastSeen(ctx, aci, store.AccountRetentionDays+1); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	if _, err := db.DeleteAbandonedAccounts(ctx); err != nil {
		t.Fatalf("sweep accounts: %v", err)
	}

	if _, _, err := keyed.PushTokenCiphertext(ctx, aci); !errors.Is(err, store.ErrNoPushToken) {
		t.Fatalf("the push token outlived its account: %v", err)
	}
}

// The rotation sweep. Backdated one day past the threshold rather than exactly
// to it, so a test sitting on the boundary cannot pass for either comparison
// operator; the retained row below pins the boundary from the other side.
func TestStalePushTokensAreSweptAndFreshOnesAreNot(t *testing.T) {
	ctx := context.Background()
	h, db, _ := authStack(t)
	stale, _ := enrol(t, h, db, "198.51.100.75")
	fresh, _ := enrol(t, h, db, "198.51.100.76")
	keyed := keyedDB(t)

	for _, aci := range []uuid.UUID{stale, fresh} {
		if err := keyed.UpsertPushToken(ctx, aci, deviceToken); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}

	days := int(store.PushTokenMaxAge.Hours() / 24)
	if err := keyed.BackdatePushToken(ctx, stale, days+1); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	if _, err := keyed.DeleteStalePushTokens(ctx); err != nil {
		t.Fatalf("sweep push tokens: %v", err)
	}

	if _, _, err := keyed.PushTokenCiphertext(ctx, stale); !errors.Is(err, store.ErrNoPushToken) {
		t.Fatalf("a token past the rotation threshold survived: %v", err)
	}
	if _, _, err := keyed.PushTokenCiphertext(ctx, fresh); err != nil {
		t.Fatalf("a token inside the threshold was swept: %v", err)
	}
}

// Turning notifications off removes the row rather than blanking it, for the
// same reason a delivered message is deleted rather than flagged.
func TestDeletingAPushTokenRemovesTheRow(t *testing.T) {
	ctx := context.Background()
	h, db, _ := authStack(t)
	aci, _ := enrol(t, h, db, "198.51.100.77")
	keyed := keyedDB(t)

	if err := keyed.UpsertPushToken(ctx, aci, deviceToken); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	deleted, err := keyed.DeletePushToken(ctx, aci)
	if err != nil || !deleted {
		t.Fatalf("delete reported %v, %v", deleted, err)
	}
	if _, _, err := keyed.PushTokenCiphertext(ctx, aci); !errors.Is(err, store.ErrNoPushToken) {
		t.Fatalf("the row survived its deletion: %v", err)
	}
}

// A token for an account that does not exist is silently not stored, the same
// shape as EnqueueMessage: the alternative is a foreign-key error that has to be
// distinguished by SQLSTATE, and an endpoint that reports it is an enumeration
// oracle.
func TestAPushTokenForAnUnknownAccountIsNotStored(t *testing.T) {
	ctx := context.Background()
	keyed := keyedDB(t)
	stranger := uuid.New()

	if err := keyed.UpsertPushToken(ctx, stranger, deviceToken); err != nil {
		t.Fatalf("upsert for an unknown account should be silent: %v", err)
	}
	if _, _, err := keyed.PushTokenCiphertext(ctx, stranger); !errors.Is(err, store.ErrNoPushToken) {
		t.Fatalf("a row was written for an account that does not exist: %v", err)
	}
}
