//go:build integration

// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
//
// AUDIT 5.28: docs/BACKEND.md §4 promised an abandonment sweep at 180 days and
// nothing implemented it. `accounts.last_seen` was written on every authenticated
// request and read by no code at all.
//
// These need a real database rather than a fake store for two reasons the unit
// tests in internal/sweep cannot cover: the threshold is compared against
// PostgreSQL's own CURRENT_DATE, and "everything cascading from it" is a property
// of six ON DELETE CASCADE clauses in the schema, not of any Go.

package integration

import (
	"context"
	"net/http"
	"testing"
	"time"

	"cipher.relay/internal/store"
)

// TestAbandonedAccountsAreDeleted is the sweep's reason for existing.
//
// Backdated one day past the threshold rather than exactly to it, because a test
// sitting on the boundary passes for either comparison operator and would not
// notice `<` becoming `<=`. The retained account below is the one that pins the
// boundary in the other direction.
func TestAbandonedAccountsAreDeleted(t *testing.T) {
	ctx := context.Background()
	h, db, _ := authStack(t)

	aci, _ := enrol(t, h, db, "198.51.100.28")

	if err := db.BackdateLastSeen(ctx, aci, store.AccountRetentionDays+1); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	deleted, err := db.DeleteAbandonedAccounts(ctx)
	if err != nil {
		t.Fatalf("sweep accounts: %v", err)
	}
	if deleted < 1 {
		t.Fatalf("the sweep removed %d accounts; the abandoned one survived", deleted)
	}

	exists, err := db.AccountExists(ctx, aci)
	if err != nil {
		t.Fatalf("account exists: %v", err)
	}
	if exists {
		t.Fatal("an account unseen for longer than the retention threshold is still on disk")
	}
}

// TestAnActiveAccountSurvivesTheAbandonmentSweep is the positive control.
//
// Without it, a sweep with a broken predicate — or one that deleted the table —
// would satisfy every assertion above. It also pins the boundary: one day inside
// the threshold must be kept, so widening the comparison by a day fails here.
func TestAnActiveAccountSurvivesTheAbandonmentSweep(t *testing.T) {
	ctx := context.Background()
	h, db, _ := authStack(t)

	aci, _ := enrol(t, h, db, "198.51.100.29")

	if err := db.BackdateLastSeen(ctx, aci, store.AccountRetentionDays-1); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	if _, err := db.DeleteAbandonedAccounts(ctx); err != nil {
		t.Fatalf("sweep accounts: %v", err)
	}

	exists, err := db.AccountExists(ctx, aci)
	if err != nil {
		t.Fatalf("account exists: %v", err)
	}
	if !exists {
		t.Fatalf("an account seen %d days ago was swept; the threshold is %d",
			store.AccountRetentionDays-1, store.AccountRetentionDays)
	}
}

// TestSweepingAnAccountTakesItsMessagesAndTokens covers "and everything
// cascading from it".
//
// The account row on its own is an identity key and a registration id. What
// makes the sweep a retention control rather than tidying is that the undelivered
// envelopes and the live session token go with it — the two things a seizure
// under THREAT_MODEL.md §1.1 is actually after.
func TestSweepingAnAccountTakesItsMessagesAndTokens(t *testing.T) {
	ctx := context.Background()
	h, db, _ := authStack(t)

	aci, _ := enrol(t, h, db, "198.51.100.30")

	// A minimum-size envelope: this test is about the cascade, not about bounds.
	envelope := make([]byte, store.MinEnvelopeBytes)
	accepted, err := db.EnqueueMessage(ctx, aci, envelope, time.Hour)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if !accepted {
		t.Fatal("the relay refused a message for an account that exists")
	}

	// The premises, asserted rather than assumed: a cascade test that starts from
	// an empty queue proves nothing about the cascade.
	pending, err := db.CountPendingMessages(ctx, aci)
	if err != nil {
		t.Fatalf("count pending: %v", err)
	}
	if pending != 1 {
		t.Fatalf("expected one queued message before the sweep, got %d", pending)
	}
	sessions, err := db.CountSessionsForAccount(ctx, aci)
	if err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if sessions != 1 {
		t.Fatalf("expected one live session before the sweep, got %d", sessions)
	}

	if err := db.BackdateLastSeen(ctx, aci, store.AccountRetentionDays+1); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	if _, err := db.DeleteAbandonedAccounts(ctx); err != nil {
		t.Fatalf("sweep accounts: %v", err)
	}

	if pending, err = db.CountPendingMessages(ctx, aci); err != nil {
		t.Fatalf("count pending: %v", err)
	} else if pending != 0 {
		t.Fatalf("%d undelivered envelope(s) outlived the account they were addressed to", pending)
	}
	if sessions, err = db.CountSessionsForAccount(ctx, aci); err != nil {
		t.Fatalf("count sessions: %v", err)
	} else if sessions != 0 {
		t.Fatalf("%d session token(s) outlived the account they authenticate", sessions)
	}
}

// TestAuthenticatingRefreshesTheActivityDate is the other half of the sweep.
//
// The threshold is only a retention control if something moves `last_seen`
// forward; if the refresh silently stopped working, every one of the tests above
// would still pass and every account in daily use would be deleted at 180 days.
// That is the failure AUDIT 5.28 names, and it is invisible from the API.
func TestAuthenticatingRefreshesTheActivityDate(t *testing.T) {
	ctx := context.Background()
	h, db, _ := authStack(t)

	aci, token := enrol(t, h, db, "198.51.100.31")

	// Far enough back that the refresh has something to do, and far enough
	// inside the threshold that this test never depends on the sweep.
	const staleDays = 30
	if err := db.BackdateLastSeen(ctx, aci, staleDays); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	if days, err := db.DaysSinceLastSeen(ctx, aci); err != nil {
		t.Fatalf("days since last seen: %v", err)
	} else if days != staleDays {
		t.Fatalf("the backdate did not take: %d days, want %d", days, staleDays)
	}

	// Any authenticated request. Rotation is used because it is authenticated
	// and has no side effect on the account row itself.
	rec := do(h, http.MethodPost, "/v1/auth/rotate", token, "198.51.100.31", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate: status %d: %s", rec.Code, rec.Body.String())
	}

	days, err := db.DaysSinceLastSeen(ctx, aci)
	if err != nil {
		t.Fatalf("days since last seen: %v", err)
	}
	if days != 0 {
		t.Fatalf("authenticating left last_seen %d days in the past; the account is "+
			"ageing towards the abandonment sweep while in use", days)
	}
}
