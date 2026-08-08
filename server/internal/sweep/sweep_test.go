// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
//
// AUDIT 5.28, the retention half: docs/BACKEND.md §4 promises an abandonment
// sweep at 180 days, and until this the `accounts.last_seen` column existed with
// nothing reading it. A policy no code implements is a document, not a control.
//
// These tests are against a fake store, so they prove the *sweeper* runs the
// task and survives its failure. That the SQL deletes the right rows, and that
// the cascade takes the account's messages and tokens with it, is a property of
// PostgreSQL and is asserted by the integration suite against a real database.

package sweep

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/google/uuid"
)

// fakeStore records which sweeps ran and can be told to fail any of them.
type fakeStore struct {
	called map[string]int
	fail   map[string]error
}

func newFakeStore() *fakeStore {
	return &fakeStore{called: map[string]int{}, fail: map[string]error{}}
}

func (f *fakeStore) run(name string) (int64, error) {
	f.called[name]++
	if err, ok := f.fail[name]; ok {
		return 0, err
	}
	return 1, nil
}

func (f *fakeStore) DeleteExpiredMessages(context.Context) (int64, error) {
	return f.run("messages")
}
func (f *fakeStore) DeleteExpiredInvites(context.Context) (int64, error) {
	return f.run("invites")
}
func (f *fakeStore) DeleteExpiredSessions(context.Context) (int64, error) {
	return f.run("sessions")
}
func (f *fakeStore) DeleteAbandonedAccounts(context.Context) (int64, error) {
	return f.run("accounts")
}
func (f *fakeStore) DeleteStalePushTokens(context.Context) (int64, error) {
	return f.run("push_tokens")
}
func (f *fakeStore) ExpiredAttachmentIDs(context.Context, int) ([]uuid.UUID, error) {
	return nil, nil
}
func (f *fakeStore) DeleteAttachment(context.Context, uuid.UUID) (bool, error) {
	return true, nil
}

func quietSweeper(store Store) *Sweeper {
	// Discarded output: these tests assert on behaviour, and a sweeper that
	// printed to the test log would only make a failure harder to read.
	return New(store, nil, slog.New(slog.NewJSONHandler(io.Discard, nil)), 0)
}

// TestOnePassSweepsEveryTable is the wiring test.
//
// The abandonment sweep is the one entry here with no `expires_at` behind it, so
// nothing else in the system would notice its absence: no read path filters
// accounts, no test would go red, and the only symptom would be rows that never
// go away. Removing "accounts" from the task table in once() fails this by name.
func TestOnePassSweepsEveryTable(t *testing.T) {
	store := newFakeStore()
	quietSweeper(store).once(context.Background())

	for _, table := range []string{
		"messages", "sessions", "invites", "push_tokens", "accounts",
	} {
		if store.called[table] != 1 {
			t.Errorf("the %s sweep ran %d times in one pass, want exactly 1",
				table, store.called[table])
		}
	}
}

// TestAFailingSweepDoesNotSkipTheOthers pins the documented independence.
//
// Each table is swept on its own so a database error on the first does not
// silently retain the rest. Asserted with the *first and most sensitive* task
// failing, because that is the ordering where a shared error path would swallow
// everything after it.
func TestAFailingSweepDoesNotSkipTheOthers(t *testing.T) {
	store := newFakeStore()
	store.fail["messages"] = errors.New("connection refused")

	quietSweeper(store).once(context.Background())

	for _, table := range []string{"sessions", "invites", "push_tokens", "accounts"} {
		if store.called[table] != 1 {
			t.Errorf("the %s sweep did not run after an earlier task failed", table)
		}
	}
}

// TestAFailingAccountSweepIsNotFatal covers the new task in the other direction.
//
// The sweeper holds no request path and its work is always still there next
// tick, so escalating a transient database error into a process exit would trade
// a delayed deletion for an outage. An account sweep is the slowest task here and
// therefore the likeliest to hit the pass deadline.
func TestAFailingAccountSweepIsNotFatal(t *testing.T) {
	store := newFakeStore()
	store.fail["accounts"] = errors.New("deadlock detected")

	quietSweeper(store).once(context.Background())

	if store.called["accounts"] != 1 {
		t.Fatalf("the account sweep ran %d times, want 1", store.called["accounts"])
	}
}
