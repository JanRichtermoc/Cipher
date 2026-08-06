// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// AccountRetentionDays is the abandonment threshold from docs/BACKEND.md §4.
//
// An account that has not authenticated for this long is deleted, and everything
// that references it goes with it through the schema's cascades: session tokens,
// one-time, signed and Kyber prekeys, undelivered messages, and the push token.
//
// The number is a retention policy, not a tuning knob. `THREAT_MODEL.md` §3.1
// says the control is deletion rather than encryption, and an account row is the
// public identity key, the registration id and an activity date — exactly the
// material a §1.1 seizure is after. A device that is lost, wiped, or simply never
// opened again would otherwise leave that on the relay for as long as the relay
// exists.
const AccountRetentionDays = 180

// maxAccountsPerSweep bounds one pass.
//
// Same reason as maxAttachmentsPerSweep: an account delete cascades across six
// tables, so an unbounded statement could hold them for as long as the backlog
// takes. A backlog is cleared over several ticks instead, and at an hourly
// interval this ceiling is far above anything a private circle can produce.
const maxAccountsPerSweep = 500

// DeleteAbandonedAccounts removes accounts unseen for AccountRetentionDays.
//
// # Why this is a sweep and not a predicate
//
// Nothing else deletes an account. There is no explicit-deletion endpoint yet and
// no expiry filter that could make an abandoned row *invisible* the way a lapsed
// message is — so before this existed, `last_seen` was a column the schema
// justified by a policy no code implemented, and docs/BACKEND.md §4's
// "abandonment sweep at 180 days" was aspirational (AUDIT 5.28).
//
// # Day resolution, and the comparison is the database's
//
// `last_seen` is a DATE (schema, accounts) because the sweep needs no more than
// that and a coarser activity trace is a smaller one. `CURRENT_DATE` is evaluated
// by Postgres for the same reason LookupSession's expiry predicate is: a
// threshold computed in Go is computed against a clock that is not the one the
// row was written by.
//
// # The one thing that does not cascade
//
// Attachments have no owner column — the id is the whole capability
// (docs/BACKEND.md §2.8) — so an abandoned account's blobs are not reachable from
// its row and are not deleted here. They are already covered: the attachment TTL
// is seven days, far inside 180, so there is nothing left to cascade to.
func (db *DB) DeleteAbandonedAccounts(ctx context.Context) (int64, error) {
	tag, err := db.pool.Exec(ctx,
		`DELETE FROM accounts
		  WHERE aci IN (
		    SELECT aci FROM accounts
		     WHERE last_seen < CURRENT_DATE - $1::int
		     LIMIT $2
		  )`, AccountRetentionDays, maxAccountsPerSweep)
	if err != nil {
		return 0, fmt.Errorf("sweep accounts: %w", err)
	}
	return tag.RowsAffected(), nil
}

// BackdateLastSeen moves an account's activity date into the past.
//
// Test support only, and it exists for the same reason ExpireMessageNow does:
// the alternative is a test that waits out the real threshold, which here is 180
// days. Kept beside the sweep it exercises so the two cannot drift.
func (db *DB) BackdateLastSeen(ctx context.Context, aci uuid.UUID, days int) error {
	if _, err := db.pool.Exec(ctx,
		`UPDATE accounts SET last_seen = CURRENT_DATE - $2::int WHERE aci = $1`,
		aci, days); err != nil {
		return fmt.Errorf("backdate last_seen: %w", err)
	}
	return nil
}

// DaysSinceLastSeen reports how many days ago an account last authenticated.
//
// Test and operational support only. An account that does not exist is an error
// rather than a zero, so a caller cannot read "seen today" out of a missing row.
func (db *DB) DaysSinceLastSeen(ctx context.Context, aci uuid.UUID) (int, error) {
	var days int
	err := db.pool.QueryRow(ctx,
		`SELECT CURRENT_DATE - last_seen FROM accounts WHERE aci = $1`, aci).Scan(&days)
	if err != nil {
		return 0, fmt.Errorf("days since last seen: %w", err)
	}
	return days, nil
}
