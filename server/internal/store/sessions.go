// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrSessionNotFound is returned when a token is unknown, expired, or belongs to
// an account that no longer exists.
//
// One error for all of them, and the caller must render all of them as the same
// 401. "Expired" and "unknown" are different facts about a presented credential,
// and telling them apart tells an attacker that a value they hold was once real.
var ErrSessionNotFound = errors.New("store: session not found")

// ErrLastSeenNotRefreshed reports that the token authenticated but the account's
// activity date could not be written.
//
// Returned *alongside a valid aci*, which is the whole point: the caller has a
// real answer and a bookkeeping problem, and must not confuse the two. Failing the
// request would turn a housekeeping error into an outage, which is why this was
// originally swallowed — but swallowing it made the failure unobservable, and now
// that the abandonment sweep exists (AccountRetentionDays) a `last_seen` that
// silently stops advancing is an active account counting down to deletion. So the
// fact travels to a caller that has a logger, and the decision to continue is made
// where it can be seen. AUDIT 5.28.
//
// A caller that treats any non-nil error as fatal fails closed, which is the safe
// direction to be wrong in but is not the intended handling; check for this
// sentinel first, as api.AuthHandler.Require does.
var ErrLastSeenNotRefreshed = errors.New("store: session valid but last_seen was not refreshed")

// CreateSession stores a hashed token for an account.
//
// Takes the hash, never the token. The signature is what makes "the token is
// never persisted" a property of the type system rather than of everyone
// remembering.
func (db *DB) CreateSession(
	ctx context.Context,
	tokenHash []byte,
	aci uuid.UUID,
	expiresAt time.Time,
) error {
	_, err := db.pool.Exec(ctx,
		`INSERT INTO session_tokens (token_hash, aci, expires_at) VALUES ($1, $2, $3)`,
		tokenHash, aci, expiresAt)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

// LookupSession resolves a token hash to the account it authenticates.
//
// The expiry predicate is in the SQL, evaluated against now(). An expiry compared
// in Go against a row read a moment earlier is compared against a clock that is
// not the database's — and unlike most such mistakes, this one fails *open*: it
// would accept a token the database considers dead.
//
// It also refreshes `accounts.last_seen`, which is the only thing that keeps an
// account out of the abandonment sweep. Done here because this is the one call on
// every authenticated path — coupling the two is what stops a route added later
// from authenticating without marking the account alive — and done as a separate
// statement rather than a CTE because it must not be able to fail the lookup.
//
// A refresh failure returns the aci together with ErrLastSeenNotRefreshed rather
// than nothing or nil; see that sentinel for why silence was the wrong answer.
func (db *DB) LookupSession(ctx context.Context, tokenHash []byte) (uuid.UUID, error) {
	var aci uuid.UUID
	err := db.pool.QueryRow(ctx,
		`SELECT aci FROM session_tokens WHERE token_hash = $1 AND expires_at > now()`,
		tokenHash).Scan(&aci)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrSessionNotFound
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("lookup session: %w", err)
	}

	// Day resolution, and only when it has actually changed, so this is a no-op
	// write for every request after the first each day. `last_seen` is an
	// activity trace (docs/BACKEND.md §2.1) — writing it more precisely than the
	// sweep needs would buy nothing and record more.
	if _, err := db.pool.Exec(ctx,
		`UPDATE accounts SET last_seen = CURRENT_DATE
		  WHERE aci = $1 AND last_seen <> CURRENT_DATE`, aci); err != nil {
		// Still not fatal — the aci is returned and the caller is expected to
		// serve the request. What changed is that the failure is no longer
		// invisible: one lost day costs nothing against a 180-day threshold, but
		// a refresh that has been failing since some deploy nobody noticed is an
		// account being counted down to deletion while it is in daily use.
		//
		// The underlying error is not carried. It would reach a log line as free
		// text, and this one runs on every authenticated request; the sentinel
		// says which write failed, and the lookup path above already reports a
		// database error in full when the *read* fails.
		return aci, ErrLastSeenNotRefreshed
	}
	return aci, nil
}

// RotateSession atomically replaces one token with another.
//
// Both halves in one transaction, and the delete is conditional on the old token
// still being live. Two properties follow, and neither survives doing this as two
// statements:
//
//   - There is never a moment when both tokens work. A rotation that inserted
//     first would leave the old credential valid for as long as the delete took,
//     which is precisely the window an attacker who stole it wants.
//   - There is never a moment when neither works. A rotation that deleted first
//     and then failed to insert would sign the user out with no way back.
//
// The old token is invalidated immediately. The consequence is real and is the
// right trade: a client that loses the response has lost its session and must
// sign in again. Keeping the old one alive "just briefly" is how a rotation
// becomes an issuance.
func (db *DB) RotateSession(
	ctx context.Context,
	oldHash, newHash []byte,
	expiresAt time.Time,
) (uuid.UUID, error) {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, fmt.Errorf("rotate: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var aci uuid.UUID
	err = tx.QueryRow(ctx,
		`DELETE FROM session_tokens
		  WHERE token_hash = $1 AND expires_at > now()
		  RETURNING aci`,
		oldHash).Scan(&aci)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrSessionNotFound
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("rotate: consume old token: %w", err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO session_tokens (token_hash, aci, expires_at) VALUES ($1, $2, $3)`,
		newHash, aci, expiresAt); err != nil {
		return uuid.Nil, fmt.Errorf("rotate: store new token: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, fmt.Errorf("rotate: commit: %w", err)
	}
	return aci, nil
}

// DeleteSession revokes one token. Signing out.
//
// Idempotent: revoking an already-revoked token succeeds. The caller is holding
// the credential, so there is nothing to learn from the outcome, and returning an
// error would make a double sign-out look like a failure.
func (db *DB) DeleteSession(ctx context.Context, tokenHash []byte) error {
	if _, err := db.pool.Exec(ctx,
		`DELETE FROM session_tokens WHERE token_hash = $1`, tokenHash); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

// DeleteSessionsForAccount revokes every session an account holds.
//
// "Sign out everywhere", and the response to a suspected compromise. Returns how
// many went so the caller can tell the user something true.
func (db *DB) DeleteSessionsForAccount(ctx context.Context, aci uuid.UUID) (int64, error) {
	tag, err := db.pool.Exec(ctx, `DELETE FROM session_tokens WHERE aci = $1`, aci)
	if err != nil {
		return 0, fmt.Errorf("delete sessions for account: %w", err)
	}
	return tag.RowsAffected(), nil
}

// DeleteExpiredSessions sweeps lapsed tokens (docs/BACKEND.md §4).
//
// LookupSession already refuses an expired token, so this is not about access
// control. It is about retention: an expired row still records that an account
// existed and was active around a particular time, and the point of the policy is
// that such rows stop existing rather than merely stop working.
func (db *DB) DeleteExpiredSessions(ctx context.Context) (int64, error) {
	tag, err := db.pool.Exec(ctx, `DELETE FROM session_tokens WHERE expires_at <= now()`)
	if err != nil {
		return 0, fmt.Errorf("sweep sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

// CountSessionsForAccount reports how many live sessions an account holds.
// Test and operational support only.
func (db *DB) CountSessionsForAccount(ctx context.Context, aci uuid.UUID) (int, error) {
	var n int
	if err := db.pool.QueryRow(ctx,
		`SELECT count(*) FROM session_tokens WHERE aci = $1`, aci).Scan(&n); err != nil {
		return 0, fmt.Errorf("count sessions: %w", err)
	}
	return n, nil
}
