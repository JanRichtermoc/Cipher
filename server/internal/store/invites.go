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
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrInviteNotRedeemable is returned when a code is unknown, already redeemed,
// or expired.
//
// **One error for all three, on purpose.** A caller that could distinguish
// "never existed" from "already used" would let an attacker confirm that a
// guessed code was once real, and one that could distinguish "expired" would
// leak the same fact more slowly. Since a redeemed invite is deleted rather than
// flagged (docs/BACKEND.md §2.2), the database cannot tell these apart either —
// the schema and the API agree, rather than the API papering over a schema that
// knows more than it should.
var ErrInviteNotRedeemable = errors.New("store: invite is not redeemable")

// ErrAccountExists is returned when the account identifier is already taken.
var ErrAccountExists = errors.New("store: account already exists")

// Account is a row of the accounts table.
type Account struct {
	ACI            uuid.UUID
	IdentityKey    []byte
	RegistrationID uint32
}

// CreateInvite stores a hashed invite.
//
// It takes the hash, never the code. The code exists only in memory on the path
// between Generate and the operator's terminal, and this signature is what
// makes that non-negotiable rather than a convention.
func (db *DB) CreateInvite(ctx context.Context, codeHash []byte, expiresAt time.Time) error {
	_, err := db.pool.Exec(ctx,
		`INSERT INTO invites (code_hash, expires_at) VALUES ($1, $2)`,
		codeHash, expiresAt)
	if err != nil {
		return fmt.Errorf("create invite: %w", err)
	}
	return nil
}

// RedeemInvite consumes an invite and creates the account it authorises, in one
// transaction.
//
// # Why this is a single statement rather than SELECT-then-DELETE
//
// The obvious implementation reads the invite, checks it, then deletes it. Two
// concurrent redemptions of the same code both pass the check before either
// deletes, and both create an account — the code is single-use in intent and
// multi-use in fact. It is a narrow window and it is trivially reachable by
// sending the same request twice at once.
//
// `DELETE ... WHERE ... RETURNING` decides and consumes in one atomic
// statement. Exactly one caller gets a row back; the loser sees no rows and is
// rejected identically to someone presenting an unknown code. Single-use is
// then a property of the statement rather than of the ordering of two of them.
//
// The expiry predicate is in the same WHERE clause for the same reason: an
// expiry checked in Go against a row read a moment earlier is checked against a
// clock that is not the database's.
func (db *DB) RedeemInvite(
	ctx context.Context,
	codeHash []byte,
	account Account,
) error {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("redeem: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// now() is the database's clock, consistently with the expiry sweep. Using
	// the application's would mean two processes disagreeing about whether an
	// invite is live.
	var consumed []byte
	err = tx.QueryRow(ctx,
		`DELETE FROM invites
		  WHERE code_hash = $1 AND expires_at > now()
		  RETURNING code_hash`,
		codeHash).Scan(&consumed)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrInviteNotRedeemable
	}
	if err != nil {
		return fmt.Errorf("redeem: consume invite: %w", err)
	}

	_, err = tx.Exec(ctx,
		`INSERT INTO accounts (aci, identity_key, registration_id)
		 VALUES ($1, $2, $3)`,
		account.ACI, account.IdentityKey, account.RegistrationID)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
			return ErrAccountExists
		}
		return fmt.Errorf("redeem: create account: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("redeem: commit: %w", err)
	}
	return nil
}

// DeleteExpiredInvites removes lapsed invites and reports how many went.
//
// Part of the retention policy (docs/BACKEND.md §4). An expired invite is not
// merely unusable — RedeemInvite already refuses it — it is a row whose
// existence records that someone was invited and did not join. Sweeping is what
// makes that stop being true.
func (db *DB) DeleteExpiredInvites(ctx context.Context) (int64, error) {
	tag, err := db.pool.Exec(ctx, `DELETE FROM invites WHERE expires_at <= now()`)
	if err != nil {
		return 0, fmt.Errorf("sweep invites: %w", err)
	}
	return tag.RowsAffected(), nil
}

// CountInvites reports how many invites exist. Test and operational support
// only; nothing on a request path calls it.
func (db *DB) CountInvites(ctx context.Context) (int, error) {
	var n int
	if err := db.pool.QueryRow(ctx, `SELECT count(*) FROM invites`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count invites: %w", err)
	}
	return n, nil
}

// AccountExists reports whether an account is present.
func (db *DB) AccountExists(ctx context.Context, aci uuid.UUID) (bool, error) {
	var exists bool
	if err := db.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM accounts WHERE aci = $1)`, aci).Scan(&exists); err != nil {
		return false, fmt.Errorf("account exists: %w", err)
	}
	return exists, nil
}
