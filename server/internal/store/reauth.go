// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrNoAccountKey is returned when an account has published no re-authentication
// key.
//
// Deliberately the *same* outcome the caller gives an unknown account and a bad
// signature: an account that predates migration 0003 has no key, and letting a
// caller tell "no such account" from "that account cannot re-authenticate yet"
// would make this endpoint an existence oracle for the whole circle. The handler
// collapses all three; this sentinel exists so the store can still say which
// happened in a test.
var ErrNoAccountKey = errors.New("store: account has no re-authentication key")

// SetAccountKey publishes an account's Ed25519 re-authentication public key.
//
// Takes the public half only — there is no signature on this API that could
// accept a private one, which is the same reason CreateSession takes a hash.
//
// # Why it is write-once rather than write-anytime
//
// A caller that could *replace* this key could lock the real owner out
// permanently: a stolen session token is a temporary capability, but overwriting
// the re-authentication key converts it into a permanent one, and the owner's
// own device could then never re-authenticate again. So a key may be published
// when there is none, and re-published only to the identical value (which makes
// the client's "publish if absent" path idempotent and safe to retry). Changing
// it requires the account to be re-created, which is what losing the device
// already means (docs/BACKEND.md §6).
func (db *DB) SetAccountKey(ctx context.Context, aci uuid.UUID, key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("set account key: want 32 bytes, got %d", len(key))
	}
	tag, err := db.pool.Exec(ctx,
		`UPDATE accounts SET reauth_key = $2
		  WHERE aci = $1 AND (reauth_key IS NULL OR reauth_key = $2)`,
		aci, key)
	if err != nil {
		return fmt.Errorf("set account key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Either no such account, or one whose key is already something else.
		// The handler answers both identically.
		return ErrNoAccountKey
	}
	return nil
}

// AccountKey reads an account's re-authentication public key.
func (db *DB) AccountKey(ctx context.Context, aci uuid.UUID) ([]byte, error) {
	var key []byte
	err := db.pool.QueryRow(ctx,
		`SELECT reauth_key FROM accounts WHERE aci = $1`, aci).Scan(&key)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoAccountKey
	}
	if err != nil {
		return nil, fmt.Errorf("account key: %w", err)
	}
	if len(key) == 0 {
		return nil, ErrNoAccountKey
	}
	return key, nil
}

// HasAccountKey reports whether an account has published one. Used by the
// client's publish-if-absent path and by tests; never by the challenge handler,
// which must behave identically whatever the answer.
func (db *DB) HasAccountKey(ctx context.Context, aci uuid.UUID) (bool, error) {
	key, err := db.AccountKey(ctx, aci)
	if errors.Is(err, ErrNoAccountKey) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return len(key) == 32, nil
}
