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

	"cipher.relay/internal/pushtoken"
)

// PushTokenMaxAge is how long a stored token may go without being refreshed
// before the relay discards it (docs/THREAT_MODEL.md §3.3, "rotate it").
//
// 30 days. What rotation means for a value the relay cannot mint is narrower
// than it sounds: only the device can produce a device token, so the relay's
// half is to stop keeping one that has not been reasserted. A client that is
// still installed re-registers and the row is rewritten under a fresh nonce; a
// client that is gone stops paying for a row that would otherwise sit in a
// seizable database until the account itself was swept at 180 days.
const PushTokenMaxAge = 30 * 24 * time.Hour

// ErrNoPushTokenKey is returned when a push token is written or read while the
// service has no key configured.
//
// Fail closed, and specifically: never store the token in the clear because the
// key is missing. Push does not exist until P8, so this is the expected state on
// the current deployment and it is deliberately not a startup failure — it is a
// failure at the point where a plaintext token would otherwise be written.
var ErrNoPushTokenKey = pushtoken.ErrNoKey

// ErrNoPushToken is returned when an account has no registered token.
var ErrNoPushToken = errors.New("no push token for this account")

// UpsertPushToken stores an APNs device token for an account, encrypted.
//
// The plaintext never reaches a column, a parameter log, or an error string: the
// value bound to the statement is ciphertext, and the nonce beside it is not
// secret. `rotated_at` is set from PostgreSQL's own CURRENT_DATE rather than
// from a time computed in Go, for the same reason the abandonment sweep is
// (AUDIT 5.28): the clock that reads the row should be the clock that wrote it.
//
// Re-registering rewrites the row under a **fresh nonce**, so a device that
// checks in regularly never leaves one ciphertext sitting under one nonce for
// the life of the account.
func (db *DB) UpsertPushToken(ctx context.Context, aci uuid.UUID, token string) error {
	if db.pushCipher == nil {
		return ErrNoPushTokenKey
	}

	ciphertext, nonce, err := db.pushCipher.Seal(aci, token)
	if err != nil {
		// Deliberately not wrapped with the token or its length beyond what the
		// cipher already says: this error reaches a log.
		return fmt.Errorf("seal push token: %w", err)
	}

	if _, err := db.pool.Exec(ctx,
		`INSERT INTO push_tokens (aci, token_ciphertext, token_nonce, rotated_at)
		 SELECT $1, $2, $3, CURRENT_DATE
		  WHERE EXISTS (SELECT 1 FROM accounts WHERE aci = $1)
		 ON CONFLICT (aci) DO UPDATE
		    SET token_ciphertext = EXCLUDED.token_ciphertext,
		        token_nonce      = EXCLUDED.token_nonce,
		        rotated_at       = CURRENT_DATE`,
		aci, ciphertext, nonce); err != nil {
		return fmt.Errorf("upsert push token: %w", err)
	}
	return nil
}

// PushToken returns the decrypted token for an account.
//
// Refuses rather than returning an empty string when the row does not
// authenticate: a ciphertext that fails to open has either been moved between
// accounts, been edited, or been sealed under a different key, and none of those
// is a device this relay should send a notification to.
func (db *DB) PushToken(ctx context.Context, aci uuid.UUID) (string, error) {
	if db.pushCipher == nil {
		return "", ErrNoPushTokenKey
	}

	var ciphertext, nonce []byte
	err := db.pool.QueryRow(ctx,
		`SELECT token_ciphertext, token_nonce FROM push_tokens WHERE aci = $1`,
		aci).Scan(&ciphertext, &nonce)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNoPushToken
		}
		return "", fmt.Errorf("read push token: %w", err)
	}

	token, err := db.pushCipher.Open(aci, ciphertext, nonce)
	if err != nil {
		return "", fmt.Errorf("open push token: %w", err)
	}
	return token, nil
}

// DeletePushToken removes an account's registration.
//
// Separate from account deletion, which the schema's ON DELETE CASCADE already
// covers: this is the "the user turned notifications off" path, and it must
// remove the row rather than blank it, for the same reason a delivered message
// is deleted rather than flagged.
func (db *DB) DeletePushToken(ctx context.Context, aci uuid.UUID) (bool, error) {
	tag, err := db.pool.Exec(ctx, `DELETE FROM push_tokens WHERE aci = $1`, aci)
	if err != nil {
		return false, fmt.Errorf("delete push token: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// DeleteStalePushTokens discards tokens that have not been refreshed within
// PushTokenMaxAge. The sweep's fifth task.
//
// Needs no key: it deletes by date and never opens a ciphertext, so a relay
// running without a push key still sheds this metadata rather than accumulating
// rows it cannot read.
func (db *DB) DeleteStalePushTokens(ctx context.Context) (int64, error) {
	tag, err := db.pool.Exec(ctx,
		`DELETE FROM push_tokens
		  WHERE rotated_at < CURRENT_DATE - $1::int`,
		int(PushTokenMaxAge/(24*time.Hour)))
	if err != nil {
		return 0, fmt.Errorf("sweep push tokens: %w", err)
	}
	return tag.RowsAffected(), nil
}

// PushTokenCiphertext returns the stored bytes without opening them.
//
// Test support, and specifically the test that matters: it is how a test asserts
// that what is in the column is not the token. Reading it through PushToken
// would prove only that the round trip works, which is the assertion a
// plaintext column would also pass.
func (db *DB) PushTokenCiphertext(ctx context.Context, aci uuid.UUID) ([]byte, []byte, error) {
	var ciphertext, nonce []byte
	err := db.pool.QueryRow(ctx,
		`SELECT token_ciphertext, token_nonce FROM push_tokens WHERE aci = $1`,
		aci).Scan(&ciphertext, &nonce)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, ErrNoPushToken
		}
		return nil, nil, fmt.Errorf("read push token ciphertext: %w", err)
	}
	return ciphertext, nonce, nil
}

// BackdatePushToken ages a row past the sweep threshold. Test support only,
// kept beside the sweep it exercises so the two cannot drift — the alternative
// is a test that waits thirty days.
func (db *DB) BackdatePushToken(ctx context.Context, aci uuid.UUID, days int) error {
	if _, err := db.pool.Exec(ctx,
		`UPDATE push_tokens SET rotated_at = CURRENT_DATE - $2::int WHERE aci = $1`,
		aci, days); err != nil {
		return fmt.Errorf("backdate push token: %w", err)
	}
	return nil
}
