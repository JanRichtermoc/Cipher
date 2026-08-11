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

// ErrBundleUnavailable is returned when no bundle can be served.
//
// **One error for every reason**, and the caller must render them all the same
// way: the account does not exist, the account has never uploaded keys, or its
// one-time prekey pool is empty. docs/BACKEND.md §8 forbids account enumeration,
// and a directory that answers "no such account" differently from "that account
// has no keys right now" is an enumeration oracle — it confirms membership of a
// closed circle to anyone who can ask, which for a five-person messenger is most
// of the metadata there is.
var ErrBundleUnavailable = errors.New("store: no prekey bundle available")

// PreKey is a one-time X25519 prekey.
type PreKey struct {
	KeyID     uint32
	PublicKey []byte
}

// SignedPreKey is a signed prekey or a Kyber prekey. Both carry a signature made
// by the account's identity key; the relay never verifies it (see PublishPreKeys).
type SignedPreKey struct {
	KeyID     uint32
	PublicKey []byte
	Signature []byte
}

// PreKeyUpload is what a client publishes.
type PreKeyUpload struct {
	SignedPreKey SignedPreKey
	// KyberLastResort is mandatory. PQXDH is a locked decision and Kyber is
	// never optional, so an upload without it is refused at the API boundary
	// rather than stored and discovered missing at dispense time.
	KyberLastResort SignedPreKey
	KyberOneTime    []SignedPreKey
	OneTimePreKeys  []PreKey
}

// Bundle is what the directory serves.
type Bundle struct {
	RegistrationID uint32
	IdentityKey    []byte
	PreKey         PreKey
	SignedPreKey   SignedPreKey
	KyberPreKey    SignedPreKey
	// KyberWasLastResort reports that the one-time Kyber pool was empty and the
	// reusable key was served instead. Surfaced so the caller can log the
	// degradation — it is the observable symptom of the pool-drain attack in
	// AUDIT 3.1 — not so it can be returned to the client, which cannot act on it.
	KyberWasLastResort bool
}

// PublishPreKeys stores an upload.
//
// # What this does not do
//
// It does not verify any signature. `processPreKeyBundle` does that on the
// client, on every use, against the identity key in the same bundle. Verifying
// here would be a second unreviewed copy of a signature check, and — much worse —
// a client that trusted the server's verdict would have no protection at all from
// a hostile relay (docs/THREAT_MODEL.md §1.1). The relay's job is to hold bytes
// and hand them back, not to have an opinion about them.
//
// # Replace versus add
//
// The signed prekey and the last-resort Kyber key are *replaced*: exactly one of
// each exists per account, which the schema enforces with a primary key and a
// partial unique index rather than by trusting this function.
//
// One-time prekeys are *added*, with conflicts ignored. Replacing them would
// discard unused keys on every replenish, which is the opposite of what a client
// topping up its pool intends — and an accidental "replace" would silently reduce
// a healthy pool to whatever the last upload contained.
//
// # The cumulative pool ceiling (AUDIT 5.40)
//
// Because one-time keys are added and nothing removes them except being dispensed
// or the account being deleted, the two pools had no cumulative bound at all.
// `MaxPreKeysPerUpload` bounds one request and the publish limit bounds requests
// at 6/day, which still leaves ≈1,200 Kyber rows a day at up to 4 KiB each —
// ≈5 MiB/day/account, ≈900 MiB across the 180-day `AccountRetentionDays` window.
// maxPerPool bounds each one-time pool instead.
//
// **The two long-lived keys are always written, whatever the pools hold.** That
// asymmetry is the point rather than an oversight: the signed prekey and the
// last-resort Kyber key are what *rotation* replaces (AUDIT 2.4), and refusing a
// whole publication because a pool was full would stop rotation dead. It would
// also be a lockout, because the client retries a publication that never
// succeeded — six attempts a day, forever, with every peer's session setup
// failing meanwhile. That is AUDIT 5.32's shape and it is worse than the storage
// this bounds.
//
// **What is refused is only the excess, and the caller is told.** Unlike the
// message-queue ceiling (5.39), silence is not required here and would be
// harmful: the publisher *is* the owner of the data, so there is no third party
// to leak a fact about, and `publish` returns the resulting pool counts, which is
// the number the client already replenishes against. A client at the ceiling
// reads a full pool and stops asking; a client below it is topped up as before.
//
// **Concurrency.** The count and the inserts share one transaction but not one
// statement, so two publications for the same account racing each other can
// overshoot by up to one upload each — bounded by `api.MaxPreKeysPerUpload`. The
// publish rate limit is 6/day/account, so this is a narrow window on a slow path,
// and closing it exactly would mean locking the account's rows on every publish.
//
// A non-positive maxPerPool stores no one-time keys at all while still rotating
// the long-lived pair. That is the fail-closed direction: an unbounded pool is
// the finding, so a misconfigured ceiling must not be the way back to it.
func (db *DB) PublishPreKeys(
	ctx context.Context,
	aci uuid.UUID,
	up PreKeyUpload,
	maxPerPool int,
) error {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("publish prekeys: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`INSERT INTO signed_prekeys (aci, key_id, public_key, signature)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (aci) DO UPDATE
		   SET key_id = EXCLUDED.key_id,
		       public_key = EXCLUDED.public_key,
		       signature = EXCLUDED.signature`,
		aci, up.SignedPreKey.KeyID, up.SignedPreKey.PublicKey,
		up.SignedPreKey.Signature); err != nil {
		return fmt.Errorf("publish signed prekey: %w", err)
	}

	// The old last-resort row is removed before the new one is inserted, because
	// the uniqueness constraint is partial (one row WHERE last_resort) and the
	// new key almost always has a different key_id, so ON CONFLICT has nothing
	// to match on.
	if _, err := tx.Exec(ctx,
		`DELETE FROM kyber_prekeys WHERE aci = $1 AND last_resort`, aci); err != nil {
		return fmt.Errorf("clear last-resort kyber prekey: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO kyber_prekeys (aci, key_id, public_key, signature, last_resort)
		 VALUES ($1, $2, $3, $4, true)
		 ON CONFLICT (aci, key_id) DO UPDATE
		   SET public_key = EXCLUDED.public_key,
		       signature = EXCLUDED.signature,
		       last_resort = true`,
		aci, up.KyberLastResort.KeyID, up.KyberLastResort.PublicKey,
		up.KyberLastResort.Signature); err != nil {
		return fmt.Errorf("publish last-resort kyber prekey: %w", err)
	}

	// Room is measured once per pool, before either loop, and the pools are
	// measured separately because they fill separately: a client can be short of
	// Kyber keys while its curve pool is untouched, and one shared allowance would
	// let whichever list came first consume the other's.
	kyberRoom, err := poolRoom(ctx, tx,
		`SELECT count(*) FROM kyber_prekeys WHERE aci = $1 AND NOT last_resort`,
		aci, maxPerPool)
	if err != nil {
		return fmt.Errorf("publish kyber prekey: %w", err)
	}
	for _, k := range up.KyberOneTime {
		if kyberRoom <= 0 {
			break
		}
		tag, err := tx.Exec(ctx,
			`INSERT INTO kyber_prekeys (aci, key_id, public_key, signature, last_resort)
			 VALUES ($1, $2, $3, $4, false)
			 ON CONFLICT (aci, key_id) DO NOTHING`,
			aci, k.KeyID, k.PublicKey, k.Signature)
		if err != nil {
			return fmt.Errorf("publish kyber prekey: %w", err)
		}
		// Only a row that was actually written spends the allowance. A key_id the
		// pool already holds inserts nothing, and charging for it would shrink the
		// pool a retried publication can reach.
		kyberRoom -= int(tag.RowsAffected())
	}

	curveRoom, err := poolRoom(ctx, tx,
		`SELECT count(*) FROM one_time_prekeys WHERE aci = $1`, aci, maxPerPool)
	if err != nil {
		return fmt.Errorf("publish one-time prekey: %w", err)
	}
	for _, k := range up.OneTimePreKeys {
		if curveRoom <= 0 {
			break
		}
		tag, err := tx.Exec(ctx,
			`INSERT INTO one_time_prekeys (aci, key_id, public_key)
			 VALUES ($1, $2, $3)
			 ON CONFLICT (aci, key_id) DO NOTHING`,
			aci, k.KeyID, k.PublicKey)
		if err != nil {
			return fmt.Errorf("publish one-time prekey: %w", err)
		}
		curveRoom -= int(tag.RowsAffected())
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("publish prekeys: commit: %w", err)
	}
	return nil
}

// poolRoom reports how many more rows a one-time pool may accept.
//
// Never negative: a pool already over its ceiling — which a lowered ceiling
// produces, and which is the only way to get there — accepts nothing further and
// drains normally as its keys are dispensed. Nothing deletes the excess, because
// deleting a published key costs a peer the session it was about to establish,
// and the pool is bounded again the moment it falls back under the line.
func poolRoom(ctx context.Context, tx pgx.Tx, countQuery string, aci uuid.UUID, ceiling int) (int, error) {
	var held int
	if err := tx.QueryRow(ctx, countQuery, aci).Scan(&held); err != nil {
		return 0, err
	}
	if room := ceiling - held; room > 0 {
		return room, nil
	}
	return 0, nil
}

// DispenseBundle serves one bundle and consumes the keys it used.
//
// # One-time means one transaction
//
// The one-time prekey is selected and deleted by a single statement, with
// `FOR UPDATE SKIP LOCKED` on the inner select. Both halves matter:
//
//   - Without the single statement, two concurrent fetches read the same row
//     before either deletes and hand the same one-time prekey to two peers — at
//     which point it is not one-time, and the forward secrecy it exists to provide
//     is gone for both sessions.
//   - Without SKIP LOCKED, the second fetch blocks on the first's row lock and
//     then finds it deleted, so a peer with a healthy pool gets a spurious
//     "unavailable" under concurrency.
//
// # The Kyber fallback, and what it costs
//
// A one-time Kyber prekey is preferred and consumed. When that pool is empty the
// reusable last-resort key is served and *not* deleted, so PQXDH still runs — but
// the KEM contribution to that session's secret is shared with every other session
// that also fell back. Classical X25519 forward secrecy is unaffected. This is the
// degradation an attacker draining the pool is buying, and it is why the fetch
// rate limit is a security control rather than a capacity one (AUDIT 3.1).
//
// # There is no fallback for the X25519 one-time prekey
//
// When that pool is empty the bundle cannot be served at all, because the client's
// `PeerKeyBundle` requires a one-time prekey — it is not optional in that type.
// Exhaustion is therefore a denial of service against session *setup* with that
// peer until they next replenish. Bounded by the per-account fetch limit and by
// the fact that fetching requires an account, which requires an invite.
func (db *DB) DispenseBundle(ctx context.Context, aci uuid.UUID) (Bundle, error) {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return Bundle{}, fmt.Errorf("dispense: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var b Bundle
	err = tx.QueryRow(ctx,
		`SELECT registration_id, identity_key FROM accounts WHERE aci = $1`,
		aci).Scan(&b.RegistrationID, &b.IdentityKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return Bundle{}, ErrBundleUnavailable
	}
	if err != nil {
		return Bundle{}, fmt.Errorf("dispense: read account: %w", err)
	}

	err = tx.QueryRow(ctx,
		`SELECT key_id, public_key, signature FROM signed_prekeys WHERE aci = $1`,
		aci).Scan(&b.SignedPreKey.KeyID, &b.SignedPreKey.PublicKey, &b.SignedPreKey.Signature)
	if errors.Is(err, pgx.ErrNoRows) {
		// The account exists but has never published. Indistinguishable from
		// "no such account" by design.
		return Bundle{}, ErrBundleUnavailable
	}
	if err != nil {
		return Bundle{}, fmt.Errorf("dispense: read signed prekey: %w", err)
	}

	err = tx.QueryRow(ctx,
		`DELETE FROM one_time_prekeys
		  WHERE (aci, key_id) IN (
		    SELECT aci, key_id FROM one_time_prekeys
		     WHERE aci = $1
		     ORDER BY key_id
		     LIMIT 1
		     FOR UPDATE SKIP LOCKED
		  )
		  RETURNING key_id, public_key`,
		aci).Scan(&b.PreKey.KeyID, &b.PreKey.PublicKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return Bundle{}, ErrBundleUnavailable
	}
	if err != nil {
		return Bundle{}, fmt.Errorf("dispense: consume one-time prekey: %w", err)
	}

	err = tx.QueryRow(ctx,
		`DELETE FROM kyber_prekeys
		  WHERE (aci, key_id) IN (
		    SELECT aci, key_id FROM kyber_prekeys
		     WHERE aci = $1 AND NOT last_resort
		     ORDER BY key_id
		     LIMIT 1
		     FOR UPDATE SKIP LOCKED
		  )
		  RETURNING key_id, public_key, signature`,
		aci).Scan(&b.KyberPreKey.KeyID, &b.KyberPreKey.PublicKey, &b.KyberPreKey.Signature)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		b.KyberWasLastResort = true
		err = tx.QueryRow(ctx,
			`SELECT key_id, public_key, signature FROM kyber_prekeys
			  WHERE aci = $1 AND last_resort`,
			aci).Scan(&b.KyberPreKey.KeyID, &b.KyberPreKey.PublicKey, &b.KyberPreKey.Signature)
		if errors.Is(err, pgx.ErrNoRows) {
			// No Kyber material at all. Refused rather than served without it:
			// PQXDH is not optional, and a bundle missing its KEM half would be
			// a silent downgrade to classical X3DH.
			return Bundle{}, ErrBundleUnavailable
		}
		if err != nil {
			return Bundle{}, fmt.Errorf("dispense: read last-resort kyber prekey: %w", err)
		}
	case err != nil:
		return Bundle{}, fmt.Errorf("dispense: consume kyber prekey: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return Bundle{}, fmt.Errorf("dispense: commit: %w", err)
	}
	return b, nil
}

// CountOneTimePreKeys reports the remaining pool size.
//
// Returned to the owner on upload so the client replenishes on a threshold rather
// than a schedule. It is the account's own count and is never disclosed for
// anyone else — the size of a peer's pool is exactly the measurement an attacker
// draining it wants.
func (db *DB) CountOneTimePreKeys(ctx context.Context, aci uuid.UUID) (int, error) {
	var n int
	if err := db.pool.QueryRow(ctx,
		`SELECT count(*) FROM one_time_prekeys WHERE aci = $1`, aci).Scan(&n); err != nil {
		return 0, fmt.Errorf("count one-time prekeys: %w", err)
	}
	return n, nil
}

// CountKyberOneTimePreKeys reports the remaining one-time Kyber pool.
func (db *DB) CountKyberOneTimePreKeys(ctx context.Context, aci uuid.UUID) (int, error) {
	var n int
	if err := db.pool.QueryRow(ctx,
		`SELECT count(*) FROM kyber_prekeys WHERE aci = $1 AND NOT last_resort`,
		aci).Scan(&n); err != nil {
		return 0, fmt.Errorf("count kyber prekeys: %w", err)
	}
	return n, nil
}
