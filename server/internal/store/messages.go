// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Envelope size bounds, derived from CipherCrypto/Sources/Wire/Envelope.swift and
// duplicated by the schema's CHECK: headerSize 31 plus a ciphertext of 1..65536.
//
// These are the *only* facts the relay knows about an envelope. It does not read
// the wire version, the payload type, the sender field, or the timestamp — all of
// which are in there and all of which it could parse. Not parsing them is the
// point: a server that understands the format acquires opinions about it, and
// every opinion is a coupling that has to be revised in lockstep with the client
// and a place where a hostile operator could make a decision about someone's mail.
const (
	MinEnvelopeBytes = 32
	MaxEnvelopeBytes = 65567
)

// PendingMessage is one undelivered envelope.
type PendingMessage struct {
	ID       uuid.UUID
	Envelope []byte
}

// EnqueueMessage stores an envelope for a recipient, subject to that recipient's
// pending-byte ceiling.
//
// # Sending to an account that does not exist is not an error
//
// `recipient_aci` has a foreign key, so an insert for an unknown account fails.
// That failure is swallowed and the caller is told the message was accepted.
//
// This looks like hiding a bug and is deliberate: reporting "no such account"
// would be an enumeration oracle, and a cleaner one than anything else the relay
// exposes. The prekey directory already answers identically for unknown,
// never-published and drained accounts (docs/BACKEND.md §8) precisely so that
// membership of the circle cannot be probed; a send endpoint that 404s only for
// strangers would hand that back.
//
// It costs a legitimate client nothing. An `aci` is only obtainable by fetching a
// bundle, which requires the account to exist and to have published keys, so a
// real sender never addresses a stranger. The only caller who does is probing.
//
// # The pending-byte ceiling (AUDIT 5.39)
//
// maxPendingBytes bounds the total `octet_length(envelope)` a single recipient
// can have waiting. This was the one authenticated growth path on the relay with
// no quota: blobs are bounded by count and bytes, publication by rate, ack and
// delete by rate, and this by nothing but the 60/minute send limit against a
// 30-day TTL — ≈5.3 GiB per day per sending account, retained for a month, on a
// box whose disk is what the retention sweep needs in order to run at all.
//
// **A refused message is dropped exactly as a stranger's is, and for the same
// reason.** The caller must answer identically whether or not a row was written:
// "this recipient's queue is full" is a statement about the recipient — that they
// exist, that they are not collecting their mail — and telling the sender turns
// the ceiling into a better oracle than the one the EXISTS above exists to avoid.
// The recipient cannot be told either; there is no channel to them that is not
// the queue itself. So the drop is silent to both parties by construction, which
// is the accepted cost recorded in docs/BACKEND.md §5, and it is the reason the
// ceiling is chosen high enough never to bind on honest traffic rather than
// merely "high enough".
//
// **Expired-but-unswept rows count.** There is no `expires_at > now()` here on
// purpose: the ceiling protects disk, a lapsed row is still on the disk until the
// hourly sweep reaches it, and a quota that does not measure what it protects is
// the shape AUDIT 5.22 records ("an unmeasurable quota is the same as no quota").
// The honest cost is bounded by the sweep interval and only bites a recipient who
// is already at the ceiling when their queue lapses; every read path already
// hides expired rows, so it changes nothing they can see.
//
// **Under concurrency it can overshoot, by a bounded amount.** This is one
// statement, so the sum and the insert share a snapshot — but under READ
// COMMITTED a concurrent statement takes its own, and neither sees the other's
// uncommitted row. N sends in flight at once can therefore each pass a check that
// only one of them should, so the queue can exceed the ceiling by at most
// (N-1) × MaxEnvelopeBytes. N is bounded by the pool: MaxConns is 16 in Open, so
// the overshoot is under 1 MiB — around 3% of the default ceiling, which is
// carrying far more headroom than that. Closing it exactly would need a per-
// recipient lock on the send path, which buys 3% for a new contention target on
// the busiest endpoint. Written down rather than discovered later.
//
// **A non-positive ceiling refuses everything**, because `pending + n <= 0` is
// false for every legal envelope. That is the fail-closed direction on purpose: a
// misconfigured relay must not be one whose quota silently does not exist, which
// is the state this finding describes. `config.Load` refuses a non-positive value
// outright, so production reaches this only through a caller that names one.
//
// No new index: `messages_recipient_idx (recipient_aci, expires_at)` already
// serves the lookup by its leading column. The aggregate does visit the heap,
// since `envelope` is not in any index — but `octet_length` on a bytea reads the
// varlena header rather than detoasting, so a large envelope costs a tuple, not a
// TOAST fetch. The scan is self-limiting: it is bounded by the ceiling it is
// enforcing, and the send limit bounds how often it runs.
//
// Returns whether a row was actually written, for tests and metrics — never for
// the response. The two reasons a row is not written are deliberately
// indistinguishable to this caller, because they must be indistinguishable to the
// sender.
func (db *DB) EnqueueMessage(
	ctx context.Context,
	recipient uuid.UUID,
	envelope []byte,
	ttl time.Duration,
	maxPendingBytes int64,
) (bool, error) {
	if len(envelope) < MinEnvelopeBytes || len(envelope) > MaxEnvelopeBytes {
		return false, fmt.Errorf("envelope is %d bytes, want %d..%d",
			len(envelope), MinEnvelopeBytes, MaxEnvelopeBytes)
	}

	// A random id, never a sequence: a monotonic value leaks the relay's total
	// message volume and cross-account ordering to anyone who sees one.
	id, err := uuid.NewRandom()
	if err != nil {
		return false, fmt.Errorf("enqueue: %w", err)
	}

	// ON CONFLICT DO NOTHING on the foreign key is not a thing, so the insert is
	// guarded by an EXISTS instead: a plain insert would raise a constraint
	// violation that this function would have to inspect by SQLSTATE, and
	// distinguishing "no such account" from a real database fault by error code
	// is exactly the kind of thing that silently starts returning the wrong
	// answer after a driver upgrade.
	//
	// The quota rides in the same statement for the same reason it is not a
	// SELECT followed by an INSERT: a separate read would widen the window above
	// from one statement to a round trip.
	tag, err := db.pool.Exec(ctx,
		`INSERT INTO messages (id, recipient_aci, envelope, expires_at)
		 SELECT $1, $2, $3, $4
		  WHERE EXISTS (SELECT 1 FROM accounts WHERE aci = $2)
		    AND (SELECT coalesce(sum(octet_length(envelope)), 0)
		           FROM messages WHERE recipient_aci = $2) + $5 <= $6`,
		id, recipient, envelope, time.Now().Add(ttl), len(envelope), maxPendingBytes)
	if err != nil {
		return false, fmt.Errorf("enqueue message: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// PendingBytes reports how many envelope bytes await an account.
//
// Test and operational support only, and it must stay that way: it is the
// quantity the ceiling above is enforced against, so exposing it through the API
// would hand a caller exactly the recipient-state oracle that enforcement is
// shaped to avoid. Counts expired-but-unswept rows, because the ceiling does.
func (db *DB) PendingBytes(ctx context.Context, recipient uuid.UUID) (int64, error) {
	var n int64
	if err := db.pool.QueryRow(ctx,
		`SELECT coalesce(sum(octet_length(envelope)), 0)
		   FROM messages WHERE recipient_aci = $1`, recipient).Scan(&n); err != nil {
		return 0, fmt.Errorf("pending bytes: %w", err)
	}
	return n, nil
}

// PendingMessages returns up to limit undelivered envelopes for an account.
//
// **Reading does not delete.** Delivery is acknowledged separately, because a
// response lost in transit would otherwise destroy the message — the client would
// have no copy and the server would have no row. Delete-on-read is the version of
// this that looks simpler and loses mail.
//
// Ordered by expiry, which given a fixed TTL is arrival order. The relay does not
// promise ordering beyond that and the client must not depend on it: the sequence
// numbers that actually order a conversation are inside the ciphertext.
func (db *DB) PendingMessages(
	ctx context.Context,
	recipient uuid.UUID,
	limit int,
) ([]PendingMessage, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT id, envelope FROM messages
		  WHERE recipient_aci = $1 AND expires_at > now()
		  ORDER BY expires_at
		  LIMIT $2`,
		recipient, limit)
	if err != nil {
		return nil, fmt.Errorf("pending messages: %w", err)
	}
	defer rows.Close()

	var out []PendingMessage
	for rows.Next() {
		var m PendingMessage
		if err := rows.Scan(&m.ID, &m.Envelope); err != nil {
			return nil, fmt.Errorf("pending messages: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// AcknowledgeMessages deletes delivered messages and reports how many went.
//
// # The row is gone, not flagged
//
// docs/THREAT_MODEL.md §3.1 is the whole reason this project has a retention
// policy at all: encryption makes a seized database unreadable, deletion makes it
// *empty*, and only the second is not a bet on the cipher holding for as long as
// the data is kept. A `delivered` column would satisfy every functional test and
// retain every message forever.
//
// # Scoped to the caller
//
// `AND recipient_aci = $2` is load-bearing. Without it any authenticated account
// could delete any other's undelivered mail by guessing ids — a silent,
// unattributable message-loss primitive, and the most damaging thing a member of
// a small circle could do to another. Ids are random 128-bit values, so guessing
// is not the realistic path; ids also travel in fetch responses, and a client
// bug, a proxy log, or a compromised device would leak them.
func (db *DB) AcknowledgeMessages(
	ctx context.Context,
	recipient uuid.UUID,
	ids []uuid.UUID,
) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	tag, err := db.pool.Exec(ctx,
		`DELETE FROM messages WHERE recipient_aci = $1 AND id = ANY($2)`,
		recipient, ids)
	if err != nil {
		return 0, fmt.Errorf("acknowledge messages: %w", err)
	}
	return tag.RowsAffected(), nil
}

// CountPendingMessages reports how many messages await an account.
// Test and operational support only.
func (db *DB) CountPendingMessages(ctx context.Context, recipient uuid.UUID) (int, error) {
	var n int
	if err := db.pool.QueryRow(ctx,
		`SELECT count(*) FROM messages WHERE recipient_aci = $1`, recipient).Scan(&n); err != nil {
		return 0, fmt.Errorf("count pending: %w", err)
	}
	return n, nil
}

// MessageExists reports whether a row is still present, regardless of expiry.
//
// Exists so a test can assert a row is *gone* rather than merely invisible — the
// difference between deletion and a soft-delete flag, which is the entire point
// of §3.1 and which a "does it come back from the API" assertion cannot see.
func (db *DB) MessageExists(ctx context.Context, id uuid.UUID) (bool, error) {
	var exists bool
	if err := db.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM messages WHERE id = $1)`, id).Scan(&exists); err != nil {
		return false, fmt.Errorf("message exists: %w", err)
	}
	return exists, nil
}

// DeleteExpiredMessages sweeps undelivered messages past their TTL.
//
// The other half of §3.1. Delete-on-delivery empties the table for anyone who
// comes back; this empties it for anyone who does not — a device that is lost,
// wiped, or simply never opened again would otherwise leave its mail on the relay
// permanently, which is the archive the policy says does not exist.
//
// The consequence is real and must be stated in the UI rather than discovered: a
// device offline past the TTL loses undelivered messages.
func (db *DB) DeleteExpiredMessages(ctx context.Context) (int64, error) {
	tag, err := db.pool.Exec(ctx, `DELETE FROM messages WHERE expires_at <= now()`)
	if err != nil {
		return 0, fmt.Errorf("sweep messages: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ExpireMessageNow forces a message past its TTL. Test support only.
//
// Manipulating expiry from Go rather than sleeping for the real TTL, which is 30
// days. Kept beside the sweep it exercises so the two cannot drift.
func (db *DB) ExpireMessageNow(ctx context.Context, id uuid.UUID) error {
	if _, err := db.pool.Exec(ctx,
		`UPDATE messages SET expires_at = now() - interval '1 second' WHERE id = $1`,
		id); err != nil {
		return fmt.Errorf("expire message: %w", err)
	}
	return nil
}
