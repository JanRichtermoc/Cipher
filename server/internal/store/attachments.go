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

// ErrAttachmentNotFound is returned when a slot is unknown or expired.
//
// One error for both. An expired slot and a slot that never existed are the same
// answer to the only question the caller can act on — the bytes are not
// available — and distinguishing them would confirm that an id the caller holds
// was once real.
var ErrAttachmentNotFound = errors.New("store: attachment not found")

// CreateAttachment records a slot.
//
// There is no owner column and no recipient column: the id **is** the
// capability. It is 122 bits of randomness handed to the recipient inside the
// end-to-end ciphertext, so the server never learns who uploaded a blob or who
// may read it, and therefore never records the edge (docs/BACKEND.md §2.8).
//
// The consequence, stated rather than implied: anyone who obtains the id can
// download the bytes. Those bytes are encrypted with a key that travels in the
// same ciphertext, so possession of the id alone yields nothing readable — the
// capability grants access to a blob, not to its contents.
func (db *DB) CreateAttachment(
	ctx context.Context,
	id uuid.UUID,
	sizeBytes int64,
	ttl time.Duration,
) error {
	if _, err := db.pool.Exec(ctx,
		`INSERT INTO attachments (id, size_bytes, expires_at) VALUES ($1, $2, $3)`,
		id, sizeBytes, time.Now().Add(ttl)); err != nil {
		return fmt.Errorf("create attachment: %w", err)
	}
	return nil
}

// AttachmentSize returns the recorded length of a live slot.
func (db *DB) AttachmentSize(ctx context.Context, id uuid.UUID) (int64, error) {
	var size int64
	err := db.pool.QueryRow(ctx,
		`SELECT size_bytes FROM attachments WHERE id = $1 AND expires_at > now()`,
		id).Scan(&size)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrAttachmentNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("attachment size: %w", err)
	}
	return size, nil
}

// DeleteAttachment removes a slot and reports whether a row went.
//
// Idempotent. Deleting a slot that is already gone is what a retried request
// looks like, and it is also what happens when the sweep gets there first.
func (db *DB) DeleteAttachment(ctx context.Context, id uuid.UUID) (bool, error) {
	tag, err := db.pool.Exec(ctx, `DELETE FROM attachments WHERE id = $1`, id)
	if err != nil {
		return false, fmt.Errorf("delete attachment: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// ExpiredAttachmentIDs returns lapsed slots, so the caller can remove the bytes
// before removing the rows.
//
// Returning ids rather than deleting in one statement, because the file and the
// row live in different systems and the order matters. Deleting the row first
// would orphan the file: nothing would remember it existed, and it would sit on
// disk until someone noticed the directory growing — a retention leak that is
// invisible to every query.
func (db *DB) ExpiredAttachmentIDs(ctx context.Context, limit int) ([]uuid.UUID, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT id FROM attachments WHERE expires_at <= now() LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("expired attachments: %w", err)
	}
	defer rows.Close()

	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("expired attachments: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// AttachmentExists reports whether a row is present regardless of expiry.
// Test support: lets a test assert a row is gone rather than merely invisible.
func (db *DB) AttachmentExists(ctx context.Context, id uuid.UUID) (bool, error) {
	var exists bool
	if err := db.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM attachments WHERE id = $1)`, id).Scan(&exists); err != nil {
		return false, fmt.Errorf("attachment exists: %w", err)
	}
	return exists, nil
}

// ExpireAttachmentNow forces a slot past its TTL. Test support only.
func (db *DB) ExpireAttachmentNow(ctx context.Context, id uuid.UUID) error {
	if _, err := db.pool.Exec(ctx,
		`UPDATE attachments SET expires_at = now() - interval '1 second' WHERE id = $1`,
		id); err != nil {
		return fmt.Errorf("expire attachment: %w", err)
	}
	return nil
}
