-- Copyright (C) 2026 Jan Richter
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- 0002 — narrow push_tokens.token_nonce to AES-GCM's 96-bit nonce (P7.S03)
--
-- No transaction control here. store.Migrate opens one and refuses a migration
-- that contains any, because PostgreSQL has no nested transactions and a COMMIT
-- in a file ends the runner's own (AUDIT 5.27).
--
-- ---------------------------------------------------------------------------
-- Why this exists
--
-- 0001 specified XChaCha20-Poly1305, whose nonce is 24 bytes, and constrained
-- the column to exactly that. That algorithm is not reachable from the Go
-- standard library: `chacha20poly1305` ships inside the toolchain only as the
-- standard library's own vendored copy and cannot be imported by this module.
-- Building it as written would have meant adding golang.org/x/crypto as the
-- relay's first cryptographic dependency — a supply-chain decision, not an
-- implementation detail.
--
-- AES-256-GCM is in crypto/cipher, and its nonce is 96 bits: the size the
-- construction is specified and analysed for. `internal/pushtoken` explains the
-- choice; docs/BACKEND.md §2.9 records it beside the column.
--
-- ---------------------------------------------------------------------------
-- Why it is safe to narrow rather than to widen
--
-- The table has never held a row: nothing in the Go tree wrote to it before this
-- step, so there is no ciphertext to re-encrypt and no 24-byte nonce to migrate.
-- If that ever stops being true, this is the migration to look at first — a
-- CHECK narrowed under existing rows fails loudly at deploy rather than
-- silently, which is the correct direction for a constraint that guards a
-- cryptographic invariant.
-- ---------------------------------------------------------------------------

ALTER TABLE push_tokens
    DROP CONSTRAINT IF EXISTS push_tokens_token_nonce_check;

ALTER TABLE push_tokens
    ADD CONSTRAINT push_tokens_token_nonce_check
    CHECK (octet_length(token_nonce) = 12);
