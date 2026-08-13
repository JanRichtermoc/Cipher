-- Copyright (C) 2026 Jan Richter
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- 0003 — an Ed25519 account key, so a device can re-authenticate (AUDIT 5.41)
--
-- No transaction control here. store.Migrate opens one and refuses a migration
-- that contains any, because PostgreSQL has no nested transactions and a COMMIT
-- in a file ends the runner's own (AUDIT 5.27).
--
-- ---------------------------------------------------------------------------
-- Why this column exists
--
-- The session token was the *only* credential path: rotation needs the old
-- token and redeeming an invite mints a new account, so an account whose token
-- hash was gone could not authenticate again by any route. Its owner had to
-- redeem a fresh invite, receive a different aci, and re-verify safety numbers
-- with every peer — which made "revoke all sessions" indistinguishable from
-- disbanding the circle. AUDIT 5.41.
--
-- With this, a device proves possession of a key it has held since registration
-- and gets a new session token. Nothing else about identity changes.
--
-- ---------------------------------------------------------------------------
-- Why Ed25519 and not the identity key we already store
--
-- The obvious design is challenge-response against accounts.identity_key, which
-- would add no column at all. It is not buildable here: a libsignal identity key
-- is Curve25519 and its signatures are XEd25519, so verifying one in Go means
-- field arithmetic the standard library does not expose. Hand-rolling it
-- violates the plan's §0.6, and importing edwards25519 or x/crypto would make
-- this the relay's first cryptographic dependency. The same wall P7.S01 hit with
-- the server-issued sender certificate: the relay cannot verify anything
-- libsignal signed.
--
-- Ed25519 is in crypto/ed25519, in the Go standard library, and CryptoKit
-- provides it on the client. No new dependency on either side.
--
-- ---------------------------------------------------------------------------
-- Why it is nullable, and why that is not a gap
--
-- Accounts created before this migration have no such key and cannot have one
-- retroactively — the private half only ever exists on their device. They
-- publish one on their next authenticated request (PUT /v1/auth/key), and until
-- they do, re-authentication for them fails exactly as it did before this
-- existed. A NOT NULL column would have meant either inventing a key the relay
-- holds both halves of, which is the opposite of the point, or refusing service
-- to every existing account.
--
-- It holds a PUBLIC key. A seized database gains a value it could already
-- derive from any signature the account ever produced; no private key material
-- reaches the relay, here or anywhere else.
-- ---------------------------------------------------------------------------

ALTER TABLE accounts
    ADD COLUMN IF NOT EXISTS reauth_key BYTEA;

-- Exactly 32 bytes when present: an Ed25519 public key is 32 bytes, and a
-- column that accepted other lengths would be accepting something that is not
-- one. NULL stays legal — see above.
ALTER TABLE accounts
    DROP CONSTRAINT IF EXISTS accounts_reauth_key_check;

ALTER TABLE accounts
    ADD CONSTRAINT accounts_reauth_key_check
    CHECK (reauth_key IS NULL OR octet_length(reauth_key) = 32);
