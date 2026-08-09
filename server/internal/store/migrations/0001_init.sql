-- 0001_init.sql — the schema specified in docs/BACKEND.md §2.
--
-- Copyright (C) 2026 Jan Richter
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Every column here is justified in BACKEND.md §2 against docs/THREAT_MODEL.md §1.1.
-- If you are adding a column, that table is where the justification goes, and the
-- question it must answer is not "is this useful" but "what would a seized database
-- learn from it".
--
-- Two conventions that are load-bearing and easy to undo by habit:
--
--   * There are no soft deletes. No deleted_at, no is_revoked, no delivered flag.
--     A row that has served its purpose is DELETEd. A flag is a record that outlives
--     the thing it describes, which is the failure mode the retention policy exists
--     to prevent.
--   * There is no created_at unless something reads it. Creation timestamps are an
--     activity trace acquired by habit rather than need.
--
-- Length CHECKs below are deliberately loose where the exact serialized size of a
-- libsignal type is not something this file can verify. A constraint that is merely
-- plausible would reject valid clients in production, which is worse than a bound
-- that only catches nonsense. Where a size IS derivable from our own wire format —
-- envelopes — the constraint is exact.

-- No BEGIN/COMMIT here, deliberately. store.Migrate already runs each file in a
-- transaction with its schema_migrations row written inside it, and PostgreSQL
-- has no nested transactions: a BEGIN inside an open one is a warning and a
-- no-op, while the matching COMMIT ends the *runner's* transaction. The
-- bookkeeping INSERT then ran outside any transaction, so a failure between the
-- two left a fully applied schema with no row recording it — and the next boot
-- reapplied the file against objects that already existed. The runner refuses a
-- migration containing transaction control for this reason.

-- ---------------------------------------------------------------------------
-- accounts (BACKEND.md §2.1)
-- ---------------------------------------------------------------------------
CREATE TABLE accounts (
    -- The routing address. Server-generated UUIDv4 at invite redemption, adopted by
    -- the client via CryptoEngine.adoptLocalAddress. Opaque: no link to a person,
    -- phone, or email exists anywhere, by THREAT_MODEL.md §3.4.
    aci             UUID    PRIMARY KEY,

    -- The peer's long-term PUBLIC identity key, required in every dispensed bundle.
    -- Held on the account rather than repeated per prekey row so there is one copy
    -- to serve and rotation has one place to happen.
    identity_key    BYTEA   NOT NULL CHECK (octet_length(identity_key) BETWEEN 32 AND 64),

    -- Required by libsignal's PreKeyBundle; processPreKeyBundle cannot run without it.
    registration_id INTEGER NOT NULL CHECK (registration_id > 0),

    -- The only input to the abandoned-account sweep. DATE, not TIMESTAMPTZ: day
    -- resolution is all the sweep needs, and it reduces the activity trace a seizure
    -- recovers from second-level to day-level at no functional cost.
    last_seen       DATE    NOT NULL DEFAULT CURRENT_DATE
);

-- ---------------------------------------------------------------------------
-- invites (BACKEND.md §2.2)
--
-- Two columns, both needed. created_by is absent on purpose: the invite graph is
-- the social graph of a closed circle and is the single most valuable thing a
-- seizure could recover. Invite-creation rate limiting is a Redis counter that
-- expires; a column would not.
--
-- A redeemed invite is DELETEd, never marked used. A replayed code then hits the
-- unknown-code path and is rejected identically, and no record survives linking an
-- account to the invite that created it.
-- ---------------------------------------------------------------------------
CREATE TABLE invites (
    -- SHA-256 of the code. Plain SHA-256 is correct ONLY because the code is
    -- server-generated with 128 bits of entropy, making preimage search infeasible.
    -- If codes ever become human-chosen or shortened, this must become a memory-hard
    -- KDF. That dependency is why the entropy assumption is written down here.
    code_hash  BYTEA       PRIMARY KEY CHECK (octet_length(code_hash) = 32),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX invites_expires_at_idx ON invites (expires_at);

-- ---------------------------------------------------------------------------
-- session_tokens (BACKEND.md §2.3)
--
-- Opaque random tokens, not JWTs. A JWT carries its claims, so revocation needs a
-- denylist that must be consulted on every request and grows forever. An opaque
-- token is a lookup by construction: revocation is DELETE and it is immediate.
-- Hence no revoked column, for the same reason invites have no used column.
-- ---------------------------------------------------------------------------
CREATE TABLE session_tokens (
    -- SHA-256 of a 256-bit random token. The token itself is NEVER stored: a
    -- database dump must not yield credentials that authenticate as a user.
    token_hash BYTEA       PRIMARY KEY CHECK (octet_length(token_hash) = 32),

    -- The token has to authenticate someone. The cascade is how account deletion
    -- actually revokes access rather than orphaning it.
    aci        UUID        NOT NULL REFERENCES accounts (aci) ON DELETE CASCADE,

    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX session_tokens_aci_idx        ON session_tokens (aci);
CREATE INDEX session_tokens_expires_at_idx ON session_tokens (expires_at);

-- ---------------------------------------------------------------------------
-- one_time_prekeys (BACKEND.md §2.4)
--
-- A dispensed row is deleted in the SAME TRANSACTION that serves it. That is what
-- "one-time" means, and doing it transactionally is what stops a concurrent fetch
-- from handing the same prekey to two peers.
-- ---------------------------------------------------------------------------
CREATE TABLE one_time_prekeys (
    aci        UUID    NOT NULL REFERENCES accounts (aci) ON DELETE CASCADE,
    -- The client's own identifier for the key, echoed back in the bundle so the
    -- client can find the private half.
    key_id     INTEGER NOT NULL CHECK (key_id >= 0),
    public_key BYTEA   NOT NULL CHECK (octet_length(public_key) BETWEEN 32 AND 64),
    PRIMARY KEY (aci, key_id)
);

-- ---------------------------------------------------------------------------
-- signed_prekeys (BACKEND.md §2.5)
--
-- aci is the PRIMARY KEY rather than part of a compound key, and that IS the
-- "exactly one live signed prekey per account" constraint — enforced by the schema
-- rather than by application code remembering to delete the old row.
--
-- The relay does NOT verify the signature. processPreKeyBundle does, on the client,
-- on every use. Verifying here would be a second unreviewed copy of a signature
-- check, and a client that trusted the server's verdict would have no protection
-- from a hostile relay at all.
-- ---------------------------------------------------------------------------
CREATE TABLE signed_prekeys (
    aci        UUID    PRIMARY KEY REFERENCES accounts (aci) ON DELETE CASCADE,
    key_id     INTEGER NOT NULL CHECK (key_id >= 0),
    public_key BYTEA   NOT NULL CHECK (octet_length(public_key) BETWEEN 32 AND 64),
    signature  BYTEA   NOT NULL CHECK (octet_length(signature) BETWEEN 32 AND 128)
);

-- ---------------------------------------------------------------------------
-- kyber_prekeys (BACKEND.md §2.6)
--
-- PQXDH is mandatory (locked decision: Kyber is never optional).
--
-- The dispense path prefers a one-time row and deletes it, falling back to the
-- last_resort row which it does not delete. Without that column the server cannot
-- tell which rows it may delete and would either exhaust the pool permanently or
-- never rotate.
--
-- The honest cost of the fallback: with the one-time pool empty, PQXDH runs against
-- a reused key, so the KEM contribution is shared with every other session that also
-- fell back. Classical X25519 forward secrecy is unaffected. This is the pressure
-- that makes prekey-fetch rate limiting a security control (AUDIT 3.1).
-- ---------------------------------------------------------------------------
CREATE TABLE kyber_prekeys (
    aci         UUID    NOT NULL REFERENCES accounts (aci) ON DELETE CASCADE,
    key_id      INTEGER NOT NULL CHECK (key_id >= 0),
    -- Loose upper bound: ML-KEM public keys are far larger than Curve25519 ones and
    -- the exact serialized size including libsignal's type prefix is not something
    -- this file can assert. The bound catches nonsense, not off-by-one.
    public_key  BYTEA   NOT NULL CHECK (octet_length(public_key) BETWEEN 32 AND 4096),
    signature   BYTEA   NOT NULL CHECK (octet_length(signature) BETWEEN 32 AND 128),
    last_resort BOOLEAN NOT NULL,
    PRIMARY KEY (aci, key_id)
);

-- At most one last-resort key per account. A partial unique index rather than an
-- application check, so a concurrent upload cannot create a second one.
CREATE UNIQUE INDEX kyber_prekeys_one_last_resort_idx
    ON kyber_prekeys (aci) WHERE last_resort;

-- ---------------------------------------------------------------------------
-- messages (BACKEND.md §2.7) — the table a seizure is actually after
--
-- Absent on purpose: sender_aci (deriving it requires parsing the envelope, which
-- no delivery decision needs), delivered (delivered means deleted), read,
-- retry_count, and any archive table.
--
-- Envelope wire format v1 has seventeen bytes at offset 2 where the sender used to
-- be. The relay does not read, index, or store them, and since P7.S01 (AUDIT 3.4)
-- every frame the shipped client produces is `.sealed`: those bytes are zero and the
-- address is inside the ciphertext, so a seized database no longer reveals who sent
-- what. Ciphertext-only has always meant no plaintext CONTENT, ever; it now also
-- means no sender at rest.
--
-- Amended 2026-08-09. This said the field was CLEARTEXT and that sealed sender would
-- remove it — written before P7.S01 and left behind by it, so the file a reviewer
-- reads to learn what this table can hold overstated the exposure.
--
-- The residual is a statement about clients, not about this schema: the relay
-- accepts type 1, 2 and 4 and parses none of them, so a peer running a pre-P7.S01
-- build, or a modified client, can still enqueue an addressed envelope with those
-- bytes populated. Nothing here can tell the difference. A live relay is separately
-- told who is sending by the bearer token on POST /v1/messages, which is AUDIT 3.9
-- and is not closed by anything in this file.
-- ---------------------------------------------------------------------------
CREATE TABLE messages (
    -- The acknowledgement handle. Random UUIDv4, NOT a sequence: a monotonic id
    -- would leak the relay's total message volume and cross-account ordering to
    -- anyone who observed a single value.
    id            UUID        PRIMARY KEY,

    -- Delivery is impossible without it. This is the irreducible metadata cost of a
    -- store-and-forward relay. Sealed sender does not remove this column; it removes
    -- the sender, not the recipient.
    recipient_aci UUID        NOT NULL REFERENCES accounts (aci) ON DELETE CASCADE,

    -- Opaque Envelope bytes. The server checks length only and never parses in.
    -- The bound is exact and derived from Envelope.swift: headerSize 31 plus a
    -- ciphertext of 1..65536 bytes.
    envelope      BYTEA       NOT NULL CHECK (octet_length(envelope) BETWEEN 32 AND 65567),

    -- Drives the TTL sweep. The only lifetime field; there is deliberately no
    -- created_at.
    expires_at    TIMESTAMPTZ NOT NULL
);

-- Delivery reads by recipient in arrival order; the sweep reads by expiry.
CREATE INDEX messages_recipient_idx  ON messages (recipient_aci, expires_at);
CREATE INDEX messages_expires_at_idx ON messages (expires_at);

-- ---------------------------------------------------------------------------
-- attachments (BACKEND.md §2.8)
--
-- No owner_aci. The id IS the capability — 122 bits of randomness delivered to the
-- recipient inside the end-to-end ciphertext — so the server never needs to know who
-- uploaded a blob or who may read it, and therefore never records the edge. Upload
-- quota is a Redis counter against the session token, which expires.
--
-- Blob bytes live on the filesystem keyed by id, not in Postgres: shredding a file
-- is one unlink, whereas a deleted BYTEA persists in table bloat and WAL until
-- vacuum and WAL rotation catch up.
-- ---------------------------------------------------------------------------
CREATE TABLE attachments (
    id         UUID        PRIMARY KEY,
    size_bytes INTEGER     NOT NULL CHECK (size_bytes > 0),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX attachments_expires_at_idx ON attachments (expires_at);

-- ---------------------------------------------------------------------------
-- push_tokens (BACKEND.md §2.9)
--
-- THREAT_MODEL.md §3.3 originally required this to be stored hashed. That cannot be
-- built: the token is replayed verbatim to APNs, so a one-way function is unusable
-- (AUDIT 6.10). Encrypted at rest under a key held ONLY in the service environment
-- and never in this database, so a dump, a backup, or a stolen replica is
-- insufficient alone. It does NOT defeat host seizure, where the environment is
-- seized with the disk — rotation and the cascade below are what work there.
-- ---------------------------------------------------------------------------
CREATE TABLE push_tokens (
    aci              UUID  PRIMARY KEY REFERENCES accounts (aci) ON DELETE CASCADE,
    token_ciphertext BYTEA NOT NULL,
    -- Per-row XChaCha20-Poly1305 nonce. Stored because it must be; not secret.
    token_nonce      BYTEA NOT NULL CHECK (octet_length(token_nonce) = 24),
    rotated_at       DATE  NOT NULL DEFAULT CURRENT_DATE
);
