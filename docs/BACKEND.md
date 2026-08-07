# Cipher relay — backend design

**Implementation:** The relay described here exists under [`server/`](../server/). Its code and
migrations own mechanics, while [`server/README.md`](../server/README.md) owns the executable
endpoint and local-operation reference. The implementation plan `STATUS` owns roadmap state;
[`RUNBOOK-VPS.md`](RUNBOOK-VPS.md) and live read-only checks own deployment state.

**Read first:** [`THREAT_MODEL.md`](THREAT_MODEL.md) in full — this document is an application of it.
[`Envelope.swift`](../CipherCrypto/Sources/Wire/Envelope.swift) defines the only payload the relay
carries; [`PeerKeyBundle.swift`](../CipherCrypto/Sources/Engine/PeerKeyBundle.swift) defines the
shape of the prekey directory.

---

## 0. The one sentence this design exists to satisfy

> The relay is assumed hostile or seizable (`THREAT_MODEL.md` §0, §1.1). Its operator is not
> trusted, including when its operator is us.

Everything below follows from that. Two consequences shape every decision on this page:

1. **Encryption is not the primary server-side control — deletion is.** A seized database that is
   encrypted is a bet on the cipher and on key hygiene across the whole retained lifetime of the
   data. A seized database that is *empty* is not a bet. Where a choice exists between storing
   something safely and not storing it, this design does not store it.
2. **A column is a permanent record; an inference is not.** Timing correlation lets an observer
   *guess* who talks to whom. A `sender` column *proves* it, to anyone holding a disk image, years
   later, with no observation required. This is why several fields that would be convenient are
   absent below, and why their absence is written down rather than left to be re-litigated.

The relay is not keyless. It stores public identity/prekey material because peers need it to start
sessions. Private E2E identity, prekey, session, and ratchet keys remain on-device. The host's TLS
private keys and service secrets are a third, operational category: necessary on the server, but
not capable of decrypting E2E message content.

---

## 1. Service modules

Go, standard library HTTP with a thin router, one binary. Six modules, each with a single reason to
exist. No framework, because a framework is a dependency surface and standing prohibition 1 applies
to the server as much as the client.

| Module | Responsibility | Never does |
|---|---|---|
| `health` | Liveness and readiness. No auth, no data. | Report version, build, or user counts |
| `invite` | Issue and redeem single-use, expiring invite codes. Creates an account on redemption. | Record who invited whom (§3.2 below) |
| `auth` | Issue, rotate, and revoke opaque session tokens. Authenticates every other route. | Hold claims in the token itself |
| `directory` | Prekey bundle upload and dispense. The one endpoint whose rate limit is load-bearing. | Serve a bundle to an unauthenticated caller |
| `relay` | Store-and-forward `Envelope` bytes. Delete on acknowledged delivery. | Parse into the ciphertext |

The relay module, built in P4.S07/S08, checks exactly two things about an envelope: that it is
32–65567 bytes, and that the recipient is a well-formed UUID. The wire version, payload type,
`sender` field and timestamp are all in those bytes, all readable without any key, and all
deliberately unread. It relays an unknown wire version, the reserved plaintext type, and a
sender-key message the client refuses outright, unchanged and without comment — a test pins
that, because a server that understands the format acquires opinions about it, every opinion
is a coupling that must be revised in lockstep with the client, and each is a place where a
hostile operator could make a decision about someone's mail.

It does **not** check that the envelope's `sender` matches the authenticated account. That
looks like a free integrity win and is not: the field is a routing hint the client is
documented never to trust, attribution comes from which session decrypted the ciphertext, and
enforcing it would mean the server both parses the format and appears to vouch for a value
nothing should rely on.

**Reading does not delete.** Delivery is acknowledged separately, so a response lost in
transit cannot destroy a message the client never stored. Acknowledgement is scoped to the
caller's own queue — without that, any account could delete any other's undelivered mail given
an id, which is a silent, unattributable message-loss primitive and the most damaging thing one
member of a small circle could do to another. Negative-tested: unscoped, one account
acknowledged another's message.

**A send to an account that does not exist is accepted and dropped**, with a response identical
to a real delivery. Reporting it would be an enumeration oracle, and a cleaner one than the
prekey directory, which already answers identically for unknown, never-published and drained
accounts. It costs a real client nothing: an `aci` is only obtainable by fetching a bundle, so
a legitimate sender never addresses a stranger.
| `blobs` | Attachment slots: opaque bytes with a size cap and a TTL. | Inspect, transcode, or scan content |

Built in P4.S09. The server records a slot's **length and expiry, and nothing else** — no content
type, no filename, no extension, no magic-byte sniffing, no scanning of any kind. There is nothing
to inspect: the bytes are encrypted before they arrive. A response is always
`application/octet-stream` with `Content-Disposition: attachment`, because a content type echoed
from upload is an attacker-chosen instruction to whatever eventually renders the bytes.

The only name on disk is the capability itself, and the on-disk path is built from a **parsed**
`uuid.UUID` rather than from caller text — which is what makes path traversal structurally
impossible here rather than a matter of sanitising, since a `uuid.UUID` cannot hold `../`.

Uploads are streamed to a temporary file and renamed into place, with an `fsync` first. A partial
blob must never be visible: writing in place would mean a client that disconnects mid-upload leaves
a truncated file at the id the database is about to point at, and the recipient would report a
corrupt attachment for what was a network error. Renaming without the `fsync` allows the opposite —
a correctly-named empty file after a power loss, which is worse, because nothing will retry it.

**Order matters in both directions, and it is the same rule at both ends: the file is never the
thing left behind.** On upload the file is written before the row, and removed if the row fails: a
row without a file is a download that 500s and is recoverable, whereas a file without a row is a
blob nothing remembers, which no sweep can find and no query can see. On deletion the bytes go
first and the row second, and a failed unlink **keeps the row and refuses**, so the sweep retries
at the TTL rather than orphaning the bytes permanently.

The explicit `DELETE /v1/blobs/{id}` used to do the opposite — row first, then a best-effort
unlink whose failure was only logged — which left exactly the undiscoverable ciphertext the rule
above exists to prevent, on a host §1 assumes is seizable (AUDIT 5.27). It now matches the sweep.
Negative-tested in both directions: skipping the file deletion leaves `row=false disk=true`, and
making the unlink fail under the old order removed the row anyway.

Durability is the other half. The upload's rename is followed by an `fsync` of the **directory**,
not only of the file: the two are separate facts, and without the second a crash can leave the
bytes on disk with no name pointing at them while the row already exists — a slot the relay
believes it has and can never serve, which nothing retries because the upload succeeded.

There is deliberately **no seventh module**. See §8.

---

## 2. Data model

PostgreSQL. **Nine tables, thirty-two columns**, and every one is justified below against
`THREAT_MODEL.md` §1.1: *if a seized database revealed this, what would the adversary learn, and is
that price worth paying?*

That count is checked, not asserted. This sentence originally said "eight tables, thirty-one
columns" — written by counting the sections below rather than the schema — and the error was found
by querying a live database in P4.S02. `TestTableCountMatchesTheDocumentedTotal` and
`TestEveryTableIsDocumented` now fail in the fast gate if a table is added without a justification
here, or removed without this paragraph changing. A stated count that has drifted is worse than no
count, because it reads as verified.

Conventions used throughout:

- **No soft deletes.** No `deleted_at`, no `is_revoked`, no `delivered` flag. A row that has served
  its purpose is removed with `DELETE`. A flag is a record that outlives the thing it describes,
  which is the exact failure mode §3.1 exists to prevent.
- **No `created_at` unless something reads it.** Creation timestamps are an activity trace acquired
  by habit rather than by need. Where a lifetime is required, `expires_at` carries it and nothing
  else does.
- **Date, not timestamp, where precision is not needed.** `DATE` instead of `TIMESTAMPTZ` reduces an
  activity trace from second-resolution to day-resolution at no functional cost.
- **Identifiers are random, never sequential.** A `BIGSERIAL` message id leaks the relay's total
  message volume to anyone who observes a single value, and leaks ordering between accounts.

### 2.1 `accounts`

One row per installation. Created only by redeeming an invite.

| Column | Type | Why it exists | What a seizure learns |
|---|---|---|---|
| `aci` | `UUID PRIMARY KEY` | The routing address. `ServiceIdentifier` on the client; messages must be addressed to *something*. Server-generated (UUIDv4) at redemption and adopted by the client via `CryptoEngine.adoptLocalAddress`. | An opaque identifier with no link to a person, phone, email, or device. This is the whole point of §3.4. |
| `identity_key` | `BYTEA NOT NULL` | The peer's long-term **public** identity key, required in every dispensed bundle. Stored on the account rather than repeated per prekey row, so there is exactly one copy to serve and rotation has one place to happen. | A public key. Public by construction; it is what safety numbers are computed from. |
| `registration_id` | `INTEGER NOT NULL` | Required by libsignal's `PreKeyBundle`. Without it `processPreKeyBundle` cannot run. Bounded by the handler to libsignal's own 14-bit range, 1 through `0x3FFF` (AUDIT 5.27): above it the value is unusable in a bundle, and above `INTEGER` it turned a malformed request into a 500. | A small integer, chosen randomly by the client. Correlatable across a reinstall only if it does not change — and it does. |
| `last_seen` | `DATE NOT NULL` | The only input to the abandoned-account sweep (§4). Day resolution, not second. | That an account was active on a given day. This is a real cost, accepted for a real need, and reduced as far as it can be without losing the sweep. |

**Absent on purpose:** `created_at` (nothing reads it; `last_seen` covers the sweep), `display_name`,
`username`, `about` (profile data is client-side only — the server has no concept of a profile),
`device_id` and a `devices` table (single-device is a locked decision; adding it is a `wireVersion`
break in `Envelope`, recorded there, not smuggled into the schema early).

### 2.2 `invites`

| Column | Type | Why it exists | What a seizure learns |
|---|---|---|---|
| `code_hash` | `BYTEA PRIMARY KEY` | SHA-256 of the code. Redemption hashes the presented code and looks it up, so the relay can validate a code it cannot reproduce. | Nothing usable. See the hash note below. |
| `expires_at` | `TIMESTAMPTZ NOT NULL` | Enforces expiry (P4.S03) and drives the sweep. | That an unredeemed invite exists and when it lapses. |

Two columns, and both are needed. **`created_by` is deliberately absent** — storing the issuer would
put the invite graph, which is the social graph of a closed circle, permanently on disk. It is the
single most valuable thing a seizure of a five-person messenger could recover, and it is not needed:
rate-limiting invite creation per account is done with a Redis counter (§3) that expires, not with a
column that does not. The cost is that an inviter's subtree cannot be revoked in bulk. At this scale
that is a manual operation on a handful of accounts, which is the correct trade.

**A redeemed invite row is `DELETE`d, not marked used.** This is better than a `used` flag on every
axis: a replayed code then hits an unknown-code path and is rejected identically, single-use is
enforced by the row's absence rather than by remembering to check a flag, and no record survives
linking an account to the invite that created it.

**On the hash:** SHA-256 is correct here *because the code is server-generated with 128 bits of
entropy* — brute-forcing the preimage is infeasible, so a password KDF would buy nothing for real
cost. That argument is entirely dependent on the entropy assumption. **If invite codes ever become
human-chosen or shortened, this must change to a memory-hard KDF**, and this paragraph is the reason
that is not a silent decision.

### 2.3 `session_tokens`

| Column | Type | Why it exists | What a seizure learns |
|---|---|---|---|
| `token_hash` | `BYTEA PRIMARY KEY` | SHA-256 of a 256-bit random token. **The token itself is never stored** (P4.S04): a database dump must not yield credentials that authenticate as a user. Same entropy argument as §2.2. | Nothing usable. |
| `aci` | `UUID NOT NULL REFERENCES accounts(aci) ON DELETE CASCADE` | The token has to authenticate *someone*. The cascade is how account deletion actually revokes access rather than orphaning it. | Which account a live session belongs to — bounded by expiry. |
| `expires_at` | `TIMESTAMPTZ NOT NULL` | Expiry and rotation. | When a session lapses. |

**Opaque random tokens, not JWTs.** A JWT carries its claims in the token, so revocation requires a
denylist — which is a second store that must be consulted on every request and that grows forever.
An opaque token is a lookup by construction: revocation is `DELETE`, and it is immediate. There is
no `revoked` column for the same reason there is no `used` column on invites.

### 2.4 `one_time_prekeys`

| Column | Type | Why it exists | What a seizure learns |
|---|---|---|---|
| `aci` | `UUID NOT NULL REFERENCES accounts(aci) ON DELETE CASCADE` | Whose pool this is. Part of the primary key. | That an account has published prekeys — which is implied by having an account. |
| `key_id` | `INTEGER NOT NULL` | The client's own identifier for the key, echoed back in the bundle so the client can find the private half. Part of the primary key. | A counter local to one account. |
| `public_key` | `BYTEA NOT NULL` | The one-time prekey. Public. | A public key that has, by the time it is seized, either been dispensed and deleted or never used. |

`PRIMARY KEY (aci, key_id)`. **A dispensed row is deleted in the same transaction that serves it** —
that is what "one-time" means, and doing it transactionally is what stops a concurrent fetch from
handing the same prekey to two peers.

### 2.5 `signed_prekeys`

| Column | Type | Why it exists | What a seizure learns |
|---|---|---|---|
| `aci` | `UUID PRIMARY KEY REFERENCES accounts(aci) ON DELETE CASCADE` | One live signed prekey per account. `PRIMARY KEY` rather than part of a compound key **is** the "exactly one" constraint — enforced by the schema, not by application code remembering to delete the old one. | Nothing beyond account existence. |
| `key_id` | `INTEGER NOT NULL` | Echoed in the bundle; the client resolves the private half by it. | A counter. |
| `public_key` | `BYTEA NOT NULL` | The signed prekey. Public. | A public key. |
| `signature` | `BYTEA NOT NULL` | Signed by the identity key. The relay **does not verify it** — `processPreKeyBundle` does, on the client, on every use. Verifying here would be a second, unreviewed copy of a signature check, and a client that trusted the server's verdict would have no protection from a hostile relay at all. | A signature over a public key. |

Rotation replaces the row atomically (`INSERT … ON CONFLICT (aci) DO UPDATE`). No previous-key grace
window is kept. **Consequence, stated rather than discovered later:** a bundle fetched in the instant
before a rotation can fail session setup once, and the client retries with the new bundle. That is a
retry, not data loss, and it is cheaper than a table that retains superseded keys.

### 2.6 `kyber_prekeys`

PQXDH (locked decision — Kyber is mandatory, never optional).

| Column | Type | Why it exists | What a seizure learns |
|---|---|---|---|
| `aci` | `UUID NOT NULL REFERENCES accounts(aci) ON DELETE CASCADE` | Whose pool. Part of the primary key. | Nothing beyond account existence. |
| `key_id` | `INTEGER NOT NULL` | Echoed in the bundle. Part of the primary key. | A counter. |
| `public_key` | `BYTEA NOT NULL` | The Kyber prekey. Public. | A post-quantum public key. |
| `signature` | `BYTEA NOT NULL` | Signed by the identity key; verified client-side, as in §2.5. | A signature. |
| `last_resort` | `BOOLEAN NOT NULL` | Distinguishes the reusable last-resort key from one-time Kyber prekeys. The dispense path prefers a one-time row and deletes it; it falls back to the last-resort row and does not. Without this column the server cannot tell which rows it may delete, and would either exhaust the pool permanently or never rotate. | Which key is the fallback. Not sensitive; it is inferable from usage anyway. |

`PRIMARY KEY (aci, key_id)`, with a partial unique index enforcing **at most one** `last_resort` row
per account.

**The honest cost of the fallback:** when the one-time pool is empty, PQXDH runs against a reused
last-resort key, so the KEM contribution to that session's secret is shared with every other session
that also fell back. Classical X25519 forward secrecy is unaffected. This is precisely the pressure
that makes prekey-fetch rate limiting (§5, AUDIT 3.1) a security control rather than a capacity
control — an attacker who can drain the one-time pool on demand can force every new session onto the
reused key.

### 2.7 `messages`

The inbox. This is the table a seizure is actually after.

| Column | Type | Why it exists | What a seizure learns |
|---|---|---|---|
| `id` | `UUID PRIMARY KEY` | The acknowledgement handle: the client acks by id and the row is deleted. Random UUIDv4, **not** a sequence — a monotonic id would leak the relay's total message volume and cross-account ordering to anyone who saw one value. | Nothing. |
| `recipient_aci` | `UUID NOT NULL REFERENCES accounts(aci) ON DELETE CASCADE` | Delivery is impossible without it. This is the irreducible metadata cost of a store-and-forward relay. | Who has mail waiting — for exactly as long as it waits. Sealed sender (§3.2 of the threat model, P7) does **not** remove this column; it removes the sender, not the recipient. |
| `envelope` | `BYTEA NOT NULL` | The opaque `Envelope` bytes. The server checks length only. | See the warning below. |
| `expires_at` | `TIMESTAMPTZ NOT NULL` | Drives the TTL sweep (§4). The only lifetime field; there is no `created_at`. | When an undelivered message lapses. |

**Absent on purpose:** `sender_aci` (deriving it would require parsing the envelope, which §1 forbids
and which no delivery decision needs), `delivered` (delivered means deleted), `read`, `retry_count`,
and any `archive` table.

> **The limit of the ciphertext-only claim, stated plainly.**
> `Envelope` wire format v1 carries `sender` **in cleartext at offset 2**. The relay does not read,
> index, or store it separately — but it is inside `envelope`, so a seized database *does* reveal
> sender→recipient pairs **for messages that were in flight at the moment of seizure**.
>
> "Ciphertext-only" means no plaintext *content*, ever, in any column. It does not yet mean no
> sender. Two controls bound this and neither is a substitute for the other: delete-on-delivery (§4)
> shrinks the exposed set to whatever is undelivered right now, and sealed sender (P7) removes the
> field from the wire entirely. Until P7 lands, this is the largest metadata residual in the design
> and it is recorded here rather than glossed.

### 2.8 `attachments`

| Column | Type | Why it exists | What a seizure learns |
|---|---|---|---|
| `id` | `UUID PRIMARY KEY` | The slot identifier, and **the capability**: 122 bits of randomness, delivered to the recipient inside the end-to-end ciphertext. Possession of the id is authorisation to download. | Nothing. |
| `size_bytes` | `INTEGER NOT NULL` | Enforces the cap at commit time and lets the sweep account for freed storage. | The size of an encrypted blob. Padding is P7 work (§3.5). |
| `expires_at` | `TIMESTAMPTZ NOT NULL` | TTL sweep. Attachments expire whether or not they are fetched. | When a blob lapses. |

**No `owner_aci`.** Because the id is the capability, the server never needs to know who uploaded a
blob or who is entitled to read it — and therefore never records the edge. Upload quota is enforced
by a Redis counter against the session token (§3), which expires; the alternative, an owner column,
would not. Blob bytes live on the filesystem keyed by `id`, not in Postgres: shredding a file is one
`unlink`, whereas a deleted `BYTEA` persists in table bloat and WAL until vacuum and WAL rotation
catch up.

### 2.9 `push_tokens`

| Column | Type | Why it exists | What a seizure learns |
|---|---|---|---|
| `aci` | `UUID PRIMARY KEY REFERENCES accounts(aci) ON DELETE CASCADE` | The token has to map to an account to be useful, and the cascade is what makes §3.3's "delete it with the account" actually happen. | That an account has push enabled. |
| `token_ciphertext` | `BYTEA NOT NULL` | The APNs device token, encrypted with XChaCha20-Poly1305 under a key held **only in the service's environment, never in Postgres**. | Nothing from a database dump alone. From a full host compromise, the token. |
| `token_nonce` | `BYTEA NOT NULL` | Per-row nonce for the above. Stored because it must be, and it is not secret. | Nothing. |
| `rotated_at` | `DATE NOT NULL` | Drives the rotation policy in §3.3 of the threat model. Day resolution. | The day a token was last rotated. |

> **Why encryption rather than hashing.** The token must be replayed verbatim to APNs, so a one-way
> function cannot be used. Calling the stored value “hashed” would promise a stronger guarantee than
> anything achievable here.
>
> The strongest achievable property is encryption at rest under a key that is not in the database, so
> that a Postgres dump, a backup, or a stolen replica is insufficient on its own. **It does not
> defeat §1.1 host seizure**, where the process environment is seized along with the disk. The
> controls that do the real work there are the ones §3.3 already names and this schema implements:
> rotate, and delete with the account. `THREAT_MODEL.md` §3.3 and [`AUDIT.md`](AUDIT.md) 6.10 record
> the correction and its limit.

---

## 3. Redis — ephemeral only

Redis holds **nothing that must survive a restart**, and losing all of it costs at most some
in-flight rate-limit state.

| Key space | Contents | TTL |
|---|---|---|
| `rl:*` | Rate-limit counters (§5) | Per limit, seconds to minutes |
| `presence:*` | Which accounts hold a live delivery connection, for online fan-out | Connection lifetime |
| `quota:*` | Per-token attachment upload accounting | 24 h |

Hard rules, because Redis defaults are wrong for this:

- **Persistence disabled** — no RDB snapshots, no AOF. On by default in most images, and it would
  quietly make Redis a second on-disk retention channel holding exactly the routing metadata this
  design works to keep off disk. This is the single most important line in this section.
- **Every key has a TTL.** A key without one is a leak by definition.
- **No messages, no envelopes, no keys, no tokens** — only hashes of tokens where a counter must be
  keyed by session.
- **Bound to the Compose network only**, never published to the host (P4.S02 explicitly forbids it),
  and `requirepass` set even so.
- **`maxmemory` set, and the policy is `noeviction`** (AUDIT 5.28). The first sentence of this
  section — losing all of it costs at most some in-flight rate-limit state — is true of a *planned*
  restart and understates an unplanned one: every limit resets, including the invite-redemption
  brute-force ceiling and the prekey-drain limit AUDIT 3.1 depends on, which is why AUDIT 5.24 made
  the subject pepper configurable. A container memory limit with no Redis-side ceiling makes the OOM
  killer the thing that decides when that happens, and it is reachable by traffic rather than by a
  deploy. With `maxmemory` below the container limit, a full Redis refuses the write instead, and
  every limiter call site already fails closed on an error. `noeviction` is stated explicitly rather
  than left to the default because `allkeys-lru` would discard rate-limit buckets under pressure —
  the same reset, arriving quietly and looking like healthy operation.

---

## 4. Retention policy (`THREAT_MODEL.md` §3.1)

The highest-value control on the server, and nearly free at schema-design time.

| Data | Deleted when |
|---|---|
| Message | The instant delivery is **acknowledged** — same transaction, `DELETE`, no flag |
| Undelivered message | TTL sweep at **30 days** |
| One-time prekey | Dispensed (same transaction) |
| One-time Kyber prekey | Dispensed (same transaction) |
| Invite | Redeemed, or expiry sweep |
| Session token | Expiry sweep, sign-out, or account deletion (cascade) |
| Attachment blob + row | Fetched-and-acked, or TTL sweep at **7 days** |
| Account and everything cascading from it | Explicit deletion, or abandonment sweep at **180 days** of no `last_seen` |
| Request logs | 24 h (§7) |

Rules that make this real rather than aspirational:

- **Acknowledged means gone.** P4.S08's test asserts the row is absent, not that a flag flipped.
  Negative-tested by replacing the `DELETE` with a hide-it-by-expiring update: the test failed
  with *"the row survived acknowledgement — it was flagged, not deleted"*, which is the whole
  distinction and is invisible to any assertion made through the API.
- **The sweep runs on a timer, not only on demand.** Every read path already filters on
  `expires_at > now()`, so a lapsed row is invisible — and under §1.1 the adversary reads the
  disk, where invisible and absent are different things. `internal/sweep` runs hourly, sweeps
  once immediately on start rather than waiting out the first interval (a relay returning from
  an outage is holding exactly the rows it should least like to keep), and never fails the
  process: its work is always still there next tick.
  A test that accepts a flag would pass against a design that retains everything forever.
- **The abandonment row above is a control, not an aspiration** (AUDIT 5.28). It read that way for
  the whole of P4 and P5: `accounts.last_seen` was written on every authenticated request and no
  code ever read it, so the 180 days were a number in this table. `store.DeleteAbandonedAccounts`
  is now the fourth task in the hourly pass, comparing against PostgreSQL's own `CURRENT_DATE` and
  bounded per pass because one account delete cascades across six tables. Accounts go **last** in
  the pass for that reason — the three cheap sweeps must not be starved by a backlog.
  Attachments are the one thing that does not cascade, because they have no owner column by design
  (§2.8); their seven-day TTL is far inside 180, so there is nothing left to reach.
- **A refresh that stops working is the same finding in reverse.** The threshold only protects
  people if something moves `last_seen` forward, and `LookupSession` used to discard a failed
  refresh in silence. It now returns `store.ErrLastSeenNotRefreshed` alongside the valid account —
  the request is still served, because failing it would turn bookkeeping into an outage — and the
  auth middleware warns, throttled to once a minute so the warning stays a fault signal rather than
  becoming the per-request record §7 forbids.
- **No archive table, no `messages_history`, no "just in case" dump.** If it would be useful to us
  after delivery, it is useful to whoever seizes the host.
- **Backups inherit this.** A nightly `pg_dump` retained for a month reintroduces every deleted
  message with a delay. Backups cover schema and account rows only — losing undelivered messages in
  a restore is the correct outcome, not a gap to fix.
- **Except the provider's, which we do not control.** OVH includes a daily whole-disk snapshot on
  VPS and it **cannot be disabled on this product** — confirmed on the staging box, 2026-07-29. It
  images the Postgres volume and the blob directory, so for up to 24 hours a snapshot holds rows
  and files the relay has already deleted. This is the one place the rule above is not true, and
  it is recorded as a residual rather than written around: `AUDIT.md` 4.8. Everything in it is
  message and attachment ciphertext, public identity/prekey material, account and routing metadata,
  server configuration/secrets, and TLS private keys. It does not contain plaintext message content
  or private E2E keys. The same provider already has the live host and process, so this widens the
  retention window rather than the adversary set; the operational secrets are still named because
  describing the image as ciphertext-only would hide what a whole-host snapshot actually is.
- **The user-visible consequence is surfaced honestly**: a device offline past 30 days loses
  undelivered messages. That is a UI string subject to the same honesty rule as every other, and it
  must say so plainly rather than presenting silent loss as delivery.

---

## 5. Rate limits

Token-bucket in Redis. Keyed by session token hash where authenticated, by source IP where not
(§7 governs how long that IP may be kept — the counter key is a hash, and it expires).

| Endpoint | Limit | Why this one matters |
|---|---|---|
| `POST /v1/invite/redeem` | 5 / hour / IP, then exponential backoff | Brute-forcing a 128-bit code is infeasible, but an unthrottled endpoint is still a free oracle and an amplifier |
| `POST /v1/invite` | 3 / day / account | Bounds circle growth. Replaces the `created_by` column the design refuses to store |
| **`GET /v1/keys/{aci}`** | **10 / hour / account, 30 / day / account** | **Load-bearing. See below.** |
| `PUT /v1/keys` | 6 / day / account | Prekey churn has no legitimate reason to be frequent |
| `POST /v1/messages` | 60 / minute / account | Flood control |
| `GET /v1/messages` | 120 / minute / account | Polling |
| `POST /v1/messages/ack` | 120 / minute / account | Each call is a `DELETE … id = ANY($2)` with up to 200 ids. **Added after it was found unthrottled** (AUDIT 5.23) |
| `POST /v1/blobs` | 100 / day and 500 MB / day / account | Storage. The byte half is enforced, not merely counted — see below |
| `DELETE /v1/blobs/{id}` | 200 / hour / account | Removes a row and unlinks a file. **Added after it was found unthrottled** (AUDIT 5.23) |
| `POST /v1/auth/rotate` | 10 / hour / account | Token grinding |

### Request body limits, and the one that refused legal requests

Every route is capped at `RELAY_MAX_REQUEST_BYTES` (128 KiB by default), applied as a
`MaxBytesReader` rather than a `Content-Length` check — a chunked request declares no length, so a
length check reads as protection while providing none.

**Two routes are exempt and own their own limit, because both legitimately exceed anything the
others could receive.** An exemption is never "no limit": the handler applies its own reader, and
`api.BodyLimitExemptPrefixes` names them in one place that `main` and the integration tests share.

| Route | Ceiling | Sized by |
|---|---|---|
| `POST /v1/blobs` | `api.MaxBlobBytes`, 100 MiB | The attachment policy (§2.8). Answers **413** above it |
| `PUT /v1/keys` | `api.MaxPublishBytes`, ≈1.1 MiB | **Computed** from the bounds `validate()` enforces — `MaxPreKeysPerUpload` keys per pool at their longest accepted key and signature lengths, base64 and JSON framing included. Answers **413** above it |
| everything else | `RELAY_MAX_REQUEST_BYTES` | An envelope (65567 bytes) plus framing |

`PUT /v1/keys` is exempt because it was not, and the relay spent a phase refusing publications it
had itself declared legal (AUDIT 5.32). A real client publishes 100 one-time keys of each kind; an
ML-KEM-1024 public key is 1569 serialized bytes, so the body is around 229 KB against a 128 KiB
global limit, and `MaxPreKeysPerUpload` permits twice that many keys again. The read failed, the
JSON decode reported an error, and the route answered a bare 400 — on an endpoint capped at six
publications a day, where each refusal still spends a token because the limiter runs before the
body is read.

**The invariant to keep:** every body `validate()` accepts must be readable. `MaxPublishBytes` is
derived from the same constants `validate()` checks, so widening a bound widens the ceiling with
it; two numbers maintained by hand is exactly how these came to disagree. And oversize is **413**,
never 400 — a caller can act on "publish a smaller pool" and cannot act on "your JSON is broken",
so collapsing the two costs a debugging session and tells the operator nothing.

### The blob byte quota, and why charging is not enforcing

The 500 MB figure was in this table for a whole phase while nothing consulted it. The bytes were
charged after each upload, in a loop, whose result was discarded — so the daily ceiling was really
the 100-upload count limit, which is ten gigabytes (AUDIT 5.22).

Two changes make it real, and both matter:

1. **One megabyte is charged *before* the write and the remainder after.** The size is not known
   until the upload finishes, and `Content-Length` is a claim, so a single upload can still exceed
   the remaining allowance by up to one blob. The pre-charge is what refuses the *next* one.
2. **The post-charge saturates.** A token bucket that refuses without deducting leaves the bucket
   exactly as full as it was before the overrun, so the next request is permitted, and the next.
   `ratelimit.Charge` therefore takes whatever is left and reports that the subject is now over
   quota; `ratelimit.Allow` keeps the non-deducting behaviour, which is the right one for a request
   that was refused and therefore not served.
3. **A partial megabyte counts as a whole one** (AUDIT 5.27). The size was converted with
   `size >> 20`, which floors, so an upload of 1 MiB + 1 byte spent the one megabyte taken before
   the write and nothing after it. A client uploading just under 2 MiB at a time therefore used
   twice the allowance it was charged — the quota was short by up to a megabyte per upload, always
   in the caller's favour. The conversion rounds up.

A limiter error on either charge **refuses the upload and removes the bytes**. An unmeasurable
quota is the same as no quota, and the limiter's stated policy is to fail closed (§5's whole
argument for that is in `ratelimit.Allow`).

### The subject pepper survives a restart only if you configure it

Bucket keys are `HMAC(pepper, kind ‖ 0x00 ‖ value)` so a Redis dump does not enumerate the
addresses that spoke to the relay. The pepper is `RELAY_RATELIMIT_PEPPER`, and when it is unset the
relay generates one per process — which means **every restart hands every caller a fresh
allowance**, including the invite-redemption brute-force limit and the prekey-drain limit
(AUDIT 5.24). Anything that can restart the process therefore resets the limits.

Configuring it is not free either: the keys become stable for the lifetime of the value, so two
Redis dumps can be correlated. That is why it is optional rather than mandatory, why the
unconfigured case is now logged as a warning rather than being silent, and why a deployment that is
not restarted casually should set it. Rotating it resets every bucket once — the same effect a
restart used to have every time.

### What the client does to stay inside these limits (P5.S10)

A limit the client trips routinely is a limit that gets raised. The iOS client's side of the
contract, recorded here because it is the half this file could not previously see:

- **Publication happens once per installation, not once per launch.** `PUT /v1/keys` is 6 per day,
  and generating the pool is a hundred keypairs. A flag in the sealed container records that the
  relay *accepted* the publication — set after the 200, never before, so a failed publication is
  retried on the next launch rather than remembered as done. **That retry is what turned AUDIT 5.32
  into a lockout:** the publication was refused for a reason no relaunch could change, and six
  honest retries spent the day's budget. The client is right to retry a failed publication; the
  relay must not refuse one it declares legal.
- **The publication body is about 229 KB**, and the relay must be able to read it. 100 one-time
  keys of each kind, an ML-KEM-1024 public key being 1569 serialized bytes. `PUT /v1/keys` owns its
  own body ceiling for this reason — see *Request body limits* above.
- **A bundle is fetched only when there is no session with that peer**, never as a refresh. Every
  fetch consumes one of the target's one-time prekeys, which is exactly the pressure AUDIT 3.1 is
  about, so the request is also marked non-idempotent client-side: a `GET` that mutates must not be
  retried automatically.
- **Sends are never retried automatically.** A duplicate envelope is undecryptable at the far end
  (the ratchet consumed the message key), so an auto-retry would spend the sender's budget to
  deliver something the recipient discards, and would look like success. Retrying is the user's
  action and re-encrypts.
- **Acknowledgement is retried**, because it is idempotent here by design and a lost
  acknowledgement leaves ciphertext on the box — which is the one outcome §4 exists to prevent.

### Why the prekey-fetch limit is a security control (AUDIT 3.1)

Every fetch of `/v1/keys/{aci}` **consumes one of the target's one-time prekeys** — that is what
one-time means. An attacker with a valid session can therefore drain any peer's pool at will, purely
by asking, without ever sending a message. The pool is empty from then until the victim's client
next uploads, and every session established in that window falls back to the reused last-resort
Kyber prekey (§2.6).

That is the mechanism behind base-key witness eviction. Rate limiting is the mitigation, it costs
almost nothing while the endpoint is being written, and it is expensive and disruptive to retrofit
onto a live service — which is exactly why P4.S06 makes it mandatory in this phase and why "defer to
P6" is listed as the anti-goal. AUDIT 3.1 does not close until this and P6.S01 rotation are both
live (P6.S02).

Measured, not asserted: with the limit removed, 60 fetch attempts consumed 60 of the target's
prekeys. With it in place the same 60 attempts consume 10 and the pool survives.

Two supporting measures, since a limit alone leaves a slow-drain path:

- **The Kyber pool degrades rather than empties.** A one-time Kyber prekey is preferred and
  consumed; when that pool is exhausted the reusable last-resort key is served and *not* deleted, so
  PQXDH keeps running. The cost is that the KEM contribution is then shared with every session that
  also fell back — classical X25519 forward secrecy is unaffected — and that degradation is exactly
  what a drain buys the attacker.
- The client is told its remaining counts on upload and replenishes on a threshold, not a schedule.
  Its own counts only: a peer's pool size is precisely the measurement someone draining it wants.

> **Correction, 2026-07-29 (P4.S05).** This section previously said the dispense path would "serve
> the last-resort key without deleting a one-time key once an account's remaining pool falls below a
> floor". That conflated the two pools and is not implementable as written. There is **no last-resort
> key for the X25519 one-time prekey** — the client's `PeerKeyBundle` requires one and it is not
> optional in that type — so when *that* pool empties, no bundle can be served at all.
>
> The honest statement of the residual: draining an account's one-time prekey pool is a denial of
> service against **session setup** with that peer until they next replenish. Existing sessions are
> unaffected; only new ones are blocked. It is bounded by the per-caller fetch limit above and by the
> fact that fetching requires an authenticated account, which requires an invite — in a closed circle
> the attacker must already be a member. Serving a bundle without a one-time prekey is possible in
> PQXDH generally and would remove this, but it requires making the field optional in the client's
> bundle type, which is a client change and out of scope for P4.

---

## 6. Authentication

```
invite code ──redeem──▶ account (aci) ──▶ session token ──▶ every other endpoint
```

- Invite codes: 128 bits from a CSPRNG, rendered in an unambiguous alphabet, single-use, expiring.
  Never hardcoded — C-01 is the client-side half of this and the server half is P4.S03.
  - **Alphabet:** Crockford base32 — digits and uppercase letters less `I`, `L`, `O`, `U`. 32
    symbols carry exactly 5 bits, so masking a uniform random byte to its low 5 bits is unbiased
    and needs no rejection sampling. 26 symbols carry 130 bits, at or above the 128 claimed.
    `Parse` maps `I`/`L`→`1` and `O`→`0` on input only, so transcription is forgiving without the
    key space widening.
  - **Single use is a property of one SQL statement**, not of two. `DELETE … WHERE … RETURNING`
    decides and consumes atomically; exactly one concurrent caller gets a row. The obvious
    `SELECT`-then-`DELETE` passes every sequential test and creates several accounts from one code
    under concurrency — measured at 3 of 16 when negative-tested.
  - **Expiry is in the same `WHERE` clause**, evaluated against `now()`. Checked in Go against a
    row read a moment earlier, it would be checked against a clock that is not the database's.
  - **Unknown, redeemed, expired and lost-race are one error**, all the way from SQL to the 401.
    The schema genuinely cannot tell them apart — a redeemed invite is deleted — so the API is not
    papering over a database that knows more than it should.
  - **Bootstrapping is `relay --issue-invite` on the host, not an endpoint.** The first account
    cannot be authorised by an authenticated call because there is nobody to authenticate, and the
    usual answer to that is an admin API, which §8 refuses. Running a command requires shell access
    to the host — the §1.1 adversary already assumed to read the database — so it grants that
    adversary nothing new and a remote attacker nothing at all. The code is printed to stdout once
    and never logged.
- Session tokens: 256 bits from a CSPRNG, hashed at rest, rotatable, revocable by `DELETE`.
  - **TTL 30 days.** Long because this is a messenger, and a session that expires weekly trains
    people to re-authenticate reflexively — the habit phishing depends on. Affordable only because
    revocation is immediate, so the TTL is a backstop for a forgotten device, not the control.
  - **Rotation is one transaction**: `DELETE … RETURNING` the old, `INSERT` the new. Two statements
    would leave either a window where both tokens work (which is the window a thief wants) or one
    where neither does (which signs the user out with no way back). Negative-tested: making it
    insert-without-delete left the old token working, produced 4 sessions after 3 rotations, and let
    8 of 8 concurrent rotations succeed.
  - **`DELETE /v1/auth/all`** revokes every session including the caller's, and is deliberately
    *not* rate limited — it only ever destroys the caller's own access, and throttling the panic
    button is the wrong trade.
  - **Redemption creates the account and first token in the same transaction.** The token is
    generated before the transaction, but only its hash enters it; invite deletion, account insert,
    and session insert commit or roll back together. A failed session insert therefore leaves the
    invite redeemable and creates no orphan account. Negative-tested by forcing the session hash
    constraint to fail, then redeeming the same invite successfully.
- Presented as `Authorization: Bearer`. Compared with a constant-time comparison after hashing.
- **No password, no recovery flow, no email.** There is nothing to phish and nothing to reset. Losing
  the device means losing the account, which is the honest consequence of §3.4 and must be stated in
  the UI before a user relies on it.

Every endpoint except `/health` and `/v1/invite/redeem` requires a token. **`/v1/keys/{aci}`
requires one too** — an unauthenticated prekey directory would make the §5 per-account limit
unenforceable and would let anyone on the internet drain any pool.

---

## 7. Logging (`THREAT_MODEL.md` §3.6)

Structured, level-filtered, and redacting by construction rather than by discipline: the log helper
takes typed fields, and no type that can hold a token, a code, a push token, an envelope, or a key
has a loggable representation. Prohibition 6 is enforced by the type system where it can be, not by
review.

- **Never logged:** request bodies, envelope bytes, tokens or their hashes, invite codes, push
  tokens, prekeys, `aci` at info level.
- **IP addresses:** retained **24 h** for operational triage, then dropped. Not correlated with
  accounts at any point.
- **Access logs:** method, route *pattern* (never the populated path — `/v1/keys/{aci}` never
  `/v1/keys/3f2b…`), status, duration. A populated path is a metadata record hiding in a log line.
- **Nor may an error message carry one** (AUDIT 5.28). The same rule applied to the access log has
  to apply to whatever a handler passes to `slog.String("reason", err.Error())`, and it did not: a
  blob's file name *is* its id, that id is the whole capability to read or delete the attachment
  (§2.8), and every `os` failure names the path. `reason` is deliberately not on the denylist —
  it carries the operationally useful half of every error the relay logs, and denying it wholesale
  is how redaction gets switched off again — so `internal/blob` removes the path at the source,
  keeping the operation and the syscall error, which is the half an operator acts on.
- Log volume is itself metadata: an error log that fires once per delivery is a delivery record.
  Tested as such — five sends must not produce five handler log lines.

**This section is verified by running the relay, not by reading it.** The logging package redacts
by type and by an attribute-name denylist, and has unit tests for both — but those test the
*mechanism*, and a mechanism can be correct and still bypassed: one `slog.String("detail", token)`
under a key nobody thought to deny and the unit tests stay green while the credential is on disk.
So the integration suite drives a complete flow at **DEBUG** — invite, redeem, publish, fetch a
bundle, send, fetch, acknowledge, upload, download, rotate, revoke, a panic, and a batch of
malformed requests — captures everything the process emits, and searches it for the actual secret
values that flow produced: both session tokens, both invite codes (grouped and ungrouped), both
client addresses, the envelope in base64 and raw, the blob bytes, all three identifiers, and the
panic value. Negative-tested by logging a rotated token under `detail`, which the denylist does not
cover; the audit caught it.

---

## 8. What this design deliberately cannot do

P4.S01's anti-goal is *"design an admin backdoor"*, and the way to satisfy it is to build a service
where there is nothing to abuse.

- **No admin API. None.** No user list, no message browser, no impersonation, no "resend", no
  password reset, no support console. Not disabled behind a flag — absent from the codebase, because
  a flag is one config change and one compromised credential away from being on.
- **No message search**, which is impossible anyway, and no full-text index to accidentally build one.
- **No read receipts, delivery receipts, or typing indicators stored server-side.** If they exist at
  all they travel as ordinary encrypted messages, which is the only form in which the server does not
  learn them.
- **No contact discovery** (prohibition 3). The relay cannot answer "does this person have an
  account" for any input except an `aci` the caller already has.
- **No account enumeration.** `GET /v1/keys/{aci}` returns an identical response shape and timing for
  a nonexistent account as for an account with an empty pool.
- Operational access is `psql` on the host — which is exactly the §1.1 adversary, and the reason the
  retention policy is what it is. **We defend against ourselves by having nothing to hand over**, not
  by promising restraint.

---

## 9. Deployment shape

Docker Compose runs three services on an internal network: `api`, `postgres`, `redis`. The committed
Compose configuration publishes only `api`, and only on loopback; Postgres and Redis remain
unreachable from the host network. P4.S02 established that boundary because exposing a datastore is
the most common way a development relay becomes an internet-facing one.

P5 added a public TLS reverse proxy in front of the same loopback-bound API without widening the
datastore boundary. [`RUNBOOK-VPS.md`](RUNBOOK-VPS.md) owns the host procedure and staging state;
live read-only checks win for mutable deployment facts.

**Every service is confined, not only `api`** (AUDIT 5.28). Until then the relay container dropped
all capabilities, refused new privileges and ran a read-only rootfs while Postgres and Redis ran with
Docker's default capability set and no ceiling on memory, CPU or process count — which protects the
wrong asset. The relay container holds a static binary and a directory of client-encrypted blobs;
Postgres holds every account row, every public identity key and every undelivered envelope, which is
the database §1.1 assumes an adversary is trying to reach. Both datastores now drop `ALL` and add
back only what their entrypoints use to take ownership of a directory and `su-exec` to a service
account, refuse new privileges, and carry `mem_limit`, `cpus` and `pids_limit`. Redis is additionally
read-only with a tmpfs `/data`, since with persistence off it writes nothing to disk at all.

Postgres is **not** read-only, and that is the recorded residual rather than an oversight: it writes
its socket, lock files and statistics outside the data volume at paths that move between major
versions, so a rootfs lockdown here would be a tmpfs list that silently rots at the next image bump.
The capability set is what confines that container.

`Scripts/verify-relay.sh` fails on a service that loses any of those, self-testing itself against the
committed file first; `Scripts/verify-image-vulns.sh` scans the binary the image actually ships.

### 9.1 Certificate pinning: the pin set and the rotation runbook (P5.S06)

The client pins the server's public key and **fails closed** (P5.S08). That makes this section
operational: a mistake here is not a weakened control, it is every installed app unable to
connect, with no server-side remedy.

#### What is pinned, and what is deliberately not

| SPKI SHA-256 (base64) | What | Pinned? |
|---|---|---|
| `MRFmm9ckpODEhUXZfYHbhMzIsxiCDsBJD/HwOy/rQBM=` | Staging leaf, `relay.mgchatman.app`, ECDSA P-256. Cert expires **2026-10-27**; the key does not rotate with it. | **YES** |
| `+qAajv1/B4owz+yao2g3R3lSNjD7qPN3eR3JXwA5FCY=` | Backup key, generated 2026-07-29, **not yet in use**. `/etc/ssl/private/cipher-backup.key`. | **YES** |
| `brzvtCELCIZUo4sD/qPX0ccRtPsd3DY6RfmxpOU9oB4=` | Let's Encrypt intermediate `YE1`, expires 2028-09-02. | no — recorded only |
| `sCkq5UWXjg+7mKu9lMhhYF5bGLsy7VI/UNW3tccdR7w=` | ISRG `Root YE`, expires 2032-09-02. | no — recorded only |
| `diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=` | `ISRG Root X2` (cross-signed by X1), expires 2032-09-02. | no — recorded only |

All five are **public values** — an SPKI hash is derived from a public key that appears in the
certificate — so recording them here discloses nothing. Extracted 2026-07-29 from the live chain.

**The intermediate is recorded and not pinned, which is a deliberate departure from this section's
original rule 1.** The effective strength of a pin set is its *weakest accepted* pin. Accepting
`YE1` means accepting **any certificate Let's Encrypt issues for this hostname**, and an attacker
who can pass ACME validation — by controlling DNS, or the host, which are exactly §1.1 and §1.3 —
can obtain one. Pinning the intermediate would therefore reduce the control to "must be a Let's
Encrypt certificate", which ordinary PKI validation already provides, while stopping none of the
adversaries pinning exists for. The availability argument that usually justifies an intermediate
pin is already met by the backup key, and better: a backup key we hold cannot be rotated out from
under us, whereas Let's Encrypt rotates intermediates on their own schedule. Recording them is
still worth doing — the rotation procedure below needs to recognise a chain change, and that needs
a baseline.

#### Rules

1. **Pin the SPKI, not the certificate**, so renewal with the same key needs no client change.
2. **Ship at least two pins, one of which is a backup key not in the current chain.** One pin plus
   one lost key is a permanently bricked client with no recovery path.
3. **New pin first, certificate second. Never the other order.** Publish the pin in a client
   release, wait for adoption, *then* switch the certificate.
4. **Record every pin with what it is, when it was extracted, and when it expires.**
5. **Both private keys must survive a host move.** `INFRASTRUCTURE.md` says moving hosts after
   P5.S08 means carrying the TLS private key; from here it means carrying *both*, because a backup
   pin whose key was left behind is not a backup.

#### `--reuse-key` is load-bearing, and it is not the default

Certbot generates a **fresh private key on every renewal** unless told otherwise. That changes the
SPKI roughly every 60 days and breaks every pinned client, with no server-side fix — the clients
are already shipped. `reuse_key = True` is set in
`/etc/letsencrypt/renewal/relay.mgchatman.app.conf`.

**Re-check it after any certbot command that rewrites that file** (`certonly` with new flags,
`reconfigure`, a `--force-renewal` with options). `Scripts/verify-pins.sh` checks it, along with
the live SPKI, against the table above.

#### Routine renewal (no client action)

The expected case, every ~60 days, fully automatic: certbot renews, reuses the key, the SPKI is
unchanged, the deploy hook reloads Nginx. Nothing to do. `Scripts/verify-pins.sh` is what tells you
this is still true rather than assuming it.

#### Planned key rotation (the procedure that must not be improvised)

Required when the leaf key is deliberately retired, and it takes **two client releases**.

1. **Verify the backup key is still present** on the host and its SPKI still matches the table.
   Rotating toward a backup that no longer exists is the failure this is designed to avoid.
2. **Generate the *next* backup key** — call it C. The pin set is now {A current, B backup, C
   next-backup}.
3. **Ship a client release pinning {A, B, C}.** Do not switch the certificate yet.
4. **Wait for adoption.** Anyone still on the previous release pins only {A, B}, so switching to B
   is safe for them, but switching to C is not. This wait is the whole reason rotation is not a
   same-day operation.
5. **Switch the certificate to key B** — reissue with `--key-type ecdsa --reuse-key` against B, and
   confirm the served leaf's SPKI equals B's.
6. **Ship a client release pinning {B, C}**, dropping the retired A.
7. **Destroy A's private key** only after step 6 has adopted. Until then it is the rollback.

#### Emergency: the leaf key is compromised

Availability now costs less than continuing to serve with a known-compromised key.

1. Reissue immediately against the backup key B (`--key-type ecdsa --reuse-key`). Every shipped
   client already pins B, so **this requires no client release** — that is precisely what B is for.
2. Revoke the old certificate: `certbot revoke --cert-path … --reason keyCompromise`.
3. Generate a new backup key and ship it as a pin in the next release. **Until that release
   adopts, the service is one lost key away from a total outage**, so treat it as urgent rather
   than as done.

#### Emergency: both keys are lost

There is no recovery. Every installed client fails closed against a host that cannot present a
pinned key. The only path is a client release with a new pin set, and users who cannot or do not
update are permanently disconnected. This is the outage rule 2 exists to prevent, and the reason
the backup key's storage and host-move handling are written down rather than assumed.

#### Changing hosts

Carry `/etc/letsencrypt/` **and** `/etc/ssl/private/cipher-backup.key` to the new host. Do not let
certbot issue a fresh key on the new host: that is a rotation, and rotations follow the procedure
above. See `INFRASTRUCTURE.md`, "the constraint that decides when hosts can still change".

### 9.2 The reverse proxy and the client address (P5.S05)

Once Nginx is in front, every request reaches the relay from the proxy. `clientAddr` feeds that
value to the rate limiter, and `POST /v1/invite/redeem` is the only per-IP limit there is — 5 per
hour, §5. Left alone, all callers share one bucket, so **the first caller to spend the budget
denies invite redemption to everyone**: a global onboarding outage any single address can trigger.

Believing a forwarding header is the opposite failure and the worse one. The header is written by
the client unless something overwrites it, so a relay that trusts it lets one caller mint a fresh
bucket per request — the limit stops existing rather than merely being wrong.

**The rule: trust an address, never a header.**

- `RELAY_TRUSTED_PROXY` is a comma-separated list of CIDRs or bare addresses. **Empty — the
  default — trusts nobody**, which is the P4 behaviour and is what development, CI, and the
  integration suite run with. An unset value must never mean "trust loopback".
- `httpx.RealIP` reads `X-Real-IP` **only** when the peer that actually opened the connection
  falls inside that list, and rewrites `RemoteAddr` so every handler downstream — including ones
  not yet written — reads the ordinary field.
- `X-Real-IP`, not `X-Forwarded-For`: Nginx *sets* the former, overwriting whatever arrived, so
  there is a single value and nothing to choose. `X-Forwarded-For` is an append-only list, and
  every "take the last element" rule is correct only for a proxy depth that is assumed rather
  than verified. A comma in `X-Real-IP` is therefore treated as evidence the assumption is broken
  and the header is discarded.
- Addresses are normalised (`::ffff:203.0.113.9` → `203.0.113.9`, zone suffixes stripped) because
  the bucket key *is* this string, and one host must not be able to present as several.
- Every rejection falls back to the proxy's own address, which over-throttles. There is no input
  that yields no limit.

**The value is deployment-specific, and the obvious guess is wrong.** With
`ports: "127.0.0.1:8080:8080"`, traffic passes through `docker-proxy`, which opens a *new*
connection into the container from the compose bridge **gateway**. The relay therefore never sees
`127.0.0.1`, and a configuration naming loopback silently trusts nothing while appearing
configured. Read the actual value off the running network rather than assuming it:

```sh
docker network inspect cipher-relay_internal \
  --format '{{ (index .IPAM.Config 0).Gateway }}'
```

**The gateway address as a `/32`, not the subnet.** Every proxied request arrives from the gateway
specifically, so the subnet is wider than it needs to be — and the extra width is the other
containers. On the staging box `postgres` and `redis` sit at `.2` and `.3`, and under a `/16` a
compromised datastore container could name any client address it liked and mint rate-limit buckets
at will. Under `172.18.0.1/32` it cannot. Verified on the deployment, not reasoned about: a loop
from inside the `postgres` container rotating `X-Real-IP` on every request still hit `429`, while
the same rotation through the host's published port did not.

**What trusting the gateway does and does not cover.** It is not confined to the compose services:
*anything on the host* that can reach the published loopback port arrives as the gateway too, and
is therefore believed. That is accepted rather than overlooked — the port is bound to `127.0.0.1`,
so reaching it already requires local execution on the host, which is past every boundary the
relay could defend. What the `/32` buys is that a container escape confined to `postgres` or
`redis` does *not* also grant it. It grants nothing to the internet: an attacker reaching Nginx
from outside is never the gateway, and Nginx overwrites `X-Real-IP` on the way through.

---

## 10. Open questions, deferred deliberately

| Question | Decided in |
|---|---|
| Sealed sender certificate issuance and rotation | P7 |
| Envelope length bucketing (`THREAT_MODEL.md` §3.5) | P7 |
| Push token rotation cadence | P7.S03 |
| Multi-device — needs `Envelope` `wireVersion` 2 and a `devices` table | P10 |
| Groups — cryptographically unreachable by locked decision §0.2.2 | P10 |
| Hosting jurisdiction (`THREAT_MODEL.md` §3.7) | P5.S01, and it is a purchase |

---

## 11. Privacy regression statement (P4 phase requirement)

Does this design leak anything new to the server, to Apple, or to disk?

**To the server:** yes, unavoidably, and it is enumerated rather than minimised in prose — account
existence (`aci`, public keys, day-resolution activity), who has mail waiting while it waits, and
sender→recipient pairs for in-flight messages via the cleartext `sender` field inside `envelope`
(§2.7). No message content, at any time, in any column. No social graph at rest: the invite graph is
never written, and the attachment ownership edge is never written.

**To Apple:** nothing new in P4 — push lands in P8. The `push_tokens` table is designed here so that
§3.3's requirements are structural rather than retrofitted.

**To disk:** the intended set only, provided two defaults are overridden: Redis persistence off (§3),
and backups scoped to exclude undelivered messages (§4). Both are listed because both are on by
default in the obvious configuration, and either would silently reintroduce retention that the schema
was designed to avoid.
