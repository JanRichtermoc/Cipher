# Cipher — threat model

Who this is defended against, what each adversary sees, and what they still see after the plan is
finished. Every privacy position below is a **decision with a date**, not an omission.

Written 2026-07-28. Companion to [`AUDIT.md`](AUDIT.md) (what is broken) and
[`CLAUDE_IMPLEMENTATION_PLAN.md`](CLAUDE_IMPLEMENTATION_PLAN.md) (when it gets fixed). AUDIT records
findings; this file records *who they matter to*. A finding with no adversary is not a finding.

**Scope:** a private circle — a handful of people who know each other and can compare safety numbers
in person. That assumption does real work below and is called out wherever it changes an answer.

---

## 0. The core decision

**The relay is assumed hostile or seizable.** Not "assumed to misbehave occasionally" — assumed to
be, at some point, fully under someone else's control: a provider that images the disk, a legal
order, a compromised host, or a stolen deploy key.

This is the strongest of the three models considered and it was chosen deliberately. It has one
dominant consequence that shapes the whole backend:

> **The server must be worth seizing as little as possible.**
> Not "the server holds ciphertext" — *the server holds almost nothing at all.*

That is why delete-on-delivery (§3.1) outranks every other server-side control, and why sealed
sender (§3.2) is a real phase rather than backlog. Encrypting content is table stakes; under this
model the goal is that a seized box yields no content, no history, and as little of the social graph
as the routing layer can be made to forget.

---

## 1. Adversaries

Ranked by how much they should shape decisions, not by likelihood.

### 1.1 Host seizure, legal compulsion, or the VPS provider

The defining adversary. Has the disk, the memory, the database, and can compel future cooperation.

| | |
|---|---|
| **Today** | Nothing — there is no server. |
| **After the plan** | Undelivered ciphertext still in flight; recipient identifiers for those; push tokens; account existence and creation times. |
| **Residual** | Coarse timing and volume of *undelivered* traffic. Delivered messages are gone (§3.1), and after sealed sender the sender of an undelivered message is not visible (§3.2). |

Compelled *future* cooperation is the case that no amount of deletion fixes: a seized-but-running
box can be made to log going forward. The controls are pinning (a substituted server cannot
transparently take over), safety numbers (a substituted *identity* is visible to users), and the
fact that content stays end-to-end encrypted regardless. **Cipher does not defend against a
compromised host that is left running and observed over time**, beyond keeping message content
unreadable. Stated plainly because a warrant canary or "we'd notice" claim would be theatre at this
scale.

### 1.2 Hostile or compromised relay (software-level)

The relay is untrusted by construction; this is the adversary `Envelope` was designed against.

- Can forge, replay, reorder, drop, or rewrite any envelope header byte. `Envelope.sender` is a
  **routing hint an attacker controls** — pinned by `LockedDecisionsTests.testEnvelopeSenderIsNotATrustInput`.
- Cannot read or forge message content: authenticity comes from the Double Ratchet.
- Cannot force a session reset — `PlaintextContent`/`DecryptionErrorMessage` is refused at the wire
  boundary (AUDIT 3.5), which otherwise hands a relay a repeatable prekey-burning primitive.
- **Can** currently drive base-key witness eviction by fetching prekey bundles (AUDIT 3.1). The
  mitigation is server-side rate limiting plus prekey rotation, both scheduled before staging is
  exposed.

### 1.3 Network attacker

Passive observer or active MITM between device and relay.

- TLS 1.3 plus certificate/public-key pinning, failing closed. No ATS exceptions, ever.
- Even a total TLS break yields ciphertext only — that is the point of end-to-end encryption, and
  the reason pinning is defence in depth rather than the primary control.
- **Residual:** traffic timing and length. Addressed by length bucketing (§3.5).

### 1.4 Device thief

Three distinct cases that are routinely conflated:

| State | What is exposed |
|---|---|
| Powered off / before first unlock | Nothing. Data Protection and the Keychain class both hold. |
| **After first unlock, locked** | **Identity key and record key are reachable** by code executing on the device. This is the accepted cost of `AfterFirstUnlockThisDeviceOnly` (AUDIT 2.1) — required so a notification extension can decrypt while locked. |
| Unlocked | Everything the app can see. The app lock (`LAContext`) is the only remaining barrier and is not a defence against an attacker with code execution. |

Backups are covered: the Keychain items are `ThisDeviceOnly` and the record container is excluded
from backup, so a restored device cannot impersonate this installation.

### 1.5 Apple

Not an attacker, but a party in the system with visibility worth stating.

- **APNs sees delivery metadata** — that a device was pinged, and when. Payloads are content-free
  and wake-only, so Apple never sees message content or sender names.
- iCloud Keychain is never used (`kSecAttrSynchronizable = false`); the identity key cannot sync.
- Encrypted device backups exclude both the Keychain items and the record container.
- **Residual:** APNs delivery timing is unavoidable while using push. Accepted.

### 1.6 Other apps, and our own logs

- Nothing secret reaches `UserDefaults`, the pasteboard beyond an expiring copy, or a log line.
  `RedactingLogger` treats **every** message from libsignal as `.private`, so nothing reaches a
  sysdiagnose.
- No crash reporter that could capture message plaintext or key material.
- The app-switcher snapshot is redacted on resign-active.

### 1.7 Compromised upstream dependency or build toolchain

The adversary with the widest reach: a malicious libsignal build, a moved tag, or a poisoned gem
runs *our* code on *every* device, with our entitlements and our keys. Encryption does not help —
this attacker is inside the trust boundary.

| | |
|---|---|
| **Today** | One dependency (libsignal), pinned to a commit, with an independently re-verified SHA-256 over the prebuilt FFI archive. |
| **After the plan** | Same, plus CI running the supply-chain gate on every build (AUDIT 1.6) and a committed, diffable pod snapshot (AUDIT 1.7). |
| **Residual** | The iOS FFI binary is **unsigned and unattested** (AUDIT 1.1) — a hash pins bytes, not origin. If Signal's build infrastructure were compromised and it published the matching hash, the pin would faithfully reproduce the malicious build. |

This is why `AUDIT.md` §1 is as long as it is, why the dependency count is exactly one, and why
§4.1 forbids adding more.

### 1.8 A circle member who turns hostile

Inherent to any messenger and mostly out of scope: a participant can screenshot, quote, or leak
anything they legitimately received. What *is* in scope:

- They cannot read messages for other pairs — sessions are pairwise.
- They cannot impersonate another member without triggering a safety-number change.
- Disappearing messages are a **courtesy, not a control**, against a hostile recipient. Never
  presented as one.

---

## 2. What is deliberately not defended against

Stating these prevents the UI from implying otherwise:

- A device with active code execution (jailbreak, kernel exploit, malicious profile). Jailbreak and
  debugger detection are hardening, not controls, and must never be marketed as such.
- A compromised host left running and observed over time (§1.1).
- Traffic analysis by a global passive adversary. Length bucketing raises the cost; it does not
  defeat a nation-state observing both endpoints.
- A hostile recipient (§1.8).
- Rubber-hose / coercion. No duress codes, no plausible deniability. Claiming either without a real
  design would be worse than not claiming it.

---

## 3. Privacy positions

Each is a decision, with its rationale and where it lands.

### 3.1 Zero retention — delete on delivery

**Decision:** the relay deletes a message the moment delivery is acknowledged, and sweeps
undelivered messages on a TTL. No archive, no "just in case" table, no soft-delete flag.

This is the highest-value control in the entire plan under the §0 model, and it is nearly free at
schema-design time while being painful to retrofit. Encryption makes a seized database unreadable;
deletion makes it *empty*. Those are not the same guarantee — the first is a bet on the cipher and
on key hygiene over the retained lifetime of the data, the second is not a bet at all.

Lands in **P4** (schema + relay). Consequence: a device offline past the TTL loses undelivered
messages. That is the correct trade and must be surfaced honestly in the UI, not hidden.

### 3.2 Sealed sender — promoted out of the backlog

**Decision:** implement it, in its own phase (**P7**), rather than treating it as optional polish.

Under an honest-but-curious model, sealed sender at five users is close to pointless — with a circle
that small the social graph is inferable from timing alone, and any pair is one of a handful of
possibilities. Under the **seizable-host** model it is worth real work, because it changes what a
seized box can prove. Timing correlation is an inference; a `sender` column is a record.

libsignal already ships sealed sender (`Pods/LibSignalClient/swift/Sources/LibSignalClient/SealedSender.swift`), so this is wiring plus a
server-issued sender-certificate scheme — **not new cryptography**. The wire format was designed for
it: `Envelope`'s `wireVersion` plus its reserved type space exists precisely so sealed sender can
arrive without a break.

### 3.3 Push-token linkage

**Decision:** treat the token↔account mapping as metadata that survives message deletion, because it
does. Rotate it, and delete it with the account. Otherwise zero retention is undermined by the one
table that has to persist.

**Amended 2026-07-29 (P4.S01, AUDIT 6.10).** This section originally said to store the token
*hashed*. That is not implementable: the token must be replayed verbatim to APNs, so a one-way
function cannot be used, and the wording promised a guarantee stronger than anything achievable.
The strongest achievable property is encryption at rest under a key held only in the service
environment and never in the database, so that a dump, a backup, or a stolen replica is insufficient
on its own. It does **not** defeat §1.1 host seizure, where the environment is seized with the disk.
Rotation and deletion-with-the-account are what do the real work there, and they were always the
substance of this position. Schema in [`BACKEND.md`](BACKEND.md) §2.9.

### 3.4 Identifiers — invite codes only

**Decision:** never phone numbers, never email. Not a UX preference — an identifier you did not
collect cannot be seized, correlated against other services, or used for contact discovery. It also
removes server-side contact discovery entirely, which is historically the largest metadata leak in
messengers that have it.

Recorded here because the current plan mandates invite codes without stating why, and an unstated
rationale is one refactor away from "let's just add email login".

### 3.5 Traffic analysis — length bucketing

**Decision:** pad ciphertext to fixed length buckets before relay. `Envelope` already caps at 64 KB,
so the bucket set is bounded and cheap. Raises the cost of distinguishing a one-word reply from a
paragraph. Lands in **P7** with sealed sender, since both are metadata work.

### 3.6 Server logs

**Decision:** no request bodies, no message metadata beyond what routing needs in the moment, and no
IP retention beyond a short operational TTL. Logs are a retention channel that survives message
deletion, so they get the same discipline as the database.

### 3.7 Jurisdiction

**Decision:** a real selection criterion under this model. Hetzner (DE) and OVH (FR) sit under GDPR
and require judicial process; a US provider is exposed to instruments with gag provisions. The
honest caveat: jurisdiction shifts *who* must ask and *how loudly*, and matters far less once §3.1
means there is nothing to hand over. Pick well, then rely on having nothing.

### 3.8 Local exposure

App-switcher redaction, expiring pasteboard for copied messages, backup exclusion for the record
container, encrypted local message database from the moment real messages exist, and disappearing
messages that actually delete rows and cached media.

---

## 4. Standing prohibitions

Violating any of these is a security regression regardless of what it enables:

1. **No analytics. No telemetry. No third-party SDKs.** Every dependency is an exfiltration path and
   a supply-chain risk; libsignal is the only one, and it is pinned, checksummed, and reviewed.
2. **No IDFA, no advertising identifier, no device fingerprinting.**
3. **No server-side contact discovery.**
4. **No crash reporting that can capture plaintext or key material** — none, or a redacting pipeline
   that provably cannot.
5. **No phone or email identifiers** (§3.4).
6. **Never log** private keys, session or ratchet state, plaintext, tokens, invite codes, safety
   numbers, or raw `ProtocolAddress`.
7. **No plaintext message content on the server, in any column, at any time** — including "temporary"
   ones.
8. **No security UI that claims a control which does not exist.** Remove it, disable it, or label it
   as unimplemented in DEBUG only.

---

## 5. How this file is used

- A new AUDIT finding names the adversary from §1 it matters to. If none applies, it is a bug, not a
  security finding.
- A plan step that touches the server or the wire states its **privacy regression**: does it leak
  anything new to the relay, to Apple, or to disk?
- A change that weakens any §4 prohibition requires editing this file first, with a date and a
  rationale. Changing the code before the argument is the failure mode this file exists to prevent.
