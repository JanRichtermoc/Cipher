# Proposal — a re-authentication path (AUDIT 5.41)

> **STATUS: DECIDED AND IMPLEMENTED, 2026-08-13. This is now a historical design record.**
> It was approved with **A1** for the §4 trade, and both changes shipped as their own steps:
> **Change D** as **P9.S10** and **Change A** as **P9.S11**. `AUDIT.md` **5.41 is CLOSED** by the
> pair — in the repository; the staging relay does not carry the relay half yet, and
> `RUNBOOK-VPS.md` owns that pending deploy.
>
> **It is still authoritative for nothing.** What was built is described by the two roadmap rows,
> `AUDIT.md` 5.41, and `BACKEND.md` §2.1a and §6; where this document and those disagree, those win,
> and they already do in one place worth naming — §7's verification list was written before the work
> and is not the evidence, the steps and their negative tests are. What this file keeps is the part
> history loses: the options that were weighed and rejected, and why.
>
> **Read §4 with 5.42.** The residual this document argued about is not the only one the design
> carried; review after the merge opened **5.42**, which §4 did not anticipate.

## 1. The problem, precisely

**AUDIT 5.41.** The session token is the only credential path, so there is no non-destructive way to
revoke sessions and no way for a device to recover from losing one.

Verified against the code rather than argued:

| Fact | Evidence |
|---|---|
| Rotation needs the old token | `POST /v1/auth/rotate` requires `Authorization: Bearer` |
| Redemption mints a **new** account | `invite.go` → `uuid.NewRandom()` for the `aci` |
| `DELETE /v1/auth/all` is self-service, per-account | `auth.go` — it authenticates *as* the account |
| A rotation rejection erases local state | `RootView.swift:129` catches `Failure.rejected` → `signOut()` |
| 401 on rotate produces that error | `InviteRedemption.swift:277` |
| Up to a 23-day delay before it fires | `AppSession.swift:255` (7-day window), `api/auth.go:30` (30-day TTL) |

Two consequences, and the second is the one that makes this urgent:

1. **Unrecoverable.** An account whose token hash is gone must re-register, receive a different
   `aci`, and re-verify safety numbers with every peer.
2. **Silently destructive, on a delay.** Each device erases its own protocol state, history and
   profile whenever it next enters its rotation window — with nothing on screen linking that to the
   operator's action weeks earlier.

It also constrains two other rows: **4.16** (backups must carry `session_tokens`, which resurrects
revocations) exists only because the token is irreplaceable, and the incident runbook has to
document mass revoke as "disband the circle" rather than as a control.

## 2. The obvious design does not work, and it fails the same way P7.S01 did

The natural answer is **challenge–response against the identity key the relay already stores**:
`accounts.identity_key` holds the public half, the private half is on the device, so the device
proves possession and the relay mints a fresh token. No new secret, no new identifier, nothing added
to what a seized relay holds.

**It is not buildable here.** A libsignal identity key is **Curve25519**, and its signatures are
**XEd25519** (`PrivateKey.generateSignature` / `PublicKey.verifySignature`). Verifying one in Go
means converting a Montgomery *u* to an Edwards *y* and verifying as Ed25519 — field arithmetic that
Go's standard library does not expose. That leaves two routes, and the project forbids both:
hand-rolling it violates §0.6 *"do not invent cryptography"*, and pulling in
`filippo.io/edwards25519` or `golang.org/x/crypto` makes it the relay's **first cryptographic
dependency**, a supply-chain change needing its own approval.

This is the **same wall P7.S01 hit** with the server-issued sender certificate, for the same reason,
and it is worth naming so the next person does not rediscover it: *the relay cannot verify anything
libsignal signed.*

## 3. Recommended: two changes, independently shippable

### 3.1 Change D — stop the silent destruction (client-only, no protocol change)

**Do this first and separately, whatever is decided about the rest.**

Today a rotation rejection is treated as a sign-out: `signOut()` sets the destructive gate and
`RootView` erases protocol state, history and profile. That conflates *"the relay will not renew
this token"* with *"the user asked to leave"*. They are not the same event, and the difference is
weeks of a person's messages.

Proposed: a rejected rotation leaves the app **authenticated-but-stale** — messaging stops, the UI
says plainly that the session ended and the account must be re-established, and **nothing is
erased** until the user confirms. Erasure stays exactly where it belongs, behind a deliberate act.

- **Cost:** small. Client-only, no migration, no relay change, no deploy.
- **Buys:** removes the worst half of 5.41 — the silent, delayed, unexplained history loss.
- **Does not buy:** the account is still unrecoverable. This is harm reduction, not a fix.
- **Risk:** an account that genuinely must be erased now waits for a user tap. Acceptable: the
  destructive gate already exists for the real sign-out path, and `requiresAccountCleanup` still
  blocks a new invite until erasure completes.

### 3.2 Change A — an Ed25519 account key (the actual fix)

Mint a **separate signing key on the device at registration**, independent of the libsignal identity
key, and publish only its public half.

- **Client:** CryptoKit `Curve25519.Signing` — Ed25519, an already-permitted dependency (§0.6 allows
  LibSignalClient *and* CryptoKit). Private half stored beside the other device secrets under the
  same non-synchronizable, `ThisDeviceOnly` Keychain class; it never leaves the device.
- **Relay:** `crypto/ed25519`, Go **standard library**. No new dependency, which is the whole reason
  this shape works where §2 does not.
- **Storage:** one new column (or a small table) holding a **public** key, plus migration `0003`.
  Nothing secret is added to the relay: a seized database gains a public key it can already infer it
  has.

Flow:

1. `POST /v1/auth/challenge` `{aci}` → a random, single-use challenge held in Redis with a short
   TTL, bound to that `aci`.
2. `POST /v1/auth/reauth` `{aci, challenge, signature}` → the relay verifies with the stored public
   key and, on success, issues a fresh session token exactly as redemption does.

**The properties that must hold, each with the precedent it copies:**

- **No enumeration oracle.** A challenge is returned for an unknown `aci` too, and every failure —
  unknown account, wrong signature, expired or reused challenge — is one indistinguishable response.
  Precedent: invite redemption's single `401` (`TestRedeemEndpointResponseIsIdenticalForUnknownAndUsed`)
  and `TestTimingOfAnUnknownAccountResemblesAKnownOne`.
- **No replay.** The challenge is server-generated, single-use, short-lived, and consumed in the same
  atomic operation that accepts it. Precedent: `DELETE … RETURNING` in invite redemption.
- **Rate limited on an unauthenticated route**, per `aci` and per client address, failing closed when
  Redis is unavailable. Precedent: `redeemLimit` and `ratelimit.Allow`'s fail-closed behaviour.
- **`aci` is not logged**, and no per-attempt record is kept. Precedent: `BACKEND.md` §7.

**This does not reverse "the relay does not verify signatures."** That decision
(`TestTheRelayDoesNotVerifySignatures`) is about **prekey bundle** signatures, and its reasoning is
that a client trusting the server's verdict would have no protection from a hostile relay. Here the
relay verifies for **its own** authentication decision, on its own behalf, and no client relies on
the result. The two coexist, but the distinction must be written into the row so nobody "fixes"
either one.

## 4. What it costs, and the residual it creates

**It weakens revocation for a stolen device.** An attacker holding an unlocked device holds the
account key, so they can re-authenticate after a mass revoke. Today they cannot.

That is the real trade and it needs the operator's decision. Three ways to take it:

| Option | Effect | Cost |
|---|---|---|
| **A1 — accept it** | Revocation stops *token theft*, not *device theft* | Honest, but a stolen device is the scenario people reach for revocation for |
| **A2 — account freeze flag** | Operator can mark an account unable to re-authenticate | Server-side state that can deny a specific user service: a censorship lever in a design that currently has none |
| **A3 — freeze with self-service unfreeze** | Freeze is per-account and reversible only by the operator | Same lever, plus a support burden with no support channel |

**Recommendation: A1, stated plainly in `AUDIT.md`.** An attacker with an unlocked device already
holds the libsignal identity private key, so they can already impersonate the account in the
protocol; re-authentication does not widen that adversary, it only makes an existing capability
easier to see. A2 introduces a mechanism whose abuse case (an operator silencing one member) is worse
than what it prevents, in a five-person circle where the operator is also a participant.

**It does not weaken "lose the device, lose the account"** (`BACKEND.md` §6), because the account key
is device-only and non-syncing. That property must stay true, because the UI states it.

## 5. What this explicitly does **not** fix

**AUDIT 3.9.** I need to correct something I wrote into the plan: the new **P10.S06** row says a
re-authentication design "would serve both". **That is wrong and should be amended.** 3.9 needs
*unauthenticated delivery* — the relay must not learn who is sending. Re-authentication is still
authentication: every send still carries a bearer token and the relay still sees sender and recipient
in one request. Signal solves 3.9 with an access key derived from the recipient's **profile key**,
which Cipher does not have. It is a genuinely separate design and P10.S06 should say so.

The two rows share a *symptom* — "the session token is the only credential" — not a solution.

## 6. Knock-on effects if Change A ships

- **4.16 could be retired rather than accepted.** If a device can re-authenticate by proving key
  possession, `session_tokens` no longer has to be in the backup, which removes the
  revocation-resurrection residual entirely and shrinks the backup to `accounts` alone.
- **The incident runbook's §8 changes shape.** Mass revoke becomes a real control — disruptive, but
  survivable — instead of "disband the circle". `RUNBOOK-INCIDENT.md` would be rewritten in the same
  change.
- **5.41 closes** on Change A; Change D alone only narrows it.

## 7. Verification this would need

Not a sketch — the gates it must arrive with:

- Negative tests for each refusal: wrong signature, replayed challenge, expired challenge, challenge
  bound to a different `aci`, and an unknown `aci` — each reintroduced in the real source and shown
  to fail by name.
- An integration test that an unknown `aci` and a wrong signature are byte-identical in response, so
  the endpoint cannot become an existence oracle.
- A test that the account key's private half never appears in any relay request body, mirroring the
  existing key-boundary discipline.
- Relay integration suite required-name additions, and the `verify-identity-fields.py` gate re-run,
  because a new account column is exactly what that gate watches.

## 8. Decision requested — answered 2026-08-13

The four questions below were the ones put to the operator. The answers are recorded here so this
document cannot be read as still waiting on them; the roadmap rows and `AUDIT.md` own what was
built.

1. **Change D** (client-only, stops silent history loss) — approve as its own small step? It is
   independently valuable and I recommend it regardless of the answer to 2.
   - **Approved.** Shipped as **P9.S10**. It found a second path into the same defect that this
     document did not name: the messaging layer's `sessionRejected` handler also called `signOut()`,
     so any 401 destroyed local state, not only one at rotation.
2. **Change A** (Ed25519 account key) — approve as a design, reject, or redirect?
   - **Approved as designed.** Shipped as **P9.S11**, relay and client together.
3. If A is approved: **A1, A2, or A3** for the revocation trade in §4? My recommendation is **A1**.
   - **A1.** The residual is accepted rather than answered with an operator freeze flag, whose abuse
     case is worse than what it prevents. `AUDIT.md` 5.41 states it without softening.
4. **P10.S06's wording** should be amended to drop the "would serve both" claim (§5), whatever else
   is decided.
   - **Done**, in the plan, before either change shipped.

**5.41 is CLOSED in the repository and not yet on the staging relay.** The one thing this document
did not foresee is **5.42**: the per-account limit that P9.S11 put on the verify route is keyed on an
`aci` an unauthenticated caller supplies, so a chosen account's recovery budget can be spent by
anyone who knows it. §4 weighed the *stolen device* residual and not that one.
