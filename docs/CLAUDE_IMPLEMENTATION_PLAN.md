# Cipher — implementation plan

Chronological, agent-executable roadmap from the current prototype to a private-circle production
E2E messenger.

**Companions:** [`README.md`](README.md) (document authority),
[`THREAT_MODEL.md`](THREAT_MODEL.md) (who we defend against), [`AUDIT.md`](AUDIT.md) (what is
broken), [`BACKEND.md`](BACKEND.md) (relay protocol), and
[`../Vendor/libsignal/DECISIONS.md`](../Vendor/libsignal/DECISIONS.md) (dependency decisions).

**Working here?** The root [`CLAUDE.md`](../CLAUDE.md) is the permanent behavioral
contract. [`README.md`](README.md) defines document authority and reading order, while
[`AGENT_HANDOFF.md`](AGENT_HANDOFF.md) is the stable human-readable execution guide. This file
owns current product status and the normative roadmap; per-step evidence belongs in
[`STEP_NOTES/`](STEP_NOTES/).

**Priority order:** security > correctness > reliability > maintainability > features > UI polish.

---

## STATUS

This is the canonical product-roadmap snapshot. Verify mutable repository, CI, test, dependency,
deployment, and operator state from their executable or live sources before acting.

| Field | Current status |
|---|---|
| Phase | P5 in progress; P1–P4 complete. |
| Completed P5 product steps | P5.S01, P5.S02, P5.S05, P5.S06, P5.S08, P5.S09, P5.S10, and P5.S11. |
| Security-remediation queue | The approved queue (5.26, 5.27, 1.14, 6.14, and 6.13 with it) is empty. **Two P5-scoped findings were never in it and are still OPEN: AUDIT 5.28** (relay lifecycle and deployment controls) **and 5.29** (the staging HTTP vhost's access log). Neither is approved work; queue them explicitly or record why they wait. `AUDIT.md` is authoritative. |
| Next planned feature | P5.S12 safety numbers, followed by P5.S13 two-device staging verification. The remediation work that preceded them is done. |
| Open and accepted risk | `AUDIT.md` is authoritative. Read every applicable OPEN and ACCEPTED row; this table never overrides it. |
| Repository and PR state | Derive from Git and the current GitHub pull-request list. Never copy an “unmerged branch” into this plan. |
| Staging and operator state | `RUNBOOK-VPS.md` owns procedures and its state table; live read-only checks win. Do not duplicate host, certificate, DNS, or pending-operator snapshots here. |
| Verification state | Derive gate count from `Scripts/verify-all.sh` and test totals from a fresh run. A copied total is not evidence. |

Before selecting or creating a branch, inspect at least:

```sh
git status --short --branch
git log --oneline --decorate -10
git branch -vv
```

Check relevant open pull requests through the authenticated GitHub surface currently available. The
approved step determines whether to continue an existing branch or create a new focused `codex/`
branch from current `main`.

Do not append implementation narratives to this block. Record durable completion in the roadmap row,
security invariants and finding status in `AUDIT.md`, operational evidence in the runbook, and
detailed test/negative-test evidence in a step note or Git history.

---

## How to use this plan

1. Complete one step fully — code, tests, docs — before starting the next.
2. Every step has a **`Done when`** that is an *observable*: a command that exits 0, a named test, or
   a file that exists. If you cannot demonstrate it, the step is not done.
3. Step IDs (`P4.S03`) are **stable**. Inserting a step never renumbers others. Cite them in commits
   and in `AUDIT.md`.
4. After any crypto or auth change: `Scripts/verify-all.sh` (from P1.S08 onward).
5. After any dependency or pin change: `Scripts/verify-supply-chain.sh`.
6. Move an `AUDIT.md` item to CLOSED **only** when a tested control exists. Downgrading to "probably
   fine" is not closing it.
7. Never ship deceptive security UI. Unfinished control ⇒ remove it, disable it, or label it
   "not implemented" in DEBUG only.
8. **Human vs AI ownership** is marked per step. Claude must not purchase domain/VPS. Claude may
   prepare configs and, once the human provides access, perform setup.

---

# P0 — Standing context (read once; obey always)

## 0.1 Project reality

- **CipherCrypto:** the sole cryptographic boundary, using the pinned LibSignalClient and CryptoKit;
  no custom cryptography. Manifests and `Vendor/libsignal/PINS.env` own current versions.
- **App (`Cipher/`):** authenticates with a relay-issued credential and routes messages through
  `ConversationStore` → `MessageRepository` → `CryptoEngine`, pinned relay transport, and sealed
  local persistence. Production `MockStore` paths are gone.
- **Relay (`server/`):** a Go store-and-forward service whose message content is ciphertext-only;
  its authenticated directory also stores public identity and prekey material. `BACKEND.md` owns
  its protocol; code and migrations own mechanics.
- **Operations:** staging exists, but deployment, certificate, DNS, and operator state are mutable.
  `RUNBOOK-VPS.md` plus live read-only checks are authoritative.
- **Verification:** CI and local development execute `Scripts/verify-all.sh`. Derive the current
  gates, tests, builds, and toolchain from scripts, fresh output, manifests, and lockfiles.
- **Readiness:** Cipher is not production-ready while P5 and the OPEN findings in `AUDIT.md` remain.

## 0.2 Locked protocol decisions (do not "fix" these)

Argued in code and in `AUDIT.md`. **Requirements, not bugs.**

1. **Identity change (AUDIT 3.2 — ACCEPTED)**
   - **Receiving** with a changed peer identity is **trusted** (messages still decrypt/accept).
   - **Sending** is **refused** until `acceptIdentity` names the **exact** key the user was shown.
   - Rationale: refusing receipt drops messages silently and trains users to ignore the warning;
     refusing sending is the direction that actually protects.
2. **Groups / SenderKeyStore (AUDIT 3.7 — ACCEPTED)** — `SenderKeyStore` deliberately unimplemented;
   group/sender-key payloads rejected at the wire boundary. No untested sender-key state may be
   reachable. Groups only in P10.
3. **`Envelope.sender` is untrusted routing metadata** — attribute messages to the session that
   successfully decrypted, never to this field.
4. **`PlaintextContent` / `DecryptionErrorMessage` refused at the wire boundary** (AUDIT 3.5 —
   CLOSED). Session resets must travel as plaintext *inside* an ordinary encrypted message.
5. **Single device only** for wire v1 (no `deviceId`). Multi-device requires `wireVersion` 2 —
   design later, do not sneak it in.
6. **Keychain `AfterFirstUnlockThisDeviceOnly` + non-synchronizable** (AUDIT 2.1 — ACCEPTED). Do not
   "tighten" to `WhenUnlocked` without an NSE + notification-content redesign.
7. **Invite-code-only identity** (THREAT_MODEL §3.4 — ACCEPTED) — Cipher collects **no phone
   number, no email address, no server-side username, and no verification code**. An account comes
   into existence only by redeeming an invite code, and the `aci` the server mints at redemption is
   an opaque UUIDv4 with no link to a person. Adding a "sign in with email", an SMS verification
   step, or a lookup-by-handle is a threat-model change, not a feature.
   - **Rationale.** An identifier that is never collected cannot be leaked, correlated against
     another service, subpoenaed, or used to enumerate the user base — which is why `BACKEND.md`
     §2.1 lists `display_name`, `username` and `about` under **"Absent on purpose"** and why the
     `aci` row says an opaque identifier "with no link to a person, phone, email, or device … is
     the whole point of §3.4". It also removes server-side contact discovery entirely, historically
     the largest metadata leak in messengers that have it. And a phone or mail flow would put a
     **third party** inside a design that has none: an SMS or mail provider learns who signed up,
     when, and from where, and is itself seizable under §1.1 — an adversary Cipher's own controls
     (pinning, E2E) do not reach, because the leak happens before any of them apply.
   - **Not in scope, deliberately:** the *local* profile — display name, username, "about" — is
     client-side only, sealed by `ProfileArchive`, and never sent anywhere. This decision is about
     what Cipher **collects**, not what someone types for themselves.

**Enforced, not merely documented.** `CipherCryptoTests/LockedDecisionsTests.swift` fails if any is
quietly "fixed", with a message saying why it was that way. Its header table maps each decision to
the test pinning it. Decisions 1 and 6 were already covered behaviourally (`ProtocolStoreTests`,
`KeychainTests`); 2–5 and the wire half of 7 are pinned there. Conformance, predicate and
reflection checks carry positive controls, so a check that stops working fails loudly instead of
passing vacuously.

Decision 7 needs a second enforcer, because most of its surface is outside `CipherCrypto` and no
Swift unit test can reach it: the account model, the auth API and the relay schema are Go and SQL.
[`Scripts/verify-identity-fields.py`](../Scripts/verify-identity-fields.py) is that half — it refuses an
identity-shaped field name in those four surfaces, strips comments first so it does not fire on the
prose describing the decision (AUDIT **R3**), and carries positive controls so a blinded scanner
fails instead of reporting a clean tree it never read (AUDIT **R2**).

## 0.3 Genuinely OPEN items

| AUDIT | Item | Closes in |
|-------|------|-----------|
| 3.8 | First-contact address is relabellable by the relay | P5.S12 / P7 |
| 4.4 | NSE/App Group sharing is not approved or cross-process tested; Keychain sharing still needs a migration and rollback design | P6 |
| 2.4 | No key rotation / replenishment | P6.S01 |
| 2.5 | No safety-number UI | **P5.S12** (moved from P6) |
| 3.1 | Base-key witness FIFO eviction | P4.S06 + P6.S01, resolved P6.S02 |
| 5.1 | Messaging works, but only against a stub — not yet device to device | P5.S13, closed P5.S14 |
| 6.2 | Acknowledgements not in About screen | P8.S07 |
| 6.3 | `ITSAppUsesNonExemptEncryption` undeclared | P8.S06 (legal) |

## 0.4 Test hosting constraint (AUDIT 6.6 — ACCEPTED)

- Crypto tests run **hosted by the app**. A host-less bundle has no Keychain access group → every
  `SecItem` returned `-34018`, so Keychain would have had zero coverage.
- Bundle-level entitlements do **not** work on simulator SDKs (`ENTITLEMENTS_REQUIRED = NO` ⇒
  `CODE_SIGN_ENTITLEMENTS` silently ignored).
- **Costs:** a broken app target blocks the security suite; concurrent `xcodebuild` against one
  simulator fails preflight (`RequestDenied … Busy`).
- **Rule:** serialize test runs per simulator. Never parallelize two `xcodebuild test` invocations on
  the same simulator. `Scripts/verify-all.sh` enforces this.

## 0.5 Critical findings that must die before any "secure" claim

| ID | Problem | Verified at | Closes in |
|----|---------|-------------|-----------|
| C-01 | Invite auth was client-side; `AuthFlowView` gated on `count >= 4` and set a Bool. **CLOSED 2026-07-30 (P5.S09):** the code is redeemed against the relay and only a server-issued token authenticates. AUDIT 5.18. | closed 2026-07-30 | P3.S01 + P5.S09 |
| C-02 | Messaging path was plaintext `MockStore` with no encrypt/decrypt façade. **CLOSED 2026-07-30 (P5.S10):** nothing leaves the device that `CryptoEngine.encrypt` did not produce, nothing is stored outside the sealed container, and `MockStore` no longer exists. AUDIT 5.3. | closed 2026-07-30 | P2.S01 + P5.S10 |
| C-03 | App lock Unlock/Passcode call `session.unlock()` with no `LAContext` (`AuthFlowView.swift:204,209`) while `:196` promises "Unlock with Face ID" | **CLOSED 2026-07-28** | P3.S02 |

## 0.6 Non-negotiable engineering rules

- Do **not** invent cryptography. LibSignalClient + CryptoKit only.
- Server stores/relays message content **only as ciphertext**, never plaintext. It intentionally
  stores public identity and prekey material; private E2E identity, prekey, session, and ratchet
  keys never leave the device. Server-side TLS private keys and service secrets are a separate
  operational custody domain. Never log secrets, tokens, invite codes, safety numbers, raw
  `ProtocolAddress`, or message content.
- Prefer fixing deceptive UI over adding features.
- Keep `AUDIT.md` honest.
- **Obey every standing prohibition in `THREAT_MODEL.md` §4** — no analytics, no third-party SDKs,
  no IDFA, no server-side contact discovery, no plaintext-capable crash reporting, no phone/email
  identifiers.

---

# P1 — Honesty, gates, and repo hygiene

**Goal:** stop lying to users; make security gates enforceable; leave a clean baseline.
**Preconditions:** none — this is the entry point.
**Read first:** this plan, `THREAT_MODEL.md`, `AUDIT.md`, `Vendor/libsignal/DECISIONS.md`,
`CryptoEngine.swift`, `Envelope.swift`, `AppSession.swift`, `ConversationStore.swift`.
**Buy domain/VPS?** **No.** No server code to deploy.
**Privacy regression check:** none — no new data leaves the device this phase.

| ID | Step | Owner | Closes | Done when | Do not |
|----|------|-------|--------|-----------|--------|
| **P1.S01** | Read the baseline docs above before writing any code. | AI | — | You can state, without re-reading, what §0.2 locks and why | Start coding first |
| **P1.S02** | Fix the `AUDIT.md` wording conflict: row 1.3 credited a CI check for re-resolving the libsignal tag while row 1.6 states there is no CI. Align to reality — the check exists in `verify-supply-chain.sh`, but nothing enforces it. | AI | — | No row in `docs/AUDIT.md` credits CI with enforcing anything while 1.6 is OPEN | Claim a control that does not exist |
| **P1.S03** | Resolve the dangling `.rtf` master-plan reference — the file does not exist in the repo. Either add it or drop every citation. The P9.S07 pen-test checklist is inlined in this document regardless, so nothing depends on it. | AI | — | Every `.rtf` path cited anywhere in `docs/` resolves on disk, or no `.rtf` is cited at all (this step's own description does not name one) | Leave a phantom source of truth |
| **P1.S04** | **Put the work under version control.** Diagnosed 2026-07-28: the repo has one commit tracking 8 files. `CipherCrypto/`, its tests, `Scripts/`, `docs/` and most of the app are untracked (75 files), as is `Pods/` (187 files, 2.4 MB, no binaries — the Rust `.a` is fetched and checksum-pinned at build time). Nothing ignores Pods; they were simply never committed, so the diff-review control `.gitignore:23` describes has never existed. Commit the tree, Pods included, or change the policy in `.gitignore` + `DECISIONS.md` deliberately. **Done 2026-07-28** on the user's instruction: 271 files committed, Pods included; `Vendor/bundle/` case bug and the tracked `xcschememanagement.plist` fixed in the same commit. Still no remote — see P1.S10. | **HUMAN** (agent must not commit unasked) | 1.7 | `git ls-files \| wc -l` covers the crypto module, tests, Scripts, docs, and agrees with what `.gitignore` claims about Pods | Leave documented-but-absent; commit without being asked |
| **P1.S05** | **Deceptive security UI pass.** App lock: wire `LocalAuthentication` now or remove Face ID copy (`AuthFlowView.swift:196`, `SettingsViews.swift:311`) until P3. Safety numbers: hide "Mark as Verified" (`ChatInfoViews.swift:306`) and `Verified` badges until P5.S12. Disappearing messages / screenshot warning / notification previews: no toggle that implies enforcement it lacks. Remove hardcoded invite codes (`SettingsViews.swift:159`) from production paths — DEBUG fixtures only. | AI | part of C-03 | No Release-reachable string claims an unimplemented control; audited by reading each hit from the security-copy grep | Add features |
| **P1.S06** | **Group UI → `#if DEBUG`.** `MockStore.createGroup` and group creation flows contradict §0.2.2, which keeps groups cryptographically unreachable. Fence them out of Release; the screens survive for P10. | AI | — | `createGroup` unreachable in a Release build; `LockedDecisionsTests` still green | Delete the work; implement groups |
| **P1.S07** | **Remove every debug affordance from Release, and give the auth gate one home.** `UICatalogView` is correctly fenced, but the *mechanism* it drives is not: `debugSkipToMain` (`AppSession.swift:41,71`, `RootView.swift:14`) is a live auth-bypass boolean in a shipping binary, as are `resetDemoState()` and the destructive "Leave & Reset Demo" button. Fence the property and both consumers, not just the buttons. Then collapse the gate: `RootView` must ask `AppSession` rather than restating the condition. | AI | 5.6, 5.7 | Release binary contains no `UICatalogView` and no `debugSkipToMain` symbol; the "onboarded && authenticated && !locked" condition appears exactly **once** in the codebase | Fence only the buttons and leave the switch |
| **P1.S08** | **Write `Scripts/verify-all.sh`** — the standing regression checklist as one serialized, fail-fast command. Wrap the existing `verify-supply-chain.sh` and `verify-app-target-manifest.sh`; do not reimplement them. | AI | — | `./Scripts/verify-all.sh` exits 0 on a clean tree | Parallelize simulator use (§0.4) |
| **P1.S09** | **Add CI** running `Scripts/verify-all.sh` on every PR and on main. Supply-chain must **fail closed** on release jobs — not "pass" merely because the cache is absent. Optionally fail Release archives if DEBUG gates leak. **Corrected 2026-07-28** against `actions/runner-images`: the first draft would have died on its first substantive step (`macos-15` ships Xcode 16 and iOS 18 simulators; `/Applications/Xcode_26.app` exists on no runner; `setup-ruby` had no version to resolve). Now `macos-26`, Xcode selected from `PINS.env`, `.ruby-version` added, and a step that asserts a simulator runtime can satisfy the 26.5 deployment target — the runner ships 26.2/26.4/26.5, so two of three cannot install the app. Every step was extracted from the YAML and executed locally, including a negative test. | AI | — | The workflow's shell steps run green locally when extracted; YAML parses; runner assumptions match the published image manifest | Let CI pass on a skipped check; assert a runner fact without checking the image manifest |
| **P1.S10** | Close AUDIT 1.6 — only once CI actually runs the supply-chain script on every PR/main build. **Blocked: needs a git remote.** There is no `gh` CLI, no SSH key and no stored GitHub credential on this machine, so an agent cannot create the repository or authenticate; asking the user for a token is not an option either. Everything that can be verified without a remote has been. The user runs, from the repo root: `git remote add origin <url>` then `git push -u origin main` — the workflow triggers on `push` to `main` and on `pull_request`, and the current branch is `e2ee/m1-build-skeleton`, so pushing only that branch will *not* trigger it. Then confirm the run is green, make `verify` a required check on PRs, and mark 1.6 CLOSED. Public vs private is the user's call; note that GitHub Actions minutes are free for public repositories, while macOS runners bill at 10× against a private repository's allowance and this job can take ~30 minutes. | **HUMAN**, then AI | 1.6 | A `verify` run is green on `main` and the supply-chain check is required on PRs | Close it early; mark it closed on a workflow that has never executed |
| **P1.S11** | **PrivacyInfo enumeration (AUDIT 6.1):** libsignal ships no manifest, so its required-reason API usage must be enumerated and merged into `Cipher/PrivacyInfo.xcprivacy`. **Done 2026-07-28, in full rather than partially** — all five categories resolved, so P8.S05 has nothing left to finish. Scanning the app binary is a *false all-clear*: libsignal links as a dynamic framework, so its symbols live in `Frameworks/`, are never dead-stripped, and ship whether Cipher calls them or not. `docs/PRIVACY_MANIFEST.md` records the findings, the method's limits, and two judgement calls. | AI | 6.1 | `Scripts/verify-privacy-manifest.sh` exits 0 and fails when a declared category is removed; `docs/PRIVACY_MANIFEST.md` gives every category a verified status | Guess at categories; scan only the app binary |
| **P1.S12** | **Stop the Release bundle naming its own debug affordances.** Found 2026-07-28 while re-checking P1.S05: `#if DEBUG` fences code, but `Localizable.xcstrings` is a resource. Xcode drops `extractionState: stale` keys from `en.lproj` and emits every translated `stringUnit` anyway, so `cs.lproj` shipped "Skip to App", "Unlock & Show Main", "Demo Controls", "UI Catalog", "Reset Onboarding" and "Leave & Reset Demo" into Release — and the P1.S07 audit missed it by searching only the Mach-O executable. Strip the debug-only translations, widen the audit to the whole `.app`, and replace the shell UI-honesty lint with a checker that understands `#if DEBUG` and matches claims anywhere in a string in any language. | AI | 5.11 | `Scripts/verify-localization.py --self-test` and the plain run both exit 0; `verify-all.sh` step 8 greps the whole bundle and was shown to fail against the pre-fix build | Fix the strings without fixing the gate that missed them |

**Exit criteria** — all must hold:
- [ ] `./Scripts/verify-all.sh` exits 0
- [ ] CI green on main; supply-chain verify is a required check
- [ ] No production UI claims an unimplemented crypto/auth control, **in any language**
- [ ] `AUDIT.md` CI wording fixed; 1.6 CLOSED or honestly OPEN; 1.7 resolved
- [ ] Groups unreachable in Release
- [ ] Nothing in the Release `.app` — code *or* resource — names a debug affordance
- [ ] Every required-reason API in the shipped bundle is declared (AUDIT 6.1)
- [ ] The full current test suite passes, including every `LockedDecisionsTests` case

---

# P2 — Crypto messaging façade (still offline)

**Goal:** `CryptoEngine` can establish sessions, encrypt, and decrypt correctly. **No network.**
**Preconditions:** P1 exit criteria met.
**Read first:** `CryptoEngine.swift`, `CipherProtocolStore.swift`, `Envelope.swift`,
`ProtocolStoreTests.swift`.
**Buy domain/VPS?** **No.**
**Privacy regression check:** none — still offline.

| ID | Step | Owner | Closes | Done when | Do not |
|----|------|-------|--------|-----------|--------|
| **P2.S01** | Design the single audited messaging API on `@CryptoActor CryptoEngine`, keeping LibSignalClient internal: process prekey bundle / start session; encrypt → ciphertext + `Envelope`; decrypt `Envelope` → plaintext with **session-bound sender attribution**; documented error/replay/duplicate policy. All store mutations go through `CipherProtocolStore`. | AI | C-02 (part) | Public API compiles with no LibSignalClient type in its signature | Leak libsignal types across the boundary |
| **P2.S02** | Encrypt/decrypt round-trip tests: golden vectors + restart persistence. | AI | — | New tests green; a session survives a store reopen | — |
| **P2.S03** | Tests where envelope sender metadata **disagrees** with session identity — attribution must follow the decrypted session (§0.2.3). | AI | — | A test proves a rewritten `Envelope.sender` does not change attribution | Trust the field |
| **P2.S04** | Keep sender-key/group wire types failing closed. **Done 2026-07-28** — extended past the wire type to the façade: `testGroupAndUnknownPayloadTypesAreRefusedByTheFacade` sweeps every discriminator 0–16 outside the two live ones through `CryptoEngine.decrypt`, and then proves the session still works, so a refusal cannot have half-consumed a prekey or stepped the ratchet on the way out. | AI | — | `LockedDecisionsTests` still green | Implement groups |
| **P2.S05** | Preserve the identity-change policy through the façade (receive OK, send blocked until exact `acceptIdentity`). Extend tests if the façade touches trust paths. | AI | — | `testChangedIdentityBlocksSendingButNotReceiving` still green via the façade | Soften either direction |
| **P2.S06** | Harden store edges: max record size before `Data(contentsOf:)`; canonicalize peer-identity flags (reject unknown bits); crash/failure injection for multi-record Signal ops and `destroyAllState` ordering (durable reset marker if needed). **Done 2026-07-28** in `StoreEdgeTests`: a 1 MiB ceiling checked from `.fileSizeKey` *before* the read (`Data(contentsOf:)` allocates whatever it finds, so an oversized file in a slot was an unauthenticated memory-exhaustion DoS), re-checked after in case the size changed; unknown peer-identity flag bits now refused rather than dropped, swept bit by bit with a positive control. **Corrected 2026-08-01 (P5.S11 remediation):** the original interrupted-destroy guard encoded the wrong invariant by accepting ciphertext deletion while the Keychain survived. Erasure now deletes the Keychain service first and refuses to mint a replacement key beside surviving ciphertext; both interruption directions are negative-tested. The multi-record transaction problem was later closed for the live receive path by P5.S10/P5.S11; the remaining NSE boundary stays in AUDIT 4.4. | AI | — | Tests cover oversize, unknown-flag, and both interrupted-destroy boundaries | — |
| **P2.S07** | **Design note only** on App Group / NSE sharing: a transactional store is required before any extension decrypts. Do not implement sharing. **Done 2026-07-28** — AUDIT 4.4 names all three blockers: no multi-record transaction (per-file atomicity is not enough; one decrypt touches session, prekey and witness), no cross-process lock that survives the holder being killed, and a Keychain item with no access group, which is a decision to take deliberately rather than a side effect of adding an extension. | AI | — | Note exists in `AUDIT.md` or `DECISIONS.md` | Add an App Group or shared Keychain group |
| **P2.S08** | *Optional* DEBUG-only UI spike: one screen that encrypts/decrypts via `CryptoEngine`. **Skipped 2026-07-28.** `MessagingTests` already drives the façade end to end against libsignal's own store, which is a stronger check than a screen; a DEBUG screen would add a second call path into the crypto module whose only purpose is to be looked at, and P1.S07 exists because DEBUG affordances leak. The real wiring is P5.S10. | AI | — | Unreachable in Release | Let it become the production path |

**Exit criteria:**
- [ ] Façade exists; no app production path required yet
- [ ] Round-trip, attribution, and identity-change tests green
- [ ] Groups still unreachable
- [ ] `AUDIT.md` updated for new APIs; 5.3 still OPEN until P5

---

# P3 — Real client auth gate & app lock

**Goal:** kill C-01/C-03 locally as far as possible; stop using `UserDefaults` as a security boundary.
**Preconditions:** P2 exit criteria met.
**Read first:** `AppSession.swift`, `AuthFlowView.swift`, `SettingsViews.swift`, `THREAT_MODEL.md` §1.4.
**Buy domain/VPS?** **No.** You may *decide* provider and registrar names; do not pay.
**Privacy regression check:** confirm no new PII enters `UserDefaults`.

| ID | Step | Owner | Closes | Done when | Do not |
|----|------|-------|--------|-----------|--------|
| **P3.S01** | Replace `AppSession` security flags. `isAuthenticated` must not be a `UserDefaults` bool. Introduce the Keychain-backed session-credential **shape** now (absent token ⇒ logged out), even though server redemption lands in P5.S09. Non-security onboarding prefs may stay in `UserDefaults`. | AI | C-01 (part), 5.2 (part) | Editing `UserDefaults` cannot produce an authenticated state; test proves it | Ship a fake token |
| **P3.S02** | Implement the real app lock with `LocalAuthentication` (`.deviceOwnerAuthentication`). Unlock/Passcode must **fail closed** on cancel or error. **Re-lock on `scenePhase` change** — today `lockIfNeeded()` has exactly one caller, a manual button, so the lock engages only on cold launch (AUDIT 5.8). Remove the fake Face ID copy and re-enable the feature disabled in P1.S05. | AI | C-03, 5.8 | A test proves `unlock()` is unreachable without an `LAContext` success, **and** that backgrounding re-locks when the lock is enabled | Treat cancel as success; ship a lock that only works at launch |
| **P3.S03** | Clipboard policy: message copy uses an expiring / local-only pasteboard where supported; disclose the residual risk. | AI | — | Copy path sets expiry; risk documented | Claim clipboard safety |
| **P3.S04** | App-switcher / capture honesty: blur or redact on resign-active. Keep a screenshot "warning" **only** if it actually observes capture — otherwise remove it. | AI | — | Snapshot redaction verified; no unbacked warning remains | Fake detection |
| **P3.S05** | Move display name / username / about out of `UserDefaults` as sensitive storage (full encrypted datastore may wait for P5.S11); at minimum stop treating it as secure. | AI | — | No PII in `UserDefaults` presented as protected | — |
| **P3.S06** | Close AUDIT 5.2 once `UserDefaults` is no longer the auth/lock gate and the `LAContext` lock is tested. | AI | 5.2 | AUDIT 5.2 CLOSED with the tests named | Close early |

**Exit criteria:**
- [ ] C-03 closed
- [ ] AUDIT 5.2 closed
- [ ] UI cannot unlock without `LAContext` success
- [ ] `./Scripts/verify-all.sh` exits 0

---

# P4 — Backend design + local Docker

**Goal:** specify and implement a **local** zero-knowledge relay. Prove the API on localhost before
spending money.
**Preconditions:** P3 exit criteria met.
**Read first:** `THREAT_MODEL.md` (all of it — this phase is where it bites), `Envelope.swift`.
**Buy domain/VPS?** **Still no.** Develop against `localhost` / Docker Compose.
**Privacy regression check:** every column added to the schema must be justified against
`THREAT_MODEL.md` §1.1. If a seized database would reveal it, it needs a reason to exist.

| ID | Step | Owner | Closes | Done when | Do not |
|----|------|-------|--------|-----------|--------|
| **P4.S01** | Write `docs/BACKEND.md`: Go service modules (invite auth, session tokens, prekey directory, message inbox, attachment blob metadata, health); PostgreSQL schema with ciphertext-only message content and an explicit public-key directory; Redis TTLs for ephemeral delivery only; threat model vs compromised VPS citing `THREAT_MODEL.md`; **retention policy (§3.1)**; **rate limits, especially prekey fetch**; no admin API by default. | AI | — | `docs/BACKEND.md` exists and every table column has a stated justification | Design an admin backdoor |
| **P4.S02** | Scaffold the Go module + Docker Compose (Postgres + Redis + API) runnable on a dev machine. | AI | — | `docker compose up` serves `/health` | Expose Postgres/Redis to the host network |
| **P4.S03** | Invite codes: server-generated, single-use, expiring, rate-limited. | AI | C-01 (part) | Integration test: reuse rejected, expiry enforced, brute force throttled | Hardcode codes |
| **P4.S04** | Opaque session tokens: random, hashed at rest, rotatable, revocable. | AI | — | Token never stored in plaintext; revocation test green | Use a JWT holding claims we cannot revoke |
| **P4.S05** | Prekey upload/download requiring PQ/Kyber material consistent with the client contract tests. | AI | — | Non-PQ bundle rejected by the server | Accept a classic-only bundle |
| **P4.S06** | **Prekey-fetch rate limiting — mandatory, not optional.** This is the real mitigation for base-key witness eviction (AUDIT 3.1); it is nearly free while writing the endpoint and expensive to retrofit under load. | AI | 3.1 (part) | Integration test: fetch flood is throttled | Defer to P6 |
| **P4.S07** | Message relay: store and forward envelopes. The server must not interpret ciphertext beyond size and type checks. | AI | 5.1 (part) | Relay round-trip via curl/integration test | Parse into the ciphertext |
| **P4.S08** | **Delete-on-delivery + TTL sweep.** Delete a message the instant delivery is acknowledged; sweep undelivered messages on a TTL. No archive, no soft-delete flag. Per `THREAT_MODEL.md` §3.1 this is the highest-value server control. | AI | — | Test: after ack, the row is **gone**, not flagged; TTL sweep removes stale undelivered rows | Add a "just in case" archive |
| **P4.S09** | Attachment slot API: client encrypts first; server stores opaque blobs with size limits. | AI | — | Server rejects oversize; stores no content type it trusts | Content scanning theatre |
| **P4.S10** | Integration tests: malicious envelope rewrite, replay, auth failures, rate limits, **retention** — all against Docker. | AI | — | Suite green in CI | — |
| **P4.S11** | Redacted structured logging; **no IP retention beyond a short operational TTL**, no request bodies (`THREAT_MODEL.md` §3.6). | AI | — | Log review finds no token, invite code, push token, or IP beyond TTL | Log "just for debugging" |

**Exit criteria:**
- [ ] `docker compose up` runs a working relay locally
- [ ] Invite → token → prekey → send/receive ciphertext works end-to-end
- [ ] Schema review confirms **zero** plaintext message columns
- [ ] Delivered messages are provably deleted, not archived
- [ ] Prekey fetch is rate limited
- [ ] Still no production host

---

# P5 — Purchase window, staging infra, client transport, and the first real messages

**Goal:** move from localhost to staging and wire the client to it — with pinning, safety numbers,
and an encrypted local database **from the first real message**.
**Preconditions:** P4 exit criteria met. Do not start 5.A before then.
**Read first:** `docs/BACKEND.md`, `THREAT_MODEL.md` §1.1 and §1.3.

> **Why safety numbers and the encrypted DB moved here from P6:** this phase is where real messages
> first exist. Without the safety-number UI the send-block policy is invisible exactly when it first
> matters — the user is blocked with no way to see *which key* to accept. Without the encrypted
> database, real messages land in plaintext at rest and migrating a populated plaintext DB later is
> strictly harder than starting encrypted.

## 5.A Purchase and staging setup

| ID | Step | Owner | Done when | Do not |
|----|------|-------|-----------|--------|
| **P5.S01** | **Buy the domain.** Needed now for TLS certificates and to mint the pins the app ships. Registrar lock + WHOIS privacy. Prefer a boring, dedicated domain. | **HUMAN** | Domain registered and locked | Buy earlier (wasted renewal) |
| **P5.S02** | **Buy the staging VPS**, same day or immediately after. Hetzner / OVH / DigitalOcean — jurisdiction is a real criterion (`THREAT_MODEL.md` §3.7). 1–2 vCPU, 2–4 GB is enough. | **HUMAN** | VPS provisioned | Buy before P4 exit; use it for production |
| **P5.S03** | **Provide access material out of band** — never committed: VPS SSH access and the chosen hostname. DNS changes remain operator-owned while no registrar API credential exists. ACME registration intentionally uses no email (`RUNBOOK-VPS.md` §H.3). | **HUMAN** | Claude has the non-secret access and public hostname needed for approved work | Paste secrets into the repo or chat history; add an unused registration email |
| **P5.S04** | DNS: A/AAAA for the API host; CAA restricting CAs; DNSSEC if supported; no unnecessary public records. | AI-after-access | `dig` shows the expected records | Create wildcards |
| **P5.S05** | VPS hardening + staging deploy: Ubuntu LTS, key-only SSH, no password auth, firewall (22/80/443 only — **no Postgres/Redis exposed**), unattended security updates, minimal packages, non-root Docker, Nginx + **TLS 1.3** + ACME, HSTS (carefully on staging), fail2ban. Secrets via env/files **not in git**. Procedure and observed results: [`RUNBOOK-VPS.md`](RUNBOOK-VPS.md). **DONE 2026-07-29, all stages.** Exit criterion met on both address families. Three latent misconfigurations found and closed on the way: AUDIT 4.8, 5.15, 5.16. | AI-after-access | External port scan shows only 22/80/443 | Expose the database |
| **P5.S06** | Document the pin set: extract SPKI/pin hashes for the staging leaf/intermediate; write the pin-rotation runbook stub in `docs/BACKEND.md` (created in P4.S01). **DONE 2026-07-29.** All five chain SPKIs extracted and recorded in `BACKEND.md` §9.1, but only the **leaf and the backup key are pinned** — the intermediate is recorded and deliberately *not* pinned, because a pin set is only as strong as its weakest accepted pin and accepting the LE intermediate accepts any certificate LE issues for the host, which an attacker passing ACME validation can obtain. Runbook now covers routine renewal, planned rotation (two releases), key compromise, both-keys-lost, and host moves. `Scripts/verify-pins.sh` checks the served SPKI against the recorded pins and that `reuse_key` is still set; negative-tested three ways. | AI-after-access | Pins recorded with a rotation procedure | Ship a pin with no rotation plan |
| **P5.S07** | Review SSH exposure, DNS, and that no secrets landed in the repo. | **HUMAN** | Reviewed | — |

## 5.B Client transport and the first real message path

| ID | Step | Owner | Closes | Done when | Do not |
|----|------|-------|--------|-----------|--------|
| **P5.S08** | iOS network client: HTTPS only, TLS 1.3, **certificate/public-key pinning** matching P5.S06, failing closed. Timeouts, retries with jitter. **DONE 2026-07-30.** `Cipher/Networking/`: `RelayEndpoint` (pins), `CertificatePinner` (+ `PinningSessionDelegate`), `RelayClient` (30 s request / 120 s resource, 3 attempts, full jitter, retries only idempotent requests and never a TLS failure). Chain validation runs **before** the pin, so a pin match can never stand in for validation. No ATS exception exists; TLS 1.3 is set via `tlsMinimumSupportedProtocolVersion`, which tightens rather than relaxes. **Hostile-response handling remediated 2026-08-05 (AUDIT 5.26):** response bodies are counted and cancelled at a derived ceiling, redirects refused so the bearer token cannot follow one, the whole call bounded against a monotonic deadline rather than one task, cancellation no longer reported as a TLS failure, the base required to be a bare origin, and fetch/acknowledge/publish responses and invite codes bounded before use. | AI | 5.1 (part) | Test: a wrong-pin server is refused | Add any ATS exception |
| **P5.S09** | Wire invite redemption + session token into the Keychain. **DONE 2026-07-30; lifecycle remediated 2026-07-31.** `InviteRedemption` exchanges a code once; the relay commits invite deletion, account and first token hash together. A versioned credential binds token, ACI, server expiry and persisted phase (`registering → profileSetup → active → destroying`). Registration/profile setup resume after crashes; only active + unexpired reaches main. Rotation begins seven days before expiry, is single-flight and non-retrying. Messaging refuses a credential/crypto ACI mismatch. Sign-out/expiry/rejection/legacy credentials gate on cryptographic erasure of all prior account state before a new invite is reachable. | AI | **C-01, 5.25, 4.13 account isolation** | Real server-issued, account-bound token gates access; interrupted registration and cleanup recover; prior-account history cannot cross sign-in | Retry invite or rotation; expose main before registration/cleanup completes |
| **P5.S10** | Replace production `MockStore` paths with a repository backed by `CryptoEngine` + network: encrypt before send, decrypt after fetch, persist ciphertext. **DONE 2026-07-30; receive durability remediated 2026-07-31.** `CipherCrypto` gained `MessagePayload`, published-key generation and the sealed app store; `Cipher/` gained the real directory/mailbox/archive/repository/store path. Ordering: durable local outgoing row → encrypt → transmit; **decrypt/ratchet + sealed incoming row in one SQLite transaction** → acknowledge; adopt → publish. A permanent wire/decrypt failure is acknowledged and dropped; any transaction failure rolls the ratchet back and is not acknowledged. The guard retries the exact envelope after a post-decrypt archive failure and must store it; the former first-attempt-only test was false assurance. Repository register/send/receive operations are FIFO-serialised across awaits and cancelled waiters are removed. | AI | **C-02**, 5.3, 4.12 | No production path reads `MockStore`; a failed archive commit leaves the envelope decryptable on retry | Leave a plaintext fallback or split decrypt/archive commits |
| **P5.S11** | **Encrypted local message database** (SQLite sealed under Keychain-backed keys, sharing the crypto queue and container rules). *Moved from P6.* **DONE 2026-07-30; protocol-record transaction extension 2026-07-31; erasure remediation 2026-08-01.** `SealedRecordDatabase` uses SDK SQLite; every value is AES-GCM sealed with slot AAD and HKDF subkeys of the existing record key. Peer ids are keyed blind indexes, never columns. Conversations, messages and profile remain queryable rows. `DatabaseRecordStore` places libsignal session/prekey/witness/trust state on the same connection, which lets P5.S10 make receive atomic. Existing sealed files migrate lazily after commit; authenticated tombstones prevent stale deleted files from resurrecting consumed keys, and failed legacy unlinks retry on open. Wrong-key open fails through the key-check row. Erasure is key-first and resumable without opening ciphertext; verified SQLite secure deletion, truncated WAL checkpoints and a one-time hygiene VACUUM remove logical-deletion residue; profile writes are latest-snapshot ordered and account-generation scoped. | AI | **4.3, 4.7, 4.12, 4.13** | No plaintext message/protocol record at rest; wrong key refused; deletion residue scrubbed; interrupted erasure and legacy cleanup recover | Ship a plaintext DB, mint a key beside orphaned ciphertext, or report a committed inbound ratchet as rolled back |
| **P5.S12** | **Safety-number / QR UI** from real identity keys (LibSignalClient Fingerprint APIs): persist verification tied to the fingerprint, invalidate on identity change, wire to the existing receive-OK / send-blocked policy. *Moved from P6.* | AI | 2.5 | Two devices show matching numbers; a substituted identity visibly changes them | Ship "Mark as Verified" that verifies nothing |
| **P5.S13** | Two-device end-to-end test via staging: register, exchange prekeys, send/receive real ciphertext. | AI + HUMAN | — | Real message delivered device-to-device | Test only in the simulator |
| **P5.S14** | Close AUDIT 5.1 / 5.3 once transport, auth, and the non-mock messaging path work on staging. | AI | 5.1, 5.3 | Both CLOSED with tests named | — |

**Exit criteria:**
- [ ] Domain + staging VPS owned and hardened
- [ ] TLS live; client pins **fail closed** on the wrong certificate
- [ ] Real invite auth end-to-end
- [ ] Two-party encrypted message via the server
- [ ] **C-01 and C-02 closed**
- [ ] **Safety numbers visible and correct on two devices**
- [ ] **No plaintext message body on the wire, in the server DB, or at rest on device**

---

# P6 — Rotation, disappearing messages, attachments

**Goal:** close the remaining half-delivered crypto UX and storage holes.
**Preconditions:** P5 exit criteria met.
**Buy anything?** Optional: APNs key setup (human). No second VPS.
**Privacy regression check:** does rotation or attachment handling add anything the relay can link?

| ID | Step | Owner | Closes | Done when | Do not |
|----|------|-------|--------|-----------|--------|
| **P6.S01** | Prekey rotation & replenishment (signed prekey, Kyber, one-time pool): client scheduler + server publish endpoints. The real mitigation companion to AUDIT 3.1. | AI | 2.4 | Pool replenishes below threshold; rotation observed across a restart | Reuse a consumed prekey id |
| **P6.S02** | With P4.S06 rate limiting and P6.S01 rotation both live, document the residual witness-eviction trade-off and only then move AUDIT 3.1 to CLOSED or formally ACCEPTED. | AI | 3.1 | AUDIT 3.1 resolved with rationale | Close it without both controls |
| **P6.S03** | Disappearing messages that **actually delete** — DB rows and media cache — enforced across restart and backgrounding. | AI | — | Test: relaunch after expiry finds no row and no cached media | Hide rather than delete |
| **P6.S04** | Attachment encrypt-before-upload end-to-end with AEAD and integrity checks; encrypted media cache wiped on delete/disappear. | AI | — | Server holds only opaque blobs; cache wipe tested | Upload then encrypt |
| **P6.S05** | Block list / device revoke — expose **only** UI that hits real server state. | AI | — | Mock `revokeDevice` gone; revoke observable server-side | Keep the mock revoke lie |

**Exit criteria:**
- [ ] AUDIT 2.4 closed
- [ ] AUDIT 3.1 closed or formally ACCEPTED with rate limiting **and** rotation in place
- [ ] Disappearing deletion tested across relaunch

---

# P7 — Metadata minimisation

**Goal:** reduce what a seized relay can prove. **Promoted out of the old Phase 9 backlog** because
the hostile/seizable-server model (`THREAT_MODEL.md` §0) makes this load-bearing, not optional.
**Preconditions:** P6 exit criteria met.
**Read first:** `THREAT_MODEL.md` §3.2, §3.3, §3.5.
**Privacy regression check:** this phase *is* the privacy check.

| ID | Step | Owner | Closes | Done when | Do not |
|----|------|-------|--------|-----------|--------|
| **P7.S01** | **Sealed sender.** libsignal already ships it (`Pods/LibSignalClient/swift/Sources/LibSignalClient/SealedSender.swift`), so this is wiring plus a server-issued sender-certificate scheme — **not new cryptography**. `Envelope`'s `wireVersion` + reserved type space exists precisely so this arrives without a wire break. | AI | 3.4 | Server cannot determine the sender of a relayed message; test proves it | Invent a certificate format |
| **P7.S02** | Length bucketing: pad ciphertext to fixed buckets before relay. `Envelope` caps at 64 KB, so the bucket set is bounded. | AI | — | Wire lengths take a small fixed set of values | Claim it defeats a global adversary |
| **P7.S03** | Push-token hardening: encrypt the replayable token under a service key held outside the database, rotate it, and delete it with the account. It is metadata that survives message deletion; encryption at rest does not defeat whole-host seizure (`THREAT_MODEL.md` §3.3). | AI | — | A database dump has no plaintext push token; rotation and account deletion are tested | Hash a token APNs must receive verbatim; let it outlive the account |

**Exit criteria:**
- [ ] AUDIT 3.4 closed or formally ACCEPTED with rationale
- [ ] A seized staging database cannot show who sent a relayed message
- [ ] `THREAT_MODEL.md` §1.1 residual row updated to match reality

---

# P8 — Push, privacy compliance, acknowledgements

**Goal:** content-free notifications; App Store / legal blockers cleared.
**Preconditions:** P7 exit criteria met.
**Privacy regression check:** APNs payloads must carry no message body and no names.

| ID | Step | Owner | Closes | Done when | Do not |
|----|------|-------|--------|-----------|--------|
| **P8.S01** | Create the APNs key/certs in Apple Developer; supply key id + `.p8` via a secret store. | **HUMAN** | — | Claude has the key out of band | Commit the `.p8` |
| **P8.S02** | Server APNs provider with **content-free / wake-only** payloads. | AI | — | Captured payload contains no body and no names | Include a preview |
| **P8.S03** | Client notification privacy: previews only after local decrypt, when unlocked and user-enabled. Default previews **OFF**. | AI | — | Default is off; toggle actually enforced | Default to on |
| **P8.S04** | Decide NSE necessity. If an NSE must decrypt: design App Group + Keychain access group + a **transactional** protocol store *together*. If not: keep the `AfterFirstUnlock` rationale documented, no shared group. | AI | — | Decision recorded in `AUDIT.md` with its consequences | Share Keychain/files without transactions |
| **P8.S05** | Re-verify the `PrivacyInfo.xcprivacy` enumeration against whatever libsignal version ships. P1.S11 closed 6.1 outright, so this is a re-check, not unfinished work — and `verify-privacy-manifest.sh` runs on every build, so a bump that introduces a category has already failed the build by now. Confirm the two judgement calls in `docs/PRIVACY_MANIFEST.md` still hold: the `C617.1` reason (breaks if anything ever hands libsignal a path outside our container) and `clock_gettime`/`gettimeofday` still being off Apple's list. | AI | 6.1 (re-check) | `Scripts/verify-privacy-manifest.sh` exits 0 against the release build, and both judgement calls are re-stated as still true in `PRIVACY_MANIFEST.md` | Assume last year's list |
| **P8.S06** | `ITSAppUsesNonExemptEncryption` determination — a legal call, not an engineering one. Claude adds the plist key only afterwards. | **HUMAN** → AI | 6.3 | Key present, decision recorded | Decide it yourself |
| **P8.S07** | In-app acknowledgements / licenses for libsignal (AGPL obligation 3 in `NOTICE.md`). | AI | 6.2 | About screen renders the pod's acknowledgements | — |
| **P8.S08** | Crash reporting: none, or a redacting pipeline that provably cannot upload plaintext or secrets. | AI | — | Decision recorded; no plaintext-capable reporter linked | Add a default SDK |

**Exit criteria:**
- [ ] AUDIT 6.1, 6.2 closed; 6.3 closed after the legal decision
- [ ] APNs content-free verified on staging
- [ ] Notification preview toggle actually enforced

---

# P9 — Production cutover, ops, pen-test

**Goal:** friend-circle production with ops discipline.
**Preconditions:** P8 exit criteria met.

| ID | Step | Owner | Done when | Do not |
|----|------|-------|-----------|--------|
| **P9.S01** | Buy/provision the **production** VPS, separate from staging, same hardening bar. | **HUMAN** | Provisioned | Reuse staging |
| **P9.S02** | Production deploy mirroring staging: separate secrets, separate DB, firewall, backups. | AI-after-access | Deployed and reachable | Share secrets with staging |
| **P9.S03** | Point production DNS; configure TLS and a **new pin set**; ship a client update trusting the prod pins, with a rotation strategy. | **HUMAN** + AI | Prod pins live; rotation documented | Reuse staging pins |
| **P9.S04** | Monitoring: metrics and alerts **without message content** — cert expiry, disk, auth anomalies, error rates. | AI | Alerts fire in a drill | Log message metadata |
| **P9.S05** | Encrypted server backups + a restore drill. Define RPO/RTO and account for message ciphertext, public key material, metadata, and operational server secrets separately. Backups inherit the §3.1 retention rules. | AI | Restore drill completed | Back up what should have been deleted |
| **P9.S06** | Incident response runbook: compromise, pin rotation, mass revoke, key rotation. | AI | Runbook exists and is walkable | — |
| **P9.S07** | **Internal pen-test checklist** (inlined here — the cited RTF §15.1 does not exist): `UserDefaults` bypass attempts; MITM with the wrong pin; relay rewriting `Envelope.sender`; relay replaying a captured prekey message; prekey pool exhaustion; invite brute force; base-key witness flooding; post-first-unlock device extraction; verifying delivered messages are actually gone from the server. | AI | Every item executed and recorded | Skip an item as "obviously fine" |
| **P9.S08** | External pen-test engagement; Claude tracks findings into `AUDIT.md` until CLOSED. | **HUMAN** | Report received; findings filed | — |

**Production readiness gate** — all must be true:
- [ ] All Critical findings closed
- [ ] High findings closed or formally ACCEPTED with compensating controls
- [ ] Two-device E2E on production
- [ ] Safety numbers verified
- [ ] App lock with biometrics verified
- [ ] APNs content-free verified
- [ ] CI supply-chain + tests green
- [ ] Backup restore drill done
- [ ] Pen-test criticals closed

**Exit criteria:** private-circle production allowed.

---

# P10 — Later / optional (do not start early)

Only after P9. Each is a large security design of its own.

| ID | Item |
|----|------|
| **P10.S01** | Multi-device (`wireVersion` 2) |
| **P10.S02** | Group messaging — implement Sender Keys or MLS properly; reverse AUDIT 3.7 only with full tests. **Never half-enable `SenderKeyStore`.** |
| **P10.S03** | Calls (WebRTC + DTLS-SRTP + authenticated signaling) |
| **P10.S04** | Optional hardening: jailbreak/debugger detection — **not** a real control against code execution; never market it as one |
| **P10.S05** | Secure Enclave spike for wrapping record keys. Identity keys remain libsignal-exportable — do not claim SE protection for the Signal identity |

**Out of scope until P10, explicitly:** group chats that actually encrypt; multi-device linking;
voice/video calls; any marketing claim of nation-state-proof metadata privacy.

*(Sealed sender and traffic padding were in this backlog and have been promoted to P7.)*

---

## Purchase & setup timeline

| When | Domain | VPS | Who acts |
|------|--------|-----|----------|
| P1–P3 | **Do not buy** | **Do not buy** | Claude: client/crypto/CI only |
| P4 | **Do not buy** | **Do not buy** | Claude: local Docker backend |
| **P5.S01–S02** | **HUMAN buys domain** | **HUMAN buys staging VPS** | Human purchases → provides access |
| P5.S04+ | AI configures DNS/TLS | AI hardens & deploys staging | Claude, after credentials |
| P8.S01 | — | — | Human: APNs keys |
| P9.S01 | Prod DNS cutover | **HUMAN buys prod VPS** | Claude deploys after access |

**Rule:** no purchase before P4 exit. No AI setup before the human provides host access. No
production VPS before staging E2E works.

---

## Standing regression checklist (every PR)

[`Scripts/verify-all.sh`](../Scripts/verify-all.sh) owns the mechanical gate list, order and count.
Run the full command serially and use its output as the evidence; do not copy the inventory or
totals into this plan.

After it passes, complete the three judgement checks below. Their identifiers remain 7–9 because
the verifier prints them as its manual handoff; they are not a count of mechanical gates.

7. Confirm groups/sender-key still rejected
8. Confirm identity-change policy: receive trusted, send refused until exact `acceptIdentity`
9. Update `AUDIT.md` and the STATUS block if status changed

---

## File map

| Area | Paths |
|------|--------|
| Crypto façade | `CipherCrypto/Sources/Engine/CryptoEngine.swift` |
| Store / Keychain | `CipherCrypto/Sources/Store/*` |
| Envelope | `CipherCrypto/Sources/Wire/Envelope.swift` |
| Locked decisions | `CipherCryptoTests/LockedDecisionsTests.swift`, and for §0.2.7 also `Scripts/verify-identity-fields.py` |
| Threat model | `docs/THREAT_MODEL.md` |
| Audit ledger | `docs/AUDIT.md` |
| Supply chain | `Vendor/libsignal/*`, `Scripts/verify-supply-chain.sh`, `Podfile` |
| All gates | `Scripts/verify-all.sh` |
| Fake auth / lock | `Cipher/App/AppSession.swift`, `Cipher/Features/Auth/AuthFlowView.swift` |
| Messaging path (app) | `Cipher/Messaging/` — store, repository, sealed archive, gate |
| Relay clients | `Cipher/Networking/RelayMailbox.swift`, `RelayKeyDirectory.swift` |

---

## Definition of done

Finished when the P9 production readiness gate is fully met and `AUDIT.md` contains no OPEN item the
private-circle launch policy marks as a blocker. P10 remains optional backlog.

---

## Appendix — step ID migration

The original plan numbered steps 1–82 globally, so any insertion renumbered everything downstream.
IDs are now phase-scoped and stable. Every original step is preserved; the four marked **moved** kept
their content and changed position for the reasons given in P5 and P7.

| Old | New | Old | New | Old | New |
|-----|-----|-----|-----|-----|-----|
| 1 | P1.S01 | 29 | P4.S04 | 57 | P8.S01 |
| 2 | P1.S02 | 30 | P4.S05 | 58 | P8.S02 |
| 3 | P1.S05 | 31 | P4.S07 | 59 | P8.S03 |
| 4 | P1.S07 | 32 | P4.S09 | 60 | P8.S04 |
| 5 | P1.S04 | 33 | P4.S10 | 61 | P8.S05 |
| 6 | P1.S09 | 34 | P4.S11 | 62 | P8.S06 |
| 7 | P1.S10 | 35 | P4 exit | 63 | P8.S07 |
| 8 | P1.S11 | 36 | P5.S01 | 64 | P8.S08 |
| 9 | P1 exit | 37 | P5.S02 | 65 | P8 exit |
| 10 | P2.S01 | 38 | P5.S03 | 66 | P9.S01 |
| 11 | P2.S02 | 39 | P5.S04 | 67 | P9.S02 |
| 12 | P2.S03 | 40 | P5.S05 | 68 | P9.S03 |
| 13 | P2.S04 | 41 | P5.S06 | 69 | P9.S04 |
| 14 | P2.S05 | 42 | P5.S07 | 70 | P9.S05 |
| 15 | P2.S06 | 43 | P5.S08 | 71 | P9.S06 |
| 16 | P2.S07 | 44 | P5.S09 | 72 | P9.S07 *(inlined)* |
| 17 | P2.S08 | 45 | P5.S10 | 73 | P9.S08 |
| 18 | P2 exit | 46 | P5.S13 | 74 | P9 gate |
| 19 | P3.S01 | 47 | P5.S14 | 75 | P9 exit |
| 20 | P3.S02 | 48 | P5 exit | 76 | **P7.S01** *(moved)* |
| 21 | P3.S03 | 49 | **P5.S12** *(moved)* | 77 | P10.S01 |
| 22 | P3.S04 | 50 | P6.S01 | 78 | P10.S02 |
| 23 | P3.S05 | 51 | **P4.S06** + P6.S02 *(moved)* | 79 | P10.S03 |
| 24 | P3.S06 | 52 | **P5.S11** *(moved)* | 80 | **P7.S02** *(moved)* |
| 25 | P3 exit | 53 | P6.S03 | 81 | P10.S04 |
| 26 | P4.S01 | 54 | P6.S04 | 82 | P10.S05 |
| 27 | P4.S02 | 55 | P6.S05 | | |
| 28 | P4.S03 | 56 | P6 exit | | |

**New steps with no predecessor:** P1.S03 (dangling RTF), P1.S06 (group UI → DEBUG), P1.S08
(`verify-all.sh`), P4.S08 (delete-on-delivery), P7.S03 (push-token hardening).
