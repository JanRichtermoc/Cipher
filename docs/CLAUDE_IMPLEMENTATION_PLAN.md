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
| Phase | **P8 is in progress out of order**: S07 (acknowledgements) and S04 (no NSE) are done, because S01 is a human step blocked on an Apple Developer account and S02/S03 need the key it produces. **Every numbered P7 step is done (S01, S02, S03).** Its exit criteria are met but the phase carries one new OPEN finding, 3.9. P6's numbered steps are all done; P1–P4 complete. P5's numbered steps are all done and six of its seven exit criteria are ticked; the seventh is a hardware decision, not engineering work, so P6 proceeds beside it rather than behind it. |
| Completed P5 product steps | P5.S01, P5.S02, P5.S05, P5.S06, P5.S08, P5.S09, P5.S10, P5.S11, P5.S12, P5.S13, and P5.S14 — every numbered P5 step. **The exit criteria were evaluated 2026-08-07: six of seven are met and ticked with their evidence; one is not.** "Safety numbers visible and correct **on two devices**" stays unticked because the P5.S13 pairing was one real iPhone plus one simulator — the residual AUDIT 5.1 records. It needs a second real device or an operator acceptance recorded as explicitly as 5.1's. **P5 is therefore not formally exited**, and that is a hardware decision rather than remaining engineering work. |
| Security-remediation queue | Empty of closed work: 5.26, 5.27, 1.14, 6.14, 6.13, 5.28, 5.29, 5.32, 5.33 and 5.34 are closed; 5.29 reached the live box 2026-08-06 and 5.32 on 2026-08-07. 5.34 and 6.17 are client- and tooling-only and need no deploy. **5.1 closed 2026-08-07 (P5.S14); 5.36 was opened and closed by P6.S01 the same day, and no 5.x row is OPEN.** Closing it split out the push clause it also carried as **5.35** (ACCEPTED, foreground-only delivery, fix in P8.S02) rather than dropping it. What remains in this ledger is ACCEPTED residuals, which are read, not cleared. `AUDIT.md` is authoritative, and a finding's CLOSED status describes the repository: check the deployed revision against `origin/main` before assuming the staging relay carries it (`RUNBOOK-VPS.md`, Deployed revision). **5.32 is why that check exists, and 5.33 is why it is not paranoia** — both passed CI while the relay a real iPhone was talking to did not have them. |
| Next planned feature | **P6.S01 through P6.S04 are complete.** P6.S01 delivered prekey rotation and threshold replenishment (AUDIT 2.4, and the 5.36 it uncovered); P6.S02 resolved AUDIT 3.1 as **ACCEPTED** after correcting the premise it rested on; P6.S03 (2026-08-08) delivered disappearing messages that delete rather than hide, with the timer carried on each message rather than held as conversation state; P6.S04 (2026-08-08) delivered attachments encrypted before upload with an AEAD and a ciphertext digest, an encrypted media cache inside the crypto container, and a derived wipe that covers every path a message can leave the archive by — which also made P6.S03's media clause testable, and it is now tested; P6.S05 (2026-08-08) found both halves of its own `Done when` already satisfied — the mock revoke went with `MockStore` in P5.S10 and blocking was already real and tested — and closed the one clause that was not, server-side session-token revocation, which was called but never asserted. **Every numbered P6 step is complete and all five exit criteria are ticked.** **P7.S01 (2026-08-08) sealed the sender**: every outbound frame is a `.sealed` container and carries seventeen zero bytes where the sender used to be, which closed **3.4** and split the part it never covered out as **3.9** — a live relay is still told who is sending by the bearer token, and closing that needs an unauthenticated delivery path that is not an approved step. The step also found that its own stated mechanism, a *server-issued* sender certificate, cannot be built here: the signature is XEd25519 over Curve25519 keys and the relay is Go with an iOS-only libsignal pin. The certificate is self-issued instead, with the operator's approval taken before any edit; **no relay change was made and no deploy is needed.** **P7.S02 (2026-08-08) bucketed the length**: nine sizes doubling from 256 bytes, applied to the plaintext rather than the ciphertext for the reason that row now records, so a frame's size no longer tracks what was written. Also client-only, also no deploy. **P7.S03 (2026-08-08) hardened the push token**, and found the table fully specified and entirely unimplemented — nothing in Go had ever touched it, so the property it was supposed to guarantee held only because no token could be stored at all. It is the first **relay** change of the phase: `internal/pushtoken`, `store/push.go`, a fifth sweep task, and **migration `0002`**, **deployed to staging 2026-08-08** and verified there — the table held 0 rows before and after, so narrowing the CHECK could not fail against existing data, and a second start reported `applied=0` (`RUNBOOK-VPS.md`, P7.S03 deploy row). `RELAY_PUSH_TOKEN_KEY` is optional and stays unset until P8; with no key the writes refuse rather than storing a token in the clear. **P8.S01 (the APNs key, a human step) is next**, and it gates P8.S02, which brings both the provider and the registration endpoint this step deliberately did not build. **6.18 is CLOSED (2026-08-08):** the account-destruction guard used to live only in `verify-all.sh`, so a direct `xcodebuild test` bypassed it and had already destroyed the P5.S13 simulator installation. `Keychain.shared` now returns a Keychain on a separate service while XCTest is loaded, in the shared handle rather than in the fixture, so it also covers the fixtures nobody has written yet. The *file* half is the stated residual: a test that opened the default container would still remove real files, which no test does and which gate 1 still refuses. One operator decision still stands between here and a formal **P5** exit: a second real device for the two-device safety-number criterion, or an explicit recorded acceptance of the one-device-plus-simulator residual. **5.35** separately carries foreground-only delivery, fixed in P8.S02 and not P7.S03. |
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
   "tighten" to `WhenUnlocked` without a notification-content redesign.
   - **Rationale corrected 2026-08-08 (P8.S04), decision unchanged.** This read "without an NSE +
     notification-content redesign", and P8.S04 decided there will be **no NSE** (AUDIT 4.4) — which
     would have left this locked decision looking unjustified and invited exactly the tightening it
     forbids. What needs the key while the device is locked is **wake-only push**: a silent push
     wakes the *app*, which fetches, decrypts and posts a local notification, in its own process.
     Same requirement, no second process.
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
| 3.8 | First-contact address is relabellable by the relay — narrowed by P7.S01 to the addressed receive path, which is still accepted for compatibility | P5.S12 / P7 |
| 3.9 | The live relay still learns the sender from the bearer token on send (split from 3.4 when P7.S01 closed it) | unscheduled |
| 4.4 | NSE/App Group sharing is not approved or cross-process tested; Keychain sharing still needs a migration and rollback design | P6 |
| ~~2.4~~ | ~~No key rotation / replenishment~~ | CLOSED P6.S01 |
| ~~2.5~~ | ~~No safety-number UI~~ | CLOSED P5.S12 |
| ~~3.1~~ | ~~Base-key witness FIFO eviction~~ | ACCEPTED P6.S02 |
| ~~5.1~~ | ~~Messaging works, but only against a stub — not yet device to device~~ | CLOSED P5.S14 |
| 5.35 | Delivery is foreground-only; nothing tells the recipient a message is waiting (split from 5.1, ACCEPTED) | P8.S02 |
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
| **P5.S12** | **Safety-number UI** from real identity keys (LibSignalClient Fingerprint APIs): persist verification tied to the fingerprint, invalidate on identity change, wire to the existing receive-OK / send-blocked policy. *Moved from P6.* **DONE 2026-08-06.** `CryptoEngine.safetyNumber` derives the digits over both identity keys and ACIs; verification is a flag inside `PeerIdentityRecord`, so it cannot outlive the key it describes and a change clears it. Accepting and verifying stay separate controls. **QR scanning was scoped out** with the operator rather than dropped: it needs a camera permission the app has never had, and a QR render with no scanner would be an inert affordance. Tracked as residual (a) on AUDIT 2.5. | AI | 2.5 | Two devices show matching numbers; a substituted identity visibly changes them | Ship "Mark as Verified" that verifies nothing |
| **P5.S13** | Two-device end-to-end test via staging: register, exchange prekeys, send/receive real ciphertext. **DONE 2026-08-07, both directions**, between a physical iPhone and the `iPhone 17 Pro` simulator against the deployed relay. Each side initiated one session, so both halves of PQXDH establishment were exercised rather than one direction replayed: a prekey message each way (1864 B and 1845 B), a curve and a Kyber prekey consumed from the recipient's pool, `POST 202` then fetch then `ack 200`, the queue draining to zero each time, and the stored envelope containing none of the plaintext. Acknowledgement follows durable storage in the same transaction, so a drained queue is evidence of decryption and not merely of receipt. The run also found and closed 5.32 and 5.33, and hit 5.34 twice and 6.17 once. **This does not close 5.1** — see that row for the accepted residual (one device plus one simulator) and for the push clause it also names. | AI + HUMAN | — | Real message delivered device-to-device | Test only in the simulator; call it done on one device plus a simulator without recording the residual |
| **P5.S14** | Close AUDIT 5.1 once transport, auth, and the non-mock messaging path work on staging. **DONE 2026-08-07.** 5.1 is CLOSED against named guards rather than against the field run alone — `MessagingTests.testRoundTripThroughTheFacade` and `testSessionSurvivesAnEngineRestart` for two real engines, the four `MessageRepositoryTests` that pin ciphertext-on-the-wire and the acknowledge-what-is-durable ordering, `CertificatePinnerTests.shippedPinsCoverTheLiveLeaf`, `SessionCredentialTests.testWritingUserDefaultsCannotAuthenticate`, and `verify-relay-integration.sh`; P5.S13 supplies the field evidence those guards describe. **The push clause 5.1 also carried did not close with it** — it is now 5.35 (ACCEPTED, foreground-only delivery, fix in P8.S02), split out rather than dropped, because 5.1 asserts the path *works* and foregrounding changes when a message is collected rather than whether it is delivered. The row also mis-cited P7.S03 for "there is no push"; P7.S03 hardens a token that P8.S01/P8.S02 create. The operator-accepted one-device-plus-simulator residual is restated on 5.1 unchanged, not quietly satisfied. **5.3 was already CLOSED in P5.S10** (2026-07-30) and is struck from this row's blockers; `AUDIT.md` owns finding status and had said so since. | AI | ~~5.3~~, 5.1 | 5.1 CLOSED with tests named | Close 5.1 by dropping the push clause, or treat the field run as its own guard |

**Exit criteria** — evaluated 2026-08-07, after P5.S14. Six are met; one is not, and it is not the
kind that can be argued into being met. Each tick names what was checked, because a ticked box whose
evidence nobody can find is worth less than an unticked one.

- [x] **Domain + staging VPS owned and hardened.** Verified live on the box 2026-08-07: `sshd -T`
      reports `passwordauthentication no` and `permitrootlogin no`; the `fail2ban` sshd jail is
      running; `/etc/docker/daemon.json` bounds container logs; only 22/80/443 listen externally with
      the API on `127.0.0.1:8080` and Postgres/Redis unpublished; all three containers run
      `CapDrop=[ALL]` with bounded memory and pids, `api` and `redis` read-only; and
      `RELAY_TRUSTED_PROXY` is the bridge subnet rather than loopback. `RUNBOOK-VPS.md` owns the
      procedures and the state table.
- [x] **TLS live; client pins fail closed on the wrong certificate.** Live probe 2026-08-07 with real
      OpenSSL 3.6.3 — *not* the LibreSSL macOS ships as `openssl`, which has already reported a false
      pass here (5.16, 6.14): TLS 1.3 negotiates, TLS 1.2 is refused with `alert protocol version`,
      and the chain and hostname validate. The served leaf matches a shipped pin, `certbot` keeps the
      key on renewal, and `RelayEndpoint` pins exactly the values `BACKEND.md` §9.1 records.
      Fail-closed is proved by tests rather than by the happy path: a pin set without the leaf, an
      empty pin set, a self-signed certificate, a wrong-pin server with a perfectly valid chain, and a
      challenge for a different host are each refused, with "the same valid chain IS accepted once the
      correct pin is present" as the positive control. **Standing operator action (6.14):**
      `verify-pins.sh` exits non-zero because the backup-key check has no material on this machine.
      That non-zero *is* 6.14's fix working — an unproven check must not read as a pass — and it is
      not a TLS failure. Running it needs `PIN_BACKUP_KEY_FILE`.
- [x] **Real invite auth end-to-end.** C-01 closed in P5.S09: the code is redeemed against the relay
      and only a server-issued token authenticates. Exercised against the deployed relay during the
      P5.S13 field run; guarded by `InviteRedemptionTests` and
      `SessionCredentialTests.testWritingUserDefaultsCannotAuthenticate`.
- [x] **Two-party encrypted message via the server.** P5.S13, 2026-08-07, both directions through the
      deployed relay with each side initiating a session. See that row for the measurements and
      AUDIT 5.1 for the named guards that hold the property between field runs.
- [x] **C-01 and C-02 closed.** Both 2026-07-30, in P5.S09 and P5.S10 respectively (§0.5).
- [ ] **Safety numbers visible and correct on two devices.** *Not met, and deliberately not ticked.*
      P5.S12 built the real thing — `CryptoEngine.safetyNumber` derives the digits from both identity
      keys through libsignal, `SafetyNumberTests` prove two engines agree and that a substituted key
      changes them, and verification is stored bound to the exact key so a change retracts it. What is
      missing is the literal words **on two devices**: the P5.S13 pairing was one real iPhone plus one
      simulator, which is the residual AUDIT 5.1 records. A simulator proves the protocol, not the
      device. Ticking this needs **a second real device**, or an operator acceptance recorded as
      explicitly as 5.1's was — it is a decision about what hardware stands behind the claim, not an
      engineering judgement.
- [x] **No plaintext message body on the wire, in the server DB, or at rest on device.** Wire:
      `MessageRepositoryTests.testASentMessageIsCiphertextTheRelayCannotRead`, and the P5.S13 run
      observed the stored envelope containing none of the plaintext. Relay: the integration suite
      passes with the race detector on and all its required tests by name. At rest: P5.S11's sealed
      database, with 4.3, 4.7, 4.12 and 4.13 closed against it. **The live relay database was
      deliberately not queried for message rows.** Confirming the property that way means reading real
      private traffic, which the root contract forbids; the tests and the field observation establish
      it without anyone having to look at someone's messages.

---

# P6 — Rotation, disappearing messages, attachments

**Goal:** close the remaining half-delivered crypto UX and storage holes.
**Preconditions:** P5 exit criteria met.
**Buy anything?** Optional: APNs key setup (human). No second VPS.
**Privacy regression check:** does rotation or attachment handling add anything the relay can link?

| ID | Step | Owner | Closes | Done when | Do not |
|----|------|-------|--------|-----------|--------|
| **P6.S01** | Prekey rotation & replenishment (signed prekey, Kyber, one-time pool): client scheduler + server publish endpoints. The real mitigation companion to AUDIT 3.1. **DONE 2026-08-07.** The relay's publish endpoint already carried both halves this needs — it replaces the signed prekey and last-resort Kyber key, *adds* one-time keys, and reports the account's own remaining pools — so **no relay change was required and none was made**; the step is entirely client-side and needs no deploy. Publishing is now rotating: every publication mints a fresh signed prekey and last-resort key, because the relay refuses an upload without them and there is no publish-without-rotate shape to build. The pair each rotation replaces is retired for thirty days and then pruned, so an in-flight bundle still decrypts and storage stays bounded. `MessageRepository.maintainKeys` runs from `ConversationStore.start` — the launch hook AUDIT **5.36** records as never having existed — and publishes when the rotation interval has elapsed or the pool is below threshold, topping up by the shortfall rather than the target. | AI | 2.4, 5.36 | Pool replenishes below threshold; rotation observed across a restart | Reuse a consumed prekey id |
| **P6.S02** | With P4.S06 rate limiting and P6.S01 rotation both live, document the residual witness-eviction trade-off and only then move AUDIT 3.1 to CLOSED or formally ACCEPTED. **DONE 2026-08-07 — resolved ACCEPTED, and the review corrected one of the row's own premises.** Witness eviction is driven by *sending* prekey messages, not by fetching bundles: one fetched bundle yields unlimited base keys, so P4.S06's fetch limit bounds pool drain and not this. Rotation does not prevent the eviction either — what it does is end the window, because the superseded pair is pruned and session setup against it then fails on the missing key. Prevention would need a control that does not exist, so CLOSED would have been the "downgrade to probably fine" the ledger forbids. | AI | 3.1 | AUDIT 3.1 resolved with rationale | Close it without both controls |
| **P6.S03** | Disappearing messages that **actually delete** — DB rows and media cache — enforced across restart and backgrounding. **DONE 2026-08-08.** The timer is on the *message*, not the conversation: a new `MessagePayload` content type (`.expiringText`, wire byte 2) carries it inside the ciphertext, so both devices delete the same message without any shared state to drift. A new content type rather than a version bump, because an unsupported version is refused for *every* message while an unknown type costs only the timed ones — and the receive path acknowledges-and-drops what it cannot parse, so that difference is message loss. Each message stores an **absolute** `expiresAtMs` and `ConversationArchive.deleteExpiredMessages` compares it to now; nothing counts down, so a device that was killed for a week deletes on the way back up. `ConversationStore.start` sweeps **before** anything is drawn. **The media half is vacuous today** — attachments are P6.S04 and no media cache exists — stated rather than implied as covered. `StoredMessage.schema` is 2; a downgrade past this build cannot read message records written by it. | AI | — | Test: relaunch after expiry finds no row and no cached media | Hide rather than delete |
| **P6.S04** | Attachment encrypt-before-upload end-to-end with AEAD and integrity checks; encrypted media cache wiped on delete/disappear. **DONE 2026-08-08.** The relay's blob endpoints already existed (P4.S08) and the quota was already enforced (AUDIT 5.22), so **no relay change was required and none was made**; the step is entirely client-side and needs no deploy. `AttachmentCipher` seals under a fresh AES-256-GCM key per attachment and `RelayBlobStore`'s parameter is that ciphertext, so the "upload then encrypt" anti-goal has no shape to take. **Two integrity checks, neither redundant:** the AEAD is the guarantee, and a SHA-256 digest of the *ciphertext*, carried in the same end-to-end message, catches a relay substituting a different blob before any key is used — the declared plaintext length bounds the download to the byte. A new content type (`.attachment`, wire byte 3) carries the pointer, key, digest and length; the timer is a **field** on it rather than a fourth type, because zero is unambiguous in a body that always has the field. The cache is a directory *inside* the crypto container, so `destroyAllState` takes it; the key lives in the sealed message row, so deleting a message is already a cryptographic erase and the unlink is the second half. **The wipe is derived, not maintained** — `removeAttachments(except:)` against the ids live rows still name — because four of the six paths that remove messages do so in bulk without decoding them. The recipient deletes the relay's copy once it holds a verified one; the sender never does, since it cannot know whether the recipient has fetched. The session is established **before** the seal and upload — the opposite order to a text send — so a refusal that is knowable without encrypting anything leaves nothing on the relay; **the residual is stated in the code**: a key that changes on an *already established* session is still refused after the upload, because there is no bundle to process and no way to test a local pre-check at this layer (both engines in the app test fixture share a Keychain identity). Picked photos are re-encoded through a bitmap, which drops EXIF including where the photo was taken. `StoredMessage.schema` is 3. | AI | — | Server holds only opaque blobs; cache wipe tested | Upload then encrypt |
| **P6.S05** | Block list / device revoke — expose **only** UI that hits real server state. **DONE 2026-08-08 — and both halves of the `Done when` were already true, which is the finding.** `revokeDevice` was a `MockStore` method behind a fabricated device list; it went with the mock itself in **P5.S10**, three steps early, and the only remaining mention of it anywhere in the tree was this row. `LinkedDevicesView` has said Cipher is single-device since then. Blocking was likewise already real and already tested — a send to a blocked peer is refused, and an inbound message from one is decrypted (the ratchet must advance), then dropped and acknowledged. What was *not* true is the second clause read literally: single device is a locked decision (§0.2.5, AUDIT 3.6), so there is no second device whose revocation could be observed. The only revocable thing is **this** device's session token, the relay has had `DELETE /v1/auth` since P4, and `SessionLifecycle.revokeBestEffort` calls it on the account-cleanup path — untested until now, which is the same shape as **5.36**: a best-effort call nobody asserts is indistinguishable from one that was never wired up. `SessionRevocationTests` now pins the token it carries, that it is the per-session endpoint and never `DELETE /v1/auth/all`, and that a refusing or unreachable relay does not stop the erase. The dead `LinkedDevice` model type is removed, and `Revoke`/`Odvolat` — both recovered from the tree rather than guessed — join the localization gate's retired-label list so the control cannot return as copy. | AI | — | Mock `revokeDevice` gone; revoke observable server-side | Keep the mock revoke lie |

**Exit criteria:**
- [x] AUDIT 2.4 closed — P6.S01, 2026-08-07. Rotation on a 48-hour interval, replenishment below a
      quarter of the pool, thirty-day retention of the pair each rotation replaces, and a publication
      floor so a drained pool cannot spend the relay's daily allowance in one foreground.
- [x] AUDIT 3.1 closed or formally ACCEPTED with rate limiting **and** rotation in place — P6.S02,
      2026-08-07. **ACCEPTED**, because neither control prevents the eviction: rotation ends the
      replay window and the fetch limit turns out to bound a different attack entirely.
- [x] Disappearing deletion tested across relaunch — P6.S03, 2026-08-08.
      `DisappearingMessageTests.testExpirySurvivesARestartAndIsEnforcedOnTheWayBackUp` drives a
      second archive over the same container, holding no memory of the send and no timer of its
      own. The **media** half of the row's `Done when` had nothing to test until P6.S04 built a
      media cache; **it is tested since 2026-08-08** by
      `AttachmentTests.testAnExpiredAttachmentTakesItsCachedBlobWithIt`, which sweeps a timed
      attachment and asserts the cache directory is empty afterwards. Negative-tested by
      disabling the wipe: *"the message disappeared but its decryptable blob stayed on disk"*.
- [x] Attachments encrypted before upload, and the cache wiped on delete or disappear — P6.S04,
      2026-08-08. `AttachmentTests.testTheRelayReceivesCiphertextAndNeverThePlaintext` applies
      its opacity check to the bytes of the real upload and is negative-tested twice: once by
      uploading the plaintext, and once by uploading a correctly *sized* body that still
      contains it, so the check cannot pass on length alone.
- [x] Only UI that hits real server state — P6.S05, 2026-08-08. The mock revoke had been gone
      since P5.S10 and blocking was already real and tested; the untested half was server-side
      session revocation, now pinned by `SessionRevocationTests` and negative-tested by making
      `revokeBestEffort` return early (*"account cleanup did not revoke the session token
      server-side"*). The retired `Revoke` control is held down by the localization gate, whose
      self-test grew from 59 cases to 61.

---

# P7 — Metadata minimisation

**Goal:** reduce what a seized relay can prove. **Promoted out of the old Phase 9 backlog** because
the hostile/seizable-server model (`THREAT_MODEL.md` §0) makes this load-bearing, not optional.
**Preconditions:** P6 exit criteria met.
**Read first:** `THREAT_MODEL.md` §3.2, §3.3, §3.5.
**Privacy regression check:** this phase *is* the privacy check.

| ID | Step | Owner | Closes | Done when | Do not |
|----|------|-------|--------|-----------|--------|
| **P7.S01** | **Sealed sender.** libsignal already ships it (`Pods/LibSignalClient/swift/Sources/LibSignalClient/SealedSender.swift`), so this is wiring plus a server-issued sender-certificate scheme — **not new cryptography**. `Envelope`'s `wireVersion` + reserved type space exists precisely so this arrives without a wire break. **DONE 2026-08-08, and the row's own mechanism turned out not to exist.** A libsignal sender certificate is signed with **XEd25519 over Curve25519 keys**; the relay is Go, its dependency set is `uuid`/`pgx`/`redis`, the standard library has no XEdDSA, and `Vendor/libsignal/PINS.env` pins a **prebuilt iOS** artifact with no Linux build and no Go binding. Issuing one server-side would mean writing the scheme by hand — §0.6, do not invent cryptography — or linking libsignal into the relay, which is a supply-chain change with its own approval. The operator was asked before any edit and chose the client-side shape. So the **certificate is self-issued**: minted once per installation from a trust root generated and dropped inside the minting call, because a signature nobody can check is structural, not meaningful. Its *name* proves nothing, exactly like the cleartext field it replaces. Its **key** does, and not by signature: libsignal refuses a container naming a key its sealer does not hold, so requiring that key to be the one the session authenticated makes the sealer and the session owner the same account — which is what stops a relay re-wrapping a captured payload under a name of its own. `.sealed` is a **new payload type (4)** rather than `wireVersion` 2, keeping the 31-byte header, the relay's size bounds and its `CHECK` untouched: **no relay change was required and none was made, so this needs no deploy.** Sending is sealed unconditionally — a per-peer choice would be visible to the relay as the difference between frame types, so the accounts still in the open would be the ones the metadata is about — and receiving still accepts addressed frames so nothing in flight is lost. Every wire refusal is re-applied **inside** the container (sender-key, `PlaintextContent`, a second device, a phone number, a PNI), because sealing hides the payload from every other check. | AI | 3.4 | Server cannot determine the sender of a relayed message; test proves it | Invent a certificate format |
| **P7.S02** | Length bucketing: pad ciphertext to fixed buckets before relay. `Envelope` caps at 64 KB, so the bucket set is bounded. **DONE 2026-08-08, and the row's own wording is the one thing that had to change.** Padding goes on the **plaintext**, not the ciphertext: a Signal ciphertext is authenticated, so appended bytes fail to decrypt rather than being ignored, and making them strippable would mean carrying the real length beside the padded one in cleartext — the exact number this exists to hide. Inside the encryption there is no such problem, and the ciphertext length follows the padded plaintext through a fixed overhead, so bucketing the input buckets what the relay stores. `MessagePadding` is nine buckets doubling from 256 bytes, with `plaintext ‖ 0x80 ‖ 0x00…` as the framing — Signal's own construction, framing rather than cryptography. The last bucket is not a doubling: it exists so the largest legal payload still has room for its terminator, because a scheme that refuses messages the payload format accepts is a scheme that fails at the ceiling. **Padding and sealing are coupled deliberately**: a frame is padded exactly when it is `.sealed`, since a build that pads is a build that seals, so the receive path decides by frame type and never by a heuristic — guessing would either truncate a real message or return padding as content, and padding is valid UTF-8, so nothing downstream would notice. A sealed frame that is *not* padded is refused. **Attachments are not padded** and that is stated rather than implied: their blobs are out of band and padding them means padding megabytes. | AI | — | Wire lengths take a small fixed set of values | Claim it defeats a global adversary |
| **P7.S03** | Push-token hardening: encrypt the replayable token under a service key held outside the database, rotate it, and delete it with the account. It is metadata that survives message deletion; encryption at rest does not defeat whole-host seizure (`THREAT_MODEL.md` §3.3). **DONE 2026-08-08.** The table was fully specified and **entirely unimplemented**: `push_tokens` existed in `0001_init.sql` and `BACKEND.md` §2.9, and no Go touched it, so "a dump has no plaintext token" was true only because nothing could write one — the same vacuous-pass shape as **5.36** and P6.S05. `internal/pushtoken` is the cipher, `store/push.go` the four operations, and the sweep grew a fifth task. **The documented algorithm turned out to be unbuildable here**, the second time this phase: a libsignal-free XChaCha20-Poly1305 is not in Go's standard library — it exists in the toolchain only as the standard library's own vendored copy — so building it as written meant `golang.org/x/crypto` as the relay's first cryptographic dependency. AES-256-GCM from `crypto/cipher` instead, and **migration `0002` narrows the nonce CHECK from 24 bytes to 12**; the table had never held a row, so nothing was re-encrypted. The `aci` is the AEAD's additional data, so a row lifted into another account does not open — without it, write access to the table would redirect one person's notifications to another person's device. **A missing key refuses rather than falling back to plaintext**, which matters because the key is *unset on the current deployment* and will stay unset until P8. "Rotate" is honest about its limit: only a device can mint a device token, so the relay's half is to discard one nothing has reasserted in 30 days and to rewrite the row under a fresh nonce whenever one is. **Deliberately no HTTP endpoint** — registering a token belongs with the APNs provider in P8.S02, and pulling it forward would be building the half that has no client. | AI | — | A database dump has no plaintext push token; rotation and account deletion are tested | Hash a token APNs must receive verbatim; let it outlive the account |

**Exit criteria:**
- [x] AUDIT 3.4 closed or formally ACCEPTED with rationale — **CLOSED** P7.S01, 2026-08-08, against
      named guards rather than against the design: `SealedSenderTests.testTheRelayedFrameNamesNobody`
      searches a real send's bytes for the sender's wire encoding *and* its raw UUID, with an
      addressed frame as the positive control that the search can find one when it is there.
      Negative-tested by restoring the addressed send in the real source. The half 3.4 did not cover
      was split out as **3.9** rather than closed by omission.
- [x] A seized staging database cannot show who sent a relayed message — the frame it stores carries
      seventeen zero bytes where the sender used to be, and `messages` has no sender column
      (`BACKEND.md` §2.4). **Established by the guards above and by the schema, deliberately not by
      querying the live database**: confirming it that way means reading real private traffic, which
      the root contract forbids — the same reasoning P5's last exit criterion records.
- [x] `THREAT_MODEL.md` §1.1 residual row updated to match reality — §3.2 also corrected, since it
      specified the server-issued scheme that turns out not to be buildable here.
- [x] **P7.S03 is done** (2026-08-08), and it is the step with a deploy attached: migration `0002`
      applies on the relay's next start. Guards, all required by name in
      `verify-relay-integration.sh`: `TestAPushTokenIsStoredEncrypted` reads the column *without*
      decrypting, so a plaintext column cannot pass it the way a round-trip assertion would;
      `TestARelayWithNoKeyRefusesToStoreAToken` pins the fail-closed behaviour that matters most
      while the key is unset; `TestDeletingTheAccountTakesItsPushToken` exercises the cascade; and
      `TestStalePushTokensAreSweptAndFreshOnesAreNot` pins the rotation threshold from both sides.
      Negative-tested by storing the token in the clear in the real source, which failed the first
      three by name.
- [ ] **Not an exit criterion, recorded so it is not mistaken for one:** AUDIT **3.9**, the live
      relay learning the sender from the bearer token, stays OPEN. **P7.S02 is done** (2026-08-08):
      `MessagingTests.testTheRelayedLengthTakesOneOfASmallFixedSetOfValues` asserts that two frames
      have the same wire length exactly when their plaintexts share a bucket — equality alone would
      pass on a scheme that padded everything to one size and lost large messages, inequality alone
      on no padding at all. Negative-tested by removing the padding (*"14 messages spanning 4 buckets
      produced 12 different wire lengths"*) and by replacing the ladder with a 256-byte one
      (*"a bucket set that grows stops being a bucket set"*). **P7.S03 is still to do**, and it is
      the first step in this phase that changes the relay and needs a deploy.

---

# P8 — Push, privacy compliance, acknowledgements

**Goal:** content-free notifications; App Store / legal blockers cleared.
**Preconditions:** P7 exit criteria met.
**Privacy regression check:** APNs payloads must carry no message body and no names.

| ID | Step | Owner | Closes | Done when | Do not |
|----|------|-------|--------|-----------|--------|
| **P8.S01** | Create the APNs key/certs in Apple Developer; supply key id + `.p8` via a secret store. | **HUMAN** | — | Claude has the key out of band | Commit the `.p8` |
| **P8.S02** | Server APNs provider with **content-free / wake-only** payloads. **Wake-only is load-bearing, not a nicety** (P8.S04): it is what makes an NSE unnecessary, because the app decrypts in its own process after being woken. The client half needs `UIBackgroundModes` = `remote-notification`, which the target does not declare today. | AI | — | Captured payload contains no body and no names | Include a preview |
| **P8.S03** | Client notification privacy: previews only after local decrypt, when unlocked and user-enabled. Default previews **OFF**. | AI | — | Default is off; toggle actually enforced | Default to on |
| **P8.S04** | Decide NSE necessity. If an NSE must decrypt: design App Group + Keychain access group + a **transactional** protocol store *together*. If not: keep the `AfterFirstUnlock` rationale documented, no shared group. **DONE 2026-08-08 — decided: no NSE**, and taken before P8.S02 rather than after, because this is the decision that says what S02 and S03 are allowed to build. **The row's own premise was wrong**, the third time a step in this stretch has found that: an NSE is not what needs to decrypt while locked. Wake-only push does, and it runs in the app's own process — silent push wakes the app, the app fetches, decrypts and posts a *local* notification. So none of AUDIT 4.4's three blockers is on the path to notifications, and 4.4 is **ACCEPTED by withdrawing the requirement, not by meeting it**; the prohibition on adding an NSE stands unchanged, backed by `verify-app-target-manifest.sh` tracking `.entitlements`. Two corrections fell out: 2.1 and `THREAT_MODEL.md` §1.4 both justified `AfterFirstUnlock` by naming an NSE, which after this decision would have read as an unjustified weakening and invited a "tightening" that silently breaks notifications — the second half of §0.2.6 above says the same. **Consequences for the steps this gates:** P8.S02 needs `UIBackgroundModes` = `remote-notification`, which the target does not declare today; P8.S03's preview toggle is *not* inert, because the app really does decrypt before posting; and 5.35 narrows rather than closes, since iOS throttles silent pushes and delivers none to a force-quit app. | AI | — | Decision recorded in `AUDIT.md` with its consequences | Share Keychain/files without transactions |
| **P8.S05** | Re-verify the `PrivacyInfo.xcprivacy` enumeration against whatever libsignal version ships. P1.S11 closed 6.1 outright, so this is a re-check, not unfinished work — and `verify-privacy-manifest.sh` runs on every build, so a bump that introduces a category has already failed the build by now. Confirm the two judgement calls in `docs/PRIVACY_MANIFEST.md` still hold: the `C617.1` reason (breaks if anything ever hands libsignal a path outside our container) and `clock_gettime`/`gettimeofday` still being off Apple's list. | AI | 6.1 (re-check) | `Scripts/verify-privacy-manifest.sh` exits 0 against the release build, and both judgement calls are re-stated as still true in `PRIVACY_MANIFEST.md` | Assume last year's list |
| **P8.S06** | `ITSAppUsesNonExemptEncryption` determination — a legal call, not an engineering one. Claude adds the plist key only afterwards. | **HUMAN** → AI | 6.3 | Key present, decision recorded | Decide it yourself |
| **P8.S07** | In-app acknowledgements / licenses for libsignal (AGPL obligation 3 in `NOTICE.md`). **DONE 2026-08-08**, out of order: P8.S01 is a human step blocked on an Apple Developer account, S02/S03 need the APNs key it produces, and S06 is a legal call — this was the one P8 step with no such dependency. CocoaPods generates the licence into `Pods/Target Support Files/`, which never ships, so `Cipher/Acknowledgements.plist` is a byte-identical copy carried by the app target's synchronized group and rendered in full by `AboutView`. `Scripts/verify-acknowledgements.sh` is gate **12** of 18 and fails on drift from the generated file, so a pod update cannot leave the previous licence on screen. **The catalog regeneration sitting uncommitted in the tree was committed first, separately**, after checking that none of the 30 keys it drops carried a translation. | AI | 6.2 | About screen renders the pod's acknowledgements | — |
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
