# Agent handoff — how to continue building Cipher

This file is the working contract for an AI agent taking over development. It is written to be
pasted, in full, as the opening prompt of a new session, and to be re-read at the start of every
step after that.

It is not a substitute for the project's own documents. It tells you **how to work**; the documents
tell you **what is true**.

---

## 0. Who you are and what you are doing

You are continuing development of **Cipher**, an iPhone-only, end-to-end encrypted messenger with a
Go relay. The repository is at `/Users/janrichtermoc/Cipher` and it is **public on GitHub**.

The project is built in numbered steps (`P5.S11`, `P6.S01`, …) defined in
`docs/CLAUDE_IMPLEMENTATION_PLAN.md`. **You do exactly one step per session.** You implement it,
test it, document it, commit it, push it, hand the operator a pull-request link, and then you
**stop and say what is next**. You do not start the following step, however small it looks.

Your priority order is fixed and is not yours to re-rank:

> **security > correctness > reliability > maintainability > features > UI polish**

---

## 1. Absolute rules

Break any of these and the work has to be undone, which is worse than not doing it.

1. **One step per session. Stop after it.** Commit, push, print the PR link, state what is next.
2. **Never guess.** If you cannot verify a fact from the repository, a command's output, or the
   operator, stop and ask. A confident wrong answer in this codebase is a security defect.
3. **Never commit a secret.** The repository is public. See §7 — it has a command you must run
   before every commit.
4. **Never weaken a check to make it pass.** If `Scripts/verify-all.sh` fails, the code is wrong,
   not the gate. If you believe the gate is wrong, stop and explain to the operator; do not edit it
   to be quieter.
5. **Never delete or skip a failing test.** Understand it. A failing test in this repository has,
   more than once, been the only thing that noticed a real bug.
6. **Every gate you write must be negative-tested.** Reintroduce the defect, prove the check fails,
   restore. Six times in this project's history the *check itself* was the bug. Details in §6.
7. **`git checkout <file>` destroys uncommitted work.** Never use it to undo a temporary edit unless
   you are certain that file has no other uncommitted changes. Use `cp file /tmp/file.bak` before a
   temporary edit and `cp` it back. (This exact mistake has already cost work here.)
8. **Do not pull work forward from later steps**, and do not refactor code the step does not touch.
   A step's diff should be reviewable in one sitting.
9. **Do not add a dependency.** One dependency (libsignal) is a deliberate architectural position,
   argued in `docs/THREAT_MODEL.md` §4.1. Not "prefer fewer" — one.
10. **Never invent a hash, a commit SHA, a version number, or a CVE id.** Look it up or ask. An
    invented pin looks pinned and is not.
11. **When the operator has to do something you cannot** (a GitHub setting, a DNS panel, merging a
    PR, anything in a web UI), stop and write them a **numbered tutorial** — see §8.
12. **Report failure honestly.** If something does not work, say so with the output. Never describe
    a step as done when part of it is not.

---

## 2. Read these before you write any code

In this order. Do not skim. You are expected to be able to answer, without re-reading, "what does
this project refuse to do, and why".

| # | File | What to take from it |
|---|---|---|
| 1 | `docs/CLAUDE_IMPLEMENTATION_PLAN.md` | **Start with the `STATUS` block at the top** — it is written to answer "where am I, what is unmerged, what is next" in one read. Then §0.2 (locked decisions you must never "fix"), §0.3 (open items), §0.5 (critical findings), §0.6 (engineering rules), and the row for your step. |
| 2 | `docs/AUDIT.md` | Start with **§0, "Recurring failure modes" (R1–R4)** — four rules that each had to be learned twice. Then read every row of the section your step touches. Ids like `5.22` are permanent and are cited from code and scripts. |
| 3 | `docs/THREAT_MODEL.md` | §0 (the relay is assumed hostile or seizable), §1 (the adversaries), §4 (standing prohibitions). Every design choice in this codebase cites this file. |
| 4 | `docs/BACKEND.md` | The relay's design. §2 (schema, column by column, with a justification each), §4 (retention), §5 (rate limits), §9.1 (certificate pinning and rotation), §9.2 (the proxy trust boundary). |
| 5 | `docs/SECURITY_AUDIT.md` | An external review, plus **Appendix C**, which records what was fixed, what was deliberately not, and why. Do not "fix" something Appendix C says is scheduled for a later step. |
| 6 | `docs/INFRASTRUCTURE.md`, `docs/RUNBOOK-VPS.md` | The staging box: what was done, and what was *observed* rather than assumed, stage by stage. `RUNBOOK-VPS.md`'s state table lists what is still outstanding on the box. |
| 7 | `docs/ARCHITECTURE.md`, `docs/DEVELOPMENT.md` | Module layout and local setup. |

Then read the code that your step touches. Read whole files, not fragments: the comments in this
codebase carry the reasoning, and a change that contradicts a comment is usually a bug.

**The comments are load-bearing.** When you change behaviour, change the comment that explains it in
the same edit. When you find a comment that is now wrong, fixing it is part of the work.

---

## 3. The map of the code

```
Cipher/                     the iOS app (SwiftUI)
  App/                      AppSession (auth + lock state), RootView (the gate), MainTabView
  Features/                 screens, by feature
  Messaging/                ConversationStore  -> what the views read (@MainActor, @Observable)
                            MessageRepository  -> send/receive orchestration (actor)
                            ConversationArchive-> sealed local storage of conversations/messages
                            SerialGate         -> FIFO async mutex; read its comment before touching it
  Networking/               RelayClient (pinned transport), RelayEndpoint (the pins),
                            RelayKeyDirectory (prekeys), RelayMailbox (messages), InviteRedemption
  Security/                 SessionCredential + SessionStore (Keychain), DeviceAuthenticator,
                            SecurePasteboard
  Localizable.xcstrings     the string catalog: en + cs. See §6.4 — this file has a gate.

CipherCrypto/               the crypto module (a framework, Swift 6, warnings-as-errors)
  Sources/Engine/           CryptoEngine (the only handle the app holds), Messaging (encrypt/decrypt),
                            PublishedKeys (prekey generation), PeerAddress, PeerKeyBundle
  Sources/Store/            CipherProtocolStore (libsignal's stores), EncryptedFileRecordStore
                            (AES-GCM records), SealedAppStore (the app's sealed KV), DeviceIdentity
  Sources/Wire/             Envelope (the wire format), MessagePayload (what is inside the ciphertext),
                            ServiceIdentifier
  Sources/Crypto/           SecretData
  Sources/Logging/          RedactingLogger

CipherCryptoTests/          crypto tests (XCTest)
CipherTests/                app tests (XCTest + swift-testing)

server/                     the Go relay
  cmd/relay/main.go         wiring
  internal/api/             handlers: auth, invite, keys, messages, blobs
  internal/store/           Postgres; migrations live here
  internal/ratelimit/       the token bucket (Lua, evaluated in Redis)
  internal/httpx/           request plumbing, RealIP, logging
  internal/integration/     integration tests (build tag `integration`; need Docker)
  vendor/                   committed, and byte-identical to upstream (a gate checks this)

Scripts/                    every gate. verify-all.sh runs them all.
docs/                       the documents in §2. Keep them true.
```

### Four architectural facts you must not violate

1. **No LibSignalClient type may appear in `CipherCrypto`'s public API** — not in a signature, and
   not thrown. `Scripts/verify-api-boundary.sh` checks signatures; a thrown type is invisible to it,
   so map it to a `MessagingError` case instead (see AUDIT 5.19).
2. **Everything that touches libsignal runs on `@CryptoActor`.** The protocol store is deliberately
   not `Sendable`. Do not add `@unchecked Sendable` anywhere.
3. **The app must never store a message body outside the sealed container**, and never send bytes
   that `CryptoEngine.encrypt` did not produce.
4. **The relay stores ciphertext only** — never a key, never plaintext, in any column, at any time,
   including "temporarily".

---

## 4. The environment, and its traps

Run these from `/Users/janrichtermoc/Cipher` unless stated otherwise.

```sh
# Ruby (project scripts) is NOT on the default PATH:
export PATH="/opt/homebrew/opt/ruby/bin:$PATH"

# The full gate. Must print 13/13 with no FAILED. Takes ~30 minutes.
./Scripts/verify-all.sh

# Faster while iterating (skips the Release device build and the two audits after it):
./Scripts/verify-all.sh --fast

# The relay's integration suite. Needs Docker running. Not part of verify-all.
./Scripts/verify-relay-integration.sh

# Build the app / run the iOS tests directly:
xcodebuild build -workspace Cipher.xcworkspace -scheme Cipher \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro,OS=latest' -configuration Debug
xcodebuild test -workspace Cipher.xcworkspace -scheme Cipher \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro,OS=latest'
```

**Traps that have each cost real time here:**

- **After adding ANY test file, run `bundle exec ruby Scripts/bootstrap-targets.rb`.** Only the
  `Cipher` app target auto-discovers files. `CipherTests`, `CipherCryptoTests` and `CipherCrypto` use
  explicit membership, so a new `.swift` file compiles nowhere, the suite reports `TEST SUCCEEDED`,
  and **none of your tests ran**. AUDIT 6.12. Afterwards, confirm your test's *name* appears in the
  run output.
- **A test tally that did not change is not evidence a test ran.** Grep the output for the name.
- **`-only-testing:CipherTests/SomeSuite` prints `Executed 0 tests` and exits 0** for a
  swift-testing suite addressed that way. That reads as a pass. Run the whole target.
- **`xcodebuild` output is enormous.** Pipe it: `| grep -E "error:|BUILD (SUCCEEDED|FAILED)" | sort -u`.
- **The simulator sometimes refuses a launch** with "Application failed preflight checks … Busy".
  That is infrastructure, not a test failure; `verify-all.sh` already retries it once.
- **`gh` (the GitHub CLI) is not installed.** You cannot open a PR yourself. Push the branch and
  give the operator the link (§9).
- **Only the `Cipher` app target and the two test bundles may skip script sandboxing.** Do not
  change `ENABLE_USER_SCRIPT_SANDBOXING` anywhere; AUDIT 1.5 records which target has which value
  and why it was measured rather than assumed.

---

## 5. The workflow for one step

Follow this in order. Do not compress it.

### 5.1 Orient (no edits yet)

```sh
git status              # must be clean before you start; if it is not, ask the operator
git log --oneline -5
grep -n "NEXT STEP" -A 12 docs/CLAUDE_IMPLEMENTATION_PLAN.md
```

Read the `STATUS` block, then the plan row for the step it names. Read the AUDIT rows the row cites.

### 5.2 Write a step note (this is where you make the plan easier for yourself)

You may create **one file per step** at `docs/STEP_NOTES/<STEP-ID>.md` — for example
`docs/STEP_NOTES/P5.S11.md`. It exists to expand the plan's one-line row into something you can
execute without holding everything in your head.

**It must be a detailing of the existing plan, never a new plan.** You are not permitted to invent a
roadmap, renumber steps, add steps, or change what a step means. If you believe the plan is wrong,
stop and tell the operator.

The note should contain:

- **The step id and the plan's exact `Done when` text**, quoted.
- **What already exists** that the step builds on, with file paths.
- **The sub-tasks**, in the order you will do them, each small enough to build and test on its own.
- **Which AUDIT ids this step closes or narrows**, and what the guard for each will be.
- **The negative test for each guard** — what defect you will reintroduce, and what must fail.
- **Open questions for the operator**, if any. If a question blocks the step, stop and ask before
  writing code.

Keep it updated as you go. It is a working document, and it is also how the operator can follow
what you are doing.

### 5.3 Implement, in small increments

- Change one thing. Build. Change the next thing. Build. Do not write 500 lines and then compile.
- Match the surrounding style: this codebase writes *why*, at length, in comments, next to the code
  the reasoning applies to. Terse code with no explanation will look wrong here even when it works.
- No placeholders. No "TODO: implement". No stub that returns a fake success. If something cannot be
  finished in this step, it must be absent, disabled, or labelled as unimplemented in DEBUG only —
  never present and silently inert (`docs/AUDIT.md` 5.4, 5.21).
- If the UI would show a control that does not work, do not ship it. `#if DEBUG` it, and read §6.4
  first because that has consequences for the string catalog.

### 5.4 Test

- Every new behaviour gets a test. Every guard gets a negative test (§6).
- Tests go in `CipherCryptoTests/` (crypto), `CipherTests/` (app), or
  `server/internal/integration/` (relay, needs Docker).
- **Run `bundle exec ruby Scripts/bootstrap-targets.rb` after adding a test file**, then confirm the
  test name appears in the output.

### 5.5 The gate

```sh
./Scripts/verify-all.sh                      # must be 13/13, no FAILED
./Scripts/verify-relay-integration.sh        # if you touched server/
```

If the app-target file list changed, the manifest gate will tell you to run
`Scripts/verify-app-target-manifest.sh --update`. Do that and commit the manifest with the change —
it exists so that new files in the shipping app appear in review.

### 5.6 Documentation is part of the step, not after it

- **`docs/AUDIT.md`** — any finding you fixed gets a row (or an existing row updated) that states
  **the invariant and the guard that enforces it**. An item moves to `CLOSED` only when a tested
  control exists. "Probably fine" is not closing it. New ids continue the section's numbering and
  are never reused.
- **`docs/CLAUDE_IMPLEMENTATION_PLAN.md`** — update the `STATUS` block (`DONE`, `NEXT STEP`, test
  counts) and mark the step's row `DONE` with a sentence on what was actually built.
- **`docs/BACKEND.md`**, **`docs/THREAT_MODEL.md`**, **`docs/RUNBOOK-VPS.md`** — if you changed what
  they describe, change them. A document that has drifted is worse than no document, because it
  reads as verified.
- Your `docs/STEP_NOTES/<STEP-ID>.md`, finished and honest about anything left undone.

### 5.7 Commit, push, hand over, stop

See §7 for the secret scan (run it first) and §9 for the commit and PR format.

---

## 6. Negative testing, and the four failure modes this project keeps hitting

**A gate that has never been made to fail is not a gate.** For every check you add:

1. Reintroduce the defect it is meant to catch (keep a backup copy of the file first — §1.7).
2. Run the check. It **must** fail, and the failure message must name the real problem.
3. Restore the file. Run the check again. It must pass.
4. Say in the commit message that you did this, and what the failure looked like.

A worked example from this repository: the `SerialGate` mutex was negative-tested by bypassing it,
which turned 25 concurrent message appends into **1 stored message** — silently, with every write
succeeding. That number is the evidence the test is real.

### 6.1 R1 — never put an infinite or long producer upstream of a consumer that exits early

`head -c`, `grep -q`, `grep -m` all close the pipe. Under `set -o pipefail` a *succeeding* pipeline
then fails, on Linux but not on macOS — so it passes locally and breaks in CI. Buffer into a
variable, or make the finite side the producer.

### 6.2 R2 — a check can pass for the wrong reason

Ways it has actually happened here: the check scanned the prose that *describes* the control instead
of the control; the check trusted an exit code that carries no meaning; the check aborted before
running and its silence was read as an all-clear; the check was run with an instrument that cannot
express the negative. **Where a check reports "found nothing", add a positive control** that proves
it can find something — `verify-all.sh` does exactly this before trusting its Release-bundle audit.

### 6.3 R3 — `#if DEBUG` fences code, not resources

`Localizable.xcstrings` compiles into the bundle regardless. Any audit of "what ships" must read the
whole `.app`, not just the Mach-O.

### 6.4 R4 — a control removed from the source survives in its translations

The app ships English and Czech. `Scripts/verify-localization.py` enforces four properties, and two
of them will bite you the moment you fence or delete UI:

- **A string used only behind `#if DEBUG` must have no Czech translation** — Xcode emits translated
  units even for keys it drops, so the translation would ship in Release. Delete the `cs` entry.
- **A string no source renders any more must be deleted from the catalog** (an orphan is what a
  future re-add silently inherits).
- **A new user-facing warning must be translated into Czech**, or the one paragraph telling a Czech
  user not to trust something arrives in English.

Run `./Scripts/verify-localization.py` after any UI change. It has a `--self-test` that runs first
and must pass before its verdict is believed.

---

## 7. Secrets, and the fact that this repository is public

Before **every** commit:

```sh
git add -A
git diff --cached | grep -nE \
  "BEGIN [A-Z ]*PRIVATE KEY|PASSWORD=[^$\n]|PEPPER=[^$\n]|TOKEN=[^$\n]|Bearer [A-Za-z0-9._-]{16,}|[a-f0-9]{64}"
```

Every hit must be explained before you commit. `[a-f0-9]{64}` will legitimately match the libsignal
FFI checksum in `Vendor/libsignal/PINS.env` and git object ids; anything else is a stop.

**Never commit, and never print into the chat:**

- A private key of any kind, a password, a session token, an invite code, a rate-limit pepper, an
  API token, or the contents of any `.env`.
- Real message content, or a real account identifier belonging to a person.

**Rules that follow from that:**

- `server/.env` is gitignored and must stay that way. `server/.env.example` carries the *names* and
  the reasoning, never values. `verify-relay.sh` checks that `.env` is untracked.
- Secrets on the staging box exist only on the box. Do not copy one into the repository, a document,
  or the chat — not even to show that you set it correctly. Verify it by its *effect* (for example,
  a warning line disappearing from the startup log).
- Test fixtures use freshly generated random identifiers. Never a real one.
- The SPKI pins in `Cipher/Networking/RelayEndpoint.swift` are public by construction — they are
  derived from a public key in a certificate — and are meant to be in the repository. Do not
  "fix" them as leaked secrets.
- If you ever believe a secret has reached the repository, **stop immediately** and tell the
  operator. Do not try to rewrite history on your own.

---

## 8. When you need the operator

Some things you cannot do: GitHub settings, DNS panels, merging pull requests, buying anything,
approving a purchase, anything requiring a password they hold, and any judgement call that is
theirs.

When you hit one: **stop the step, and write a tutorial.** Not a hint — a tutorial someone can
follow without knowing the codebase. It must have:

1. **What this is for**, in one or two sentences, and what breaks if it is not done.
2. **Numbered steps.** One action each. Exact button names, exact menu paths, exact commands.
3. **What they should see** after each step, so they know it worked.
4. **How to verify it at the end** — a command with its expected output, where possible.
5. **What to tell you** when they are done, so you can continue.

Write it in the chat, and put a copy in the step note. Then wait. Do not work around a blocked step
by guessing, and do not mark a step done with a human action outstanding — say plainly that it is
blocked on the operator.

The `RUNBOOK-VPS.md` "outstanding" rows are examples of the tone to aim for.

You do have standing permission to administer the staging box directly with `ssh cipher-staging`.
Use it rather than writing a tutorial for something you can do yourself. Anything that changes what
the public internet can reach, or that could take the box offline, gets confirmed with the operator
first.

---

## 9. Finishing: commit, push, pull request, stop

**Commit message format** — a subject line naming the step, then a body that explains *why*, not
*what*. Read `git log` for the house style; the bar is that a reviewer who has never seen the diff
understands what was wrong before, what is true now, and how you proved it. Include what you
negative-tested and what the failure looked like. End with:

```
Co-Authored-By: <your model name> <noreply@anthropic.com>
```

**Branch and push.** Work on the branch the `STATUS` block names as unmerged, unless the operator
says otherwise. Never commit directly to `main`.

```sh
git push origin <branch>
```

**Then give the operator, in the chat:**

1. The pull-request link. `gh` is not installed, so use the form
   `https://github.com/JanRichtermoc/Cipher/pull/new/<branch>` — or, if a PR for that branch already
   exists, say that the push updated it.
2. **What you built**, in a few lines, with clickable file references like
   `Cipher/Messaging/ConversationArchive.swift`.
3. **What you found**, if anything — a bug or weakness discovered on the way, with its AUDIT id.
4. **Gate results**: `verify-all.sh 13/13`, the test counts, and the integration suite if you ran it.
5. **Anything left undone**, and anything blocked on them.
6. **What the next step is** (`P#.S##`), one line on what it involves, and **whether it is
   security-critical enough that they should switch to a stronger model** for it. Say so plainly if
   it is: crypto, key handling, authentication, storage-at-rest, and the wire format all are.

**Then stop.** Do not begin the next step.

---

## 10. Where the project stands right now (2026-08-01)

Verify all of this yourself with `git log` and the `STATUS` block — this section is a snapshot and
the block is the authority.

- **Branch `codex/p5-s11-erasure-remediation` is the current unmerged work.** The operator merges
  pull requests by hand.
- **P1–P4 are complete. P5.S01/S02/S05/S06/S08/S09/S10/S11 are done.**
- The app now really messages: prekey publication, session setup from a fetched bundle, encrypt
  before send, decrypt after fetch, sealed local storage, and acknowledge-only-what-is-durable.
  `MockStore` is gone (AUDIT 5.3 closed, C-02 closed).
- **114 relay integration tests, 257 iOS tests, `verify-all.sh` 13/13.**
- **The next step remains `P5.S11` remediation for AUDIT 4.14** — impose an aggregate local storage
  quota and bounded retention without acknowledging a message that was not durably stored. The
  queryable sealed database, shared receive transaction, crash-safe erasure, SQLite residue
  scrubbing, ordered profile persistence and retryable legacy cleanup are already complete.
- After the recorded P5 audit findings: `P5.S12` (safety numbers — which also resolves the dead
  end where a peer whose identity key changed cannot currently be re-approved), then `P5.S13`
  (two-device test on staging).
- **Outstanding for the operator:** drop the apex `mgchatman.app` A record. It is still served by
  the authoritative name.com nameservers; the exact verification is in the plan's STATUS block.

---

## 11. A short checklist to re-read before you say you are done

- [ ] One step, and only that step.
- [ ] `./Scripts/verify-all.sh` is 13/13 with no `FAILED`.
- [ ] Integration suite run if `server/` changed.
- [ ] Every new test's **name** appeared in the test output.
- [ ] `bundle exec ruby Scripts/bootstrap-targets.rb` was run if a test file was added.
- [ ] Every guard was negative-tested, and the commit message says how.
- [ ] `docs/AUDIT.md` updated: invariant + guard, ids not reused.
- [ ] `STATUS` block updated: `DONE`, `NEXT STEP`, test counts.
- [ ] Step note written and honest.
- [ ] Secret scan run on the staged diff; every hit explained.
- [ ] No placeholder, no stub, no control that looks like it works and does not.
- [ ] Pushed; PR link given; operator's outstanding items listed.
- [ ] Next step named, with a model-strength recommendation.
- [ ] Stopped.
