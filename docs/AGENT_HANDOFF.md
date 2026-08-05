# Agent handoff — executing one Cipher step

This is the human-readable execution guide for one implementation or cleanup step. Claude Code
loads the root [`CLAUDE.md`](../CLAUDE.md) automatically; that file is the permanent behavioral
contract and wins if this guide conflicts. Do not paste this document into a new session.

Current roadmap state lives only in [`CLAUDE_IMPLEMENTATION_PLAN.md`](CLAUDE_IMPLEMENTATION_PLAN.md),
security finding state only in [`AUDIT.md`](AUDIT.md), and document authority in
[`README.md`](README.md). This guide deliberately contains no current branch, test total, gate
count, dependency version, deployment snapshot, or next-step claim.

## 1. Orient before editing

1. Read `docs/README.md`, then follow its start sequence and task reading map.
2. Inspect the worktree, recent history, local/remote branches, remotes, and relevant open pull
   requests. Derive current state; never select a branch from copied prose.
3. If user work is dirty and the approved scope could overlap it, stop and ask before touching it.
4. Read the plan `STATUS`, §0.2, §0.3, §0.5, §0.6, and the approved step row.
5. Read `AUDIT.md` §0 and every OPEN or ACCEPTED finding the step touches.
6. Read the task-specific sources named by `docs/README.md`, then the complete code, tests, build
   configuration, scripts, CI, and history needed to establish a baseline.
7. Confirm the operator approved exactly one step, its paths do not overlap other work, and no pull
   request already covers it.
8. Classify the step before implementation and report the recommended current model alias and effort
   under root `CLAUDE.md`. If the active model is weaker, stop before editing and give the operator
   the exact model-switch commands.

The plan defines what a product step means. `AUDIT.md` owns security status. Executable sources and
fresh command output own mutable mechanics. If they disagree, stop and resolve the authority conflict
before implementation. Never invent a hash, version, pin, CVE identifier, or repository fact; verify
it from its canonical source or ask.

Optional plugins and memory may reduce output or recover leads from an earlier session, but they are
never evidence of current state. Use only enabled capabilities whose declared scope matches the task;
do not guess commands or change plugin configuration. Never store secrets, private messages, personal
identifiers, or mutable repository/operation status in agent memory. Delegate only an independently
bounded task when separate context or independent review materially improves correctness or security,
not merely to finish faster; verify the result in the main session.

## 2. Repository map

```text
Cipher/                     iOS application
  App/                      authentication, lifecycle, lock, and account cleanup
  Features/                 SwiftUI screens grouped by feature
  Messaging/                repository orchestration and sealed conversation persistence
  Networking/               pinned relay transport, key directory, mailbox, invite redemption
  Security/                 Keychain session state, device authentication, secure pasteboard

CipherCrypto/               Swift crypto boundary; the app talks through CryptoEngine
  Sources/Engine/           session establishment, encrypt/decrypt, published keys
  Sources/Store/            libsignal stores, sealed SQLite rows, key custody and erasure
  Sources/Wire/             fail-closed envelope and payload types
  Sources/Logging/          redacted logging

CipherCryptoTests/          crypto and storage tests
CipherTests/                app and orchestration tests
server/                     Go relay, migrations, unit and integration tests, vendored modules
Scripts/                    repository verification and target-bootstrap commands
docs/                       authority-indexed project documentation and historical evidence
Vendor/libsignal/           first-party pin decisions plus deliberately vendored dependency input
Pods/                       deliberately committed dependency source; preserve supply-chain policy
```

Four boundaries are worth repeating when navigating code, although their full authority remains the
plan, threat model, and audit ledger:

- LibSignalClient types stay out of `CipherCrypto`'s public API, including thrown errors.
- Libsignal access stays on `@CryptoActor`; do not bypass isolation with `@unchecked Sendable`.
- Message bodies stay inside the sealed container and only `CryptoEngine.encrypt` output goes on the
  wire.
- The relay stores ciphertext only, never message plaintext or private keys.

## 3. Detail the approved step

For a non-trivial product step, create or update one `docs/STEP_NOTES/<STEP-ID>.md`. A note expands
the existing roadmap row; it never adds, renumbers, or changes a step.

Record:

- the step ID and its exact `Done when` text;
- the existing source and tests it builds on;
- ordered, independently testable sub-tasks;
- affected AUDIT IDs and the guard for each;
- the defect reintroduced for each new or changed guard;
- operator questions and actions.

If a question changes scope or blocks a safe implementation, ask before writing code. Historical
step notes remain evidence; do not rewrite them to look current.

## 4. Implement and prove

- Change one coherent thing at a time and run focused validation while working.
- Preserve load-bearing comments and update them with the behavior they explain.
- Do not add placeholders, fake success, inert Release controls, or future-step scaffolding.
- Read [`DEVELOPMENT.md`](DEVELOPMENT.md) for current commands and environment traps. Build through
  `Cipher.xcworkspace`, serialize simulator test runs, and let repository scripts derive toolchain
  details.
- If a test file or explicit target member changes, run the documented target-bootstrap procedure,
  run the complete affected target, and prove the exact new test name appeared.
- Every new behavior needs a test. Every new or changed gate needs a positive control plus a defect
  reintroduction that fails for the intended reason. Follow `AUDIT.md` §0, especially R1–R4.
- Run `./Scripts/verify-all.sh` before commit. Derive its gate and test totals from that run. Run
  `./Scripts/verify-relay-integration.sh` as well when `server/` changes.
- A failed or skipped check remains a failure to report. Never weaken a test or gate to obtain green.

## 5. Keep the authorities consistent

Update only documents whose owned facts changed:

- implementation plan: roadmap state and step completion;
- `AUDIT.md`: finding state, invariant, and tested guard;
- threat model/backend: security or protocol reasoning;
- runbook/infrastructure: procedures and observed operations;
- step note: implementation and negative-test evidence.

Do not duplicate mutable totals, versions, branches, deployments, or operator actions into this guide
or root instructions. Preserve historical evidence and accepted risk. Check every changed link and
heading anchor.

## 6. Review, commit, and hand off

Before committing:

1. Review `git status`, the complete diff, `git diff --check`, untracked/ignored files, and exact
   intended paths.
2. Stage exact paths rather than the entire worktree.
3. Review the staged diff for secrets and private information without printing suspicious values.
   If likely private material appears, follow the stop procedure in root `CLAUDE.md`.
4. Re-run any validation affected by staging or final documentation edits.
5. Follow recent repository history for commit subject, explanatory body, and co-author convention.
   When a gate changed, include the observed negative-test failure in that evidence.

Push the focused branch and open a pull request through an authenticated available integration. If
that is impossible, give the operator the compare link and a numbered tutorial. Report scope,
preserved information, findings, verification, negative-test evidence, unresolved work, and the next
recommended step. Never merge without explicit approval, and stop after the pull request.

## 7. Operator action

When credentials, a provider console, DNS, GitHub settings, a purchase, physical devices, or an
operator-only judgment blocks the step, stop at the nearest safe boundary. Give a numbered tutorial
with one action per step, exact labels or commands, expected results, final verification, rollback
for risky actions, and the exact result to send back. Do not continue other work around the blocker.

Existing staging access may be used only within already approved scope. Confirm first before changing
public reachability, risking availability, rotating credentials, or modifying provider/GitHub state.

## 8. Final checklist

- [ ] Exactly one approved step and one focused branch/PR.
- [ ] No unrelated refactor, later work, protocol change, or dependency change.
- [ ] Focused validation passed; new tests and negative tests were observed by name.
- [ ] Full current repository verification passed; relay integration ran if required.
- [ ] Canonical status, finding, operational, and historical documents remain consistent.
- [ ] Exact staged paths and the staged public/secret boundary were reviewed.
- [ ] PR link, evidence, preserved information, unresolved work, and next recommendation reported.
- [ ] Work stopped after the PR.
