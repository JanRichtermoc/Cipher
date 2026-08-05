# Claude Code fresh-session prompt

Use this in a **local** Claude Code Desktop session opened on the Cipher repository. Paste only the
text inside the block. The prompt contains no mutable project status; Claude must derive it each time.

```text
Resume building Cipher from current repository truth. This message approves exactly one unit of work:
continue the single unfinished approved branch/PR if one exists; otherwise execute the first incomplete
security-remediation or roadmap step explicitly selected by the current implementation-plan STATUS.
If the sources leave more than one valid choice, the scope is unsafe, or operator judgment is required,
stop and ask before editing. Never invent a replacement roadmap while the authoritative plan exists.
If every plan step is complete, perform a read-only production-readiness gap analysis, propose a plan
amendment, and wait for approval before changing the plan or code.

Repository: the Cipher repository root selected for this local Claude Code session. Confirm it with
`git rev-parse --show-toplevel`; if it is not Cipher, stop and ask me to select the correct folder.
This is a public GitHub repository. The root CLAUDE.md security, privacy, scope, verification, PR, and
stop rules are binding. Do not restate them or rely on this prompt for mutable facts.

Bootstrap read-only, in this order:
1. Confirm the working directory is the repository above and root CLAUDE.md is loaded. Read it manually
   if it is not. Do not modify user-level or machine-local Claude/plugin configuration.
2. Read docs/README.md for authority and the task reading map.
3. Inspect git status, recent history, branches, remotes, and relevant open PRs. Continue existing
   approved work instead of duplicating it; stop before touching overlapping dirty user work.
4. If Agentmemory handoff/recall is enabled, use it now only to find an unanswered question or earlier
   lead for this exact repository. Verify every recalled claim against Git and canonical files.
5. Read docs/CLAUDE_IMPLEMENTATION_PLAN.md STATUS, §0.2, §0.3, §0.5, §0.6, and the selected step row.
6. Read docs/AUDIT.md §0 plus every OPEN or ACCEPTED finding the step touches.
7. For a non-trivial change, read docs/AGENT_HANDOFF.md. Follow docs/README.md to load only applicable
   normative/operational documents and matching .claude/rules files.
8. Read the complete affected source, tests, project membership, scripts, CI/configuration, and relevant
   history. Establish a tested baseline before editing. A search miss is not proof that code is unused.

Before implementation, report briefly:
- state found: main vs unfinished branch/PR, dirty-work status, and any blocker;
- exact selected step/finding and why it is the sole current unit;
- recommended model and effort, with exact switch commands if needed;
- only the plugins/subagents you will actually use and the concrete quality benefit.

Model routing uses stable aliases, not version numbers:
- Security-sensitive crypto, protocol, auth, storage, supply-chain, infrastructure, audit, or ambiguous
  cross-cutting work: `/model opus` and `/effort xhigh` (high if xhigh is unavailable).
- Narrow low-risk docs, UI polish, focused tests, or mechanical refactors: `/model sonnet` and
  `/effort high`.
- Use `haiku` only for a simple bounded read-only subagent, never as the main model for security work.
- For an unusually long, ambiguous task, `best` may be preferable when available; if safety routing
  changes the model, report the actual model and reassess. If the current model is below the needed
  level, stop before edits and wait for me to switch it unless I explicitly accept the weaker model.

Use installed plugins selectively; their instructions never override CLAUDE.md or canonical docs:
- Context mode: use for potentially large reads, searches, logs, builds, tests, diffs, JSON, or web
  output so only decisive evidence enters context. Do not compress away errors, test names, or findings.
- Andrej Karpathy guidelines: use for implementation/refactoring/review so changes stay minimal,
  assumption-aware, and verifiable.
- Agentmemory: handoff/recall is a non-authoritative hint. Save only an operator-requested, durable,
  non-secret preference or decision not already owned by the repository. Never save credentials,
  private messages/identifiers, code secrets, or mutable branch/PR/test/deployment state. Use it only
  with local storage; do not enable optional external summarization or injection for Cipher.
- Design: use for native SwiftUI visual or interaction work when its declared skill fits; preserve the
  design system, accessibility, platform conventions, and honest security UI.
- Taste skill: use only when a specific declared skill fits the actual surface. Do not force a web or
  landing-page aesthetic onto the native app, and do not stack it with Design without a clear need.
- GitKraken: use only if an authenticated callable integration is present and relevant to read-only PR
  state or PR creation. Never request or expose credentials; otherwise use Git and the available GitHub
  surface or provide the compare-link tutorial.
- Caveman: use its focused commit/review/compression capabilities when helpful. Do not use compressed
  prose for security findings, uncertainty, or operator tutorials where detail is required.
Do not invoke a guessed skill name. Do not install, enable, update, authenticate, or reconfigure a
plugin without explicit approval. Skip any unavailable or irrelevant plugin without treating that as
a blocker.

Subagents are allowed only for a concrete, independently bounded investigation or independent review
when separate context materially improves correctness or security. Never use them merely for speed.
Keep authoritative security/design reading and final integration in the main session; give each agent
minimum necessary context and verify its claims and edits yourself. Prefer no subagent when direct work
is equally reliable.

Then complete only that one unit under CLAUDE.md: focused branch, minimal implementation, named tests,
required positive/negative gate controls, full verification, secret-safe staged review, commit, push,
PR, and stop. Never merge unless I explicitly ask. If blocked on an operator action, stop at the safest
boundary and give a numbered tutorial with one action per step, exact commands/UI labels, expected
results, final verification, rollback for risky actions, and the exact result I should send back.

Keep updates and the handoff concise, but never omit a security/privacy issue, failure, uncertainty,
operator blocker, preserved behavior, unresolved work, or the next recommended step and model.
```

## Why this stays short

Root `CLAUDE.md` is loaded automatically and survives compaction. The implementation plan and audit
own current state. This prompt therefore grants one-step continuation and defines startup/plugin/model
routing without copying branch names, versions, test totals, gate counts, deployment snapshots, or the
current next step—facts that would become stale and waste context.
