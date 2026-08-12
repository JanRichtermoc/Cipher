# Cipher documentation map

This index is the entry point for first-party documentation. It separates permanent requirements,
current status, operations, historical evidence, and reference material so an old snapshot cannot
silently override current truth.

## Start here

1. Read the root [`CLAUDE.md`](../CLAUDE.md), which Claude Code loads automatically.
2. Read `CLAUDE_IMPLEMENTATION_PLAN.md`: `STATUS`, §0.2 locked decisions, §0.3 open items, §0.5
   critical findings, §0.6 engineering rules, and the approved step row.
3. Read [`AUDIT.md`](AUDIT.md) §0 plus every OPEN or ACCEPTED finding the task touches.
4. Follow the task map below to load only the relevant normative and operational documents.
5. Read the complete code, tests, build configuration, scripts, and history needed for the change.

Mutable facts must be derived from commands and executable sources. In particular, gate counts come
from `Scripts/verify-all.sh`, tests from fresh test output, versions from manifests and lockfiles,
branch state from Git, CI requirements from GitHub, and deployed state from read-only live checks.

## Authority when sources overlap

| Information | Canonical owner | Overlap rule |
|---|---|---|
| Permanent agent behavior | Root [`CLAUDE.md`](../CLAUDE.md) | Wins over old handoff snapshots and tool-specific rules. |
| Current roadmap status and step definitions | [`CLAUDE_IMPLEMENTATION_PLAN.md`](CLAUDE_IMPLEMENTATION_PLAN.md) | `STATUS` and roadmap row win; verify mutable facts before acting. |
| Locked protocol decisions | Implementation plan §0.2 | Requirements, not backlog suggestions. The threat model supplies rationale. |
| Security finding status and accepted risk | [`AUDIT.md`](AUDIT.md) | Wins over the dated security report, step notes, and prose elsewhere. |
| Threats and standing prohibitions | [`THREAT_MODEL.md`](THREAT_MODEL.md) | Wins for security boundaries; current code/operations prove implementation state. |
| Relay protocol, schema, retention, and pinning | [`BACKEND.md`](BACKEND.md) | Wins over generic architecture prose. Migrations and code prove mechanics. |
| Development and verification commands | [`DEVELOPMENT.md`](DEVELOPMENT.md) and `Scripts/` | Executable scripts and build configuration win over copied prose. |
| Hosting decisions and live operation | [`INFRASTRUCTURE.md`](INFRASTRUCTURE.md) and [`RUNBOOK-VPS.md`](RUNBOOK-VPS.md) | Runbook owns procedures; live read-only checks win for mutable state. |
| Dependency versions and bytes | Manifests, lockfiles, and `Vendor/libsignal/PINS.env` | Never copy versions into always-loaded instructions. |
| Historical implementation evidence | `SECURITY_AUDIT.md` and `STEP_NOTES/` | Evidence only; never overrides current status or `AUDIT.md`. |

## Task reading map

| Task | Read before editing |
|---|---|
| Any implementation or cleanup | Plan sections above and `AUDIT.md` §0 plus applicable rows. Use [`AGENT_HANDOFF.md`](AGENT_HANDOFF.md) for the stable detailed execution checklist; it contains no current status. |
| iOS UI, app state, or Xcode | [`DEVELOPMENT.md`](DEVELOPMENT.md), applicable threat/audit rows, privacy manifest when the shipped bundle changes. |
| Cryptography, identity, keys, wire types, or sealed storage | [`THREAT_MODEL.md`](THREAT_MODEL.md), plan §0.2/§0.6, [`AUDIT.md`](AUDIT.md), [`Vendor/libsignal/DECISIONS.md`](../Vendor/libsignal/DECISIONS.md), and applicable backend sections. |
| Relay, schema, auth, retention, or rate limits | [`BACKEND.md`](BACKEND.md), threat model, audit ledger, [`server/README.md`](../server/README.md), and migrations. |
| Staging, DNS, TLS, pins, backup, or recovery | [`INFRASTRUCTURE.md`](INFRASTRUCTURE.md), [`RUNBOOK-VPS.md`](RUNBOOK-VPS.md), `BACKEND.md` §9, and applicable audit rows. |
| A suspected compromise, key exposure, or lost device | [`RUNBOOK-INCIDENT.md`](RUNBOOK-INCIDENT.md) first — it classifies and routes; then the owning procedure it names. |
| Tests, scripts, or CI | [`DEVELOPMENT.md`](DEVELOPMENT.md), `AUDIT.md` §0 and §6, all affected scripts, workflow configuration, and Xcode target membership. |
| Privacy or release compliance | [`PRIVACY_MANIFEST.md`](PRIVACY_MANIFEST.md), threat model, audit §6, entitlements, manifest, and Release-bundle gates. |
| App icon or visual provenance | [`APP_ICON.md`](APP_ICON.md) and the asset catalog. |
| Review of old decisions | Relevant step note or security report, then reconcile it against the current plan and `AUDIT.md`. |

## First-party document catalog

“Mutable” means the document may intentionally record current state and must be verified before use.
Files under `Pods/` and `server/vendor/` are third-party material and are not part of this catalog.

| Document | Purpose and authority | Kind | Read when | Mutable? |
|---|---|---|---|---|
| [`../CLAUDE.md`](../CLAUDE.md) | Permanent project behavior for Claude Code. | Normative instruction | Every session; automatic. | No |
| [`CLAUDE_CODE_SESSION_PROMPT.md`](CLAUDE_CODE_SESSION_PROMPT.md) | Copyable fresh-session bootstrap that grants one-step continuation, routes optional personal plugins, and points to canonical sources without duplicating status. | Human entry point | Paste into a new local Claude Code session. | No |
| [`README.md`](README.md) | Document authority, precedence, and reading routes. | Normative index | Every task. | No |
| [`AGENT_HANDOFF.md`](AGENT_HANDOFF.md) | Stable human-readable execution, verification, operator, commit, and PR guide. Root `CLAUDE.md` owns the contract; the plan and audit own current state. | Operational guide | Any non-trivial change or release handoff. | No |
| [`CLAUDE_IMPLEMENTATION_PLAN.md`](CLAUDE_IMPLEMENTATION_PLAN.md) | Current phase, locked decisions, open-item summary, and roadmap step definitions. | Current status + normative roadmap | Every roadmap task. | Yes |
| [`AUDIT.md`](AUDIT.md) | Canonical OPEN/CLOSED/ACCEPTED security ledger and recurring failure modes. | Current security authority | Every task touching security or a cited finding. | Yes |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | Adversaries, privacy positions, and standing prohibitions. | Normative security | Any design, protocol, data, logging, or dependency change. | Only explicit “today” snapshots |
| [`BACKEND.md`](BACKEND.md) | Relay modules, schema, retention, auth, rate limits, logging, pinning, and proxy boundary. | Normative protocol + reference | Relay/client transport and deployment work. | Deployment/status notes only |
| [`DEVELOPMENT.md`](DEVELOPMENT.md) | Local setup, commands, toolchain, and pre-push workflow. Scripts win if copied mechanics drift. | Current reference | Building, testing, CI, or onboarding. | Yes |
| [`INFRASTRUCTURE.md`](INFRASTRUCTURE.md) | Hosting/registrar decisions, access model, constraints, and accepted backup residual. | Operational decision record | Infrastructure, domain, provider, or recovery work. | Yes |
| [`RUNBOOK-VPS.md`](RUNBOOK-VPS.md) | Reproducible staging deployment, verification, rollback, and recovery procedures. | Operational | Any staging or TLS change. | Yes |
| [`RUNBOOK-INCIDENT.md`](RUNBOOK-INCIDENT.md) | Incident classification and response: host compromise, TLS key compromise, secret exposure, lost device, impersonation. Routes to the owning procedure rather than restating it. | Operational | A suspected compromise, exposure, or lost device. | Yes |
| [`PRIVACY_MANIFEST.md`](PRIVACY_MANIFEST.md) | Required-reason API inventory and audit method. | Compliance reference | API use, dependency, manifest, or Release changes. | Yes |
| [`APP_ICON.md`](APP_ICON.md) | Icon source, generation, and replacement provenance. | Reference | Icon or asset replacement. | No |
| [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md) | Dated external-style review plus Appendix C remediation crosswalk. `AUDIT.md` owns current status. | Historical audit | Security review and rationale archaeology. | No; preserve report chronology |
| [`STEP_NOTES/README.md`](STEP_NOTES/README.md) | Purpose and limits of step notes. | Historical index | Creating or interpreting a step note. | No |
| [`STEP_NOTES/P5.S09.md`](STEP_NOTES/P5.S09.md) | Account-lifecycle implementation and negative-test evidence. | Historical evidence | Work touching registration, credentials, or account erasure. | No |
| [`STEP_NOTES/P5.S11.md`](STEP_NOTES/P5.S11.md) | Encrypted local database, remediation, quota, and negative-test evidence. | Historical evidence | Work touching sealed storage or local retention. | No |
| [`STEP_NOTES/P9.S04.md`](STEP_NOTES/P9.S04.md) | Monitoring design, the metadata constraint, guards, and the alert-firing drill. | Historical evidence | Monitoring, alerting, or operational-visibility work. | No |
| [`STEP_NOTES/P9.S05.md`](STEP_NOTES/P9.S05.md) | Backup scope and its reasoning, encryption shape, RPO/RTO, guards, and the executed restore drill. | Historical evidence | Backup, restore, retention, or disaster-recovery work. | No |
| [`STEP_NOTES/P9.S07.md`](STEP_NOTES/P9.S07.md) | Internal pen-test checklist: nine items, substrate per item, and live-staging evidence. | Historical evidence | Pen-test, relay hardening, or production-readiness review. | No |
| [`../server/README.md`](../server/README.md) | Relay development, endpoints, environment, and integration-test usage. Backend/audit docs win on design and risk. | Current reference | Relay development. | Yes |
| [`../Vendor/libsignal/DECISIONS.md`](../Vendor/libsignal/DECISIONS.md) | First-party record of libsignal selection, pinning, integration, and verification decisions. | Normative dependency record | Crypto or dependency work. | Only deliberate dependency review |
| [`../NOTICE.md`](../NOTICE.md) | Copyright and third-party attribution. | Legal | Dependency, distribution, or licensing changes. | Yes, only with legal/dependency change |
| [`../LICENSE`](../LICENSE) | Repository license terms. | Legal | Distribution or licensing questions. | No |
| [`../.claude/rules/ios-xcode.md`](../.claude/rules/ios-xcode.md) | Path-scoped iOS/Xcode constraints. | Tool instruction | Automatic on matching paths. | No |
| [`../.claude/rules/cryptography.md`](../.claude/rules/cryptography.md) | Path-scoped cryptography and libsignal constraints. | Tool instruction | Automatic on matching paths. | No |
| [`../.claude/rules/relay.md`](../.claude/rules/relay.md) | Path-scoped relay constraints. | Tool instruction | Automatic on matching paths. | No |
| [`../.claude/rules/verification.md`](../.claude/rules/verification.md) | Path-scoped test, gate, and CI constraints. | Tool instruction | Automatic on matching paths. | No |
| [`../.claude/rules/documentation.md`](../.claude/rules/documentation.md) | Path-scoped documentation authority and consistency rules. | Tool instruction | Automatic on matching paths. | No |
| [`../.cursor/rules/project-authority.mdc`](../.cursor/rules/project-authority.mdc) | Always-applied Cursor bootstrap that routes work to canonical project sources without copying architecture or mutable facts. | Tool instruction | Automatic in Cursor. | No |

## Tool-specific and third-party material

- `CLAUDE_CODE_SESSION_PROMPT.md` names optional user-installed plugins as capability-routing hints.
  It does not make them project dependencies, enable them, or grant them authority over this map.
- `.cursor/rules/project-authority.mdc` is retained for Cursor and owns no project facts; it only
  loads the permanent contract and routes tasks through this documentation map.
- `.codex/` and `.claude/settings.local.json` are machine-local and must not be committed.
- `Pods/**`, `server/vendor/**`, and installed `Vendor/bundle/**` documentation belongs to upstream
  dependencies. It may explain that dependency, but cannot instruct first-party Cipher work.
- `server/vendor/**/CLAUDE.md` is excluded through `.claude/settings.json`; do not edit vendored bytes
  merely to disable upstream instructions.
