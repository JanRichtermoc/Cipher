---
paths:
  - "server/**/*"
---

# Relay

- Read `docs/BACKEND.md`, `docs/THREAT_MODEL.md`, `server/README.md`, and applicable audit findings
  before changing relay code, schema, Docker configuration, logging, auth, retention, or rate limits.
- The relay accepts, stores, and forwards ciphertext only. Never add plaintext, keys, human identity,
  contacts, or trusted sender attribution to its schema, logs, metrics, or API.
- Preserve opaque revocable session tokens, single-use invite semantics, delete-on-delivery behavior,
  bounded attachments, explicit rate limits, and the configured proxy trust boundary.
- Treat migrations and compatibility behavior as permanent until an approved migration proves they
  can be retired. Do not edit committed `server/vendor/` bytes directly.
- Keep `server/.env` private and untracked; verify configuration by effects or safe metadata.
- Run focused Go checks, `./Scripts/verify-relay-integration.sh`, and the full verification for any
  `server/` change. A count floor alone does not prove critical integration tests ran.
- Deployment or public-reachability changes require separate explicit approval and the VPS runbook.
