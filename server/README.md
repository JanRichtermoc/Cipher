# Cipher relay

The store-and-forward relay. Go, PostgreSQL, Redis, one binary.

**Design:** [`docs/BACKEND.md`](../docs/BACKEND.md) — read it before changing the schema.
**Threat model:** [`docs/THREAT_MODEL.md`](../docs/THREAT_MODEL.md) — read it before changing anything.

This server is assumed **hostile or seizable**, including when its operator is us. It holds no
plaintext, retains nothing past delivery, and has no administrative interface at all.

---

## Status

**P4.S09 — the relay is feature-complete for P4.** Invite → session token → prekeys → send →
fetch → ack, plus attachment slots, delete-on-delivery and an hourly retention sweep.

| | | |
|---|---|---|
| `GET` | `/health` | no auth |
| `GET` | `/health/ready` | no auth |
| `POST` | `/v1/invite/redeem` | no auth — single-use, expiring, 5/hour/IP |
| `POST` | `/v1/invite` | **auth** — issue an invite, 3/day/account |
| `POST` | `/v1/auth/rotate` | **auth** — exchange for a fresh token, 10/hour |
| `DELETE` | `/v1/auth` | **auth** — sign out this session |
| `DELETE` | `/v1/auth/all` | **auth** — sign out everywhere, including here |
| `PUT` | `/v1/keys` | **auth** — publish your own prekeys, 6/day |
| `GET` | `/v1/keys/{aci}` | **auth** — fetch a bundle, 10/hour and 30/day |
| `POST` | `/v1/messages` | **auth** — send an envelope, 60/min |
| `GET` | `/v1/messages` | **auth** — fetch pending, 120/min, batches of 100 |
| `POST` | `/v1/messages/ack` | **auth** — delivered means **deleted** |
| `POST` | `/v1/blobs` | **auth** — upload, ≤100 MiB, 100/day |
| `GET` | `/v1/blobs/{id}` | **auth** — the id *is* the capability |
| `DELETE` | `/v1/blobs/{id}` | **auth** — shred early |

### Creating the first account

There is no admin API and there never will be (`BACKEND.md` §8), so the first invite is minted by
a command on the host rather than by an authenticated call:

```sh
docker compose run --rm api --issue-invite
```

The code is printed once and is never stored or logged — only its SHA-256 reaches the database.
Redeem it, which creates the account **and** returns its first session token:

```sh
curl -sS -X POST http://127.0.0.1:8080/v1/invite/redeem \
  -H 'Content-Type: application/json' \
  -d '{"code":"<the code>","identity_key":"<base64, 32-64 bytes>","registration_id":1234}'
# -> {"aci":"…","token":"…","token_expires_at":"…"}
```

Every later invite is issued by an account that already exists:

```sh
curl -sS -X POST http://127.0.0.1:8080/v1/invite -H "Authorization: Bearer $TOKEN"
```

**Who issued it is never recorded.** The `invites` table has two columns and neither is
`created_by` — the invite graph is the social graph of a closed circle, and it is the most valuable
thing a seizure could recover. The per-account cap that stops unbounded minting is a Redis counter
keyed by an HMAC of the account id; it expires, and a column would not.

---

## Running it

```sh
cp .env.example .env
# fill in POSTGRES_PASSWORD and REDIS_PASSWORD — there are no defaults
docker compose up --build
curl -sS http://127.0.0.1:8080/health
curl -sS -i http://127.0.0.1:8080/health/ready
```

Migrations apply automatically at startup. To start over:

```sh
docker compose down -v      # -v also drops the Postgres volume
```

### Without Docker

The unit tests need neither Postgres nor Redis:

```sh
go test ./...
```

The full fast gate — build, vet, gofmt, race tests, and the compose invariants — is:

```sh
../Scripts/verify-relay.sh
```

It also runs as gate 4 of `Scripts/verify-all.sh`, before anything that invokes `xcodebuild`,
so a relay defect surfaces in seconds rather than after a half-hour simulator build.

### Integration tests

Against a real Postgres and a real Redis, because the two properties that matter most cannot be
demonstrated against fakes — single use is enforced by one SQL statement being atomic, and expiry
by a predicate evaluated on the database's clock:

```sh
../Scripts/verify-relay-integration.sh
```

They run **inside** the compose network. Publishing Postgres to the host so a host-side test
process could reach it is the anti-goal P4.S02 names, and "only for tests" is how that exposure
always begins — so `docker-compose.test.yml` adds a runner container instead, and the script
asserts against the *running* containers that neither datastore has a host binding.

---

## Things that look like details and are not

**Only `api` publishes a port, and only on `127.0.0.1`.** `ports: "8080:8080"` — the form every
tutorial shows — binds `0.0.0.0`, which publishes the service to every interface including the
LAN. On a laptop on a café network that is a relay on the internet. `Scripts/verify-relay.sh`
fails if any other service gains a `ports:` entry or if `api` stops binding loopback.

**Redis persistence is off, and the relay refuses to start if it is not.** Persistence is *on* by
default in the standard image. Redis holds routing metadata — rate-limit counters, presence,
quota — and leaving the default on writes all of it to disk, silently reinstating the retention
the schema is designed to avoid. `docker-compose.yml` passes `--save "" --appendonly no`,
`cache.AssertNoPersistence` asks the running server directly at startup, and `verify-relay.sh`
checks the compose file. Three layers because the default is wrong and the failure is silent.

**Base images are pinned by digest, not tag.** A tag is a pointer its publisher can move. This is
the same rule `docs/AUDIT.md` 1.8 applies to GitHub Actions and 1.3 to libsignal, and a base image
has the largest blast radius of the three because everything in it runs as the service.

**`vendor/` is committed.** The container build then needs no network at all, so it cannot pull a
substituted dependency, and every dependency byte appears in the diff on every bump — the same
property `.gitignore` states for `Pods/`.

**The runtime image is `scratch`.** No shell, no package manager, no libc. Remote code execution
lands in an image containing exactly one executable, and there is nothing to patch. The cost:
debugging needs a sidecar rather than `docker exec`, and the health check has to be the binary
itself (`relay --health-check`).

**Attachment bytes live on the filesystem, not in Postgres.** Shredding a file is one `unlink`;
a deleted `BYTEA` persists in table bloat and in the WAL until vacuum and WAL rotation catch up. For
a service whose central control is that deleted data is *gone*, "eventually unreachable through the
query planner" is not the same guarantee. The blob directory is the container's **only** writable
path — `read_only: true` covers everything else.

**The Postgres volume mounts `/var/lib/postgresql`, not `/var/lib/postgresql/data`.** Postgres 18
changed this: data now lives in a major-version subdirectory so `pg_upgrade --link` works without
crossing a mount boundary, and the image *refuses to start* if it finds data at the old path — which
is the path every pre-18 compose file and every tutorial uses. The failure is a wall of text about
`pg_ctlcluster` that never plainly says "your mount point is wrong".

**Secrets have no defaults, here or in the code.** A development default is a production
credential the day someone forgets to override it, and the failure is silent because the service
starts fine. `config.Load` reports *every* missing variable at once rather than the first.

**`server/.env` is gitignored and this repository is public.** A committed `.env` is a credential
disclosure that survives in history after the file is deleted; `git rm --cached` does not undo a
push. `verify-relay.sh` fails if it ever becomes tracked.

---

## Layout

```
cmd/relay/            main, signal handling, graceful shutdown, --health-check
internal/config/      environment loading; no defaults for secrets
internal/logging/     slog with redaction by type and by key denylist
internal/httpx/       middleware, error responses; the ordering comment matters
internal/health/      liveness (touches nothing) and readiness (cached)
internal/store/       Postgres pool + embedded migrations
internal/store/migrations/
                      the schema; every column justified in BACKEND.md §2
internal/cache/       Redis, and the refusal to run against a persistent one
```

`internal/` throughout: nothing here is a library, and an exported package is an
invitation to import it from somewhere that should not have it.
