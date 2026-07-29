# Cipher relay

The store-and-forward relay. Go, PostgreSQL, Redis, one binary.

**Design:** [`docs/BACKEND.md`](../docs/BACKEND.md) — read it before changing the schema.
**Threat model:** [`docs/THREAT_MODEL.md`](../docs/THREAT_MODEL.md) — read it before changing anything.

This server is assumed **hostile or seizable**, including when its operator is us. It holds no
plaintext, retains nothing past delivery, and has no administrative interface at all.

---

## Status

**P4.S02 — scaffold.** Configuration, logging, Postgres, Redis, health, and the full schema.
The endpoints arrive in P4.S03 onward:

| | |
|---|---|
| `GET /health` | live |
| `GET /health/ready` | live |
| invite, auth, directory, relay, blobs | P4.S03 – P4.S09 |

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

The full gate — build, vet, gofmt, race tests, and the compose invariants — is:

```sh
../Scripts/verify-relay.sh
```

It also runs as gate 4 of `Scripts/verify-all.sh`, before anything that invokes `xcodebuild`,
so a relay defect surfaces in seconds rather than after a half-hour simulator build.

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
