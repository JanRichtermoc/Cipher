#!/bin/bash
#
# Gate: the relay builds, vets, formats, and passes its tests.
#
# Copyright (C) 2026 Jan Richter
# SPDX-License-Identifier: AGPL-3.0-only
#
# This runs the parts of the server that need no Docker. Everything here is a
# pure unit test against httptest and the environment; the integration suite
# against a live Postgres and Redis is P4.S10 and needs a container runtime.
#
# Go is REQUIRED, not optional. Skipping when the toolchain is absent would make
# this gate report success for a check that ran nothing — the failure mode
# docs/AUDIT.md 1.9 and 5.12 both record, and the reason this script would rather
# stop the whole verification than quietly contribute a green line.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER="$REPO_ROOT/server"

# Homebrew's Go is not on a non-interactive PATH by default, exactly as with Ruby
# (see docs/DEVELOPMENT.md).
export PATH="/opt/homebrew/bin:/usr/local/go/bin:$PATH"

if ! command -v go >/dev/null 2>&1; then
  cat >&2 <<'EOF'
FAILED: the Go toolchain is not on PATH, so the relay was not verified.

  Install it:  brew install go
  Minimum:     1.25 (server/go.mod). Set by pgx v5.10.0, which declares
               go >= 1.25.0; our own code would build on 1.23. Verified by
               building under 1.23 (fails) and 1.25.5 (passes), not assumed.

This is deliberately fatal rather than skipped. A gate that passes because it
ran nothing is the failure this project has already been bitten by twice.
EOF
  exit 1
fi

cd "$SERVER"

echo "  using $(go version)"

# --- Formatting -------------------------------------------------------------
# vendor/ is excluded: it is upstream source, and reformatting a dependency would
# make the diff-on-every-bump review that vendoring exists for unreadable.
unformatted="$(gofmt -l . | grep -v '^vendor/' || true)"
if [ -n "$unformatted" ]; then
  echo "FAILED: gofmt would change these files:" >&2
  printf '  %s\n' $unformatted >&2
  exit 1
fi
echo "  ok    gofmt clean"

# --- Vendor consistency -----------------------------------------------------
# `go mod vendor` is committed so the container build needs no network and every
# dependency byte is in the diff. If vendor/ has drifted from go.mod, the build
# that CI verifies is not the build the Dockerfile produces.
go mod verify >/dev/null || {
  echo "FAILED: go mod verify — a module's checksum does not match go.sum" >&2
  exit 1
}
echo "  ok    module checksums verified"

# --- Build ------------------------------------------------------------------
# -mod=vendor explicitly: with a vendor directory present Go uses it by default,
# but stating it means a future default change cannot silently start resolving
# from the network instead of from the reviewed tree.
go build -mod=vendor ./... || {
  echo "FAILED: relay does not build" >&2
  exit 1
}
echo "  ok    relay builds"

go vet -mod=vendor ./... || {
  echo "FAILED: go vet" >&2
  exit 1
}
echo "  ok    go vet clean"

# --- Tests ------------------------------------------------------------------
# -race because the readiness cache and the redaction handler are both touched
# concurrently, and a data race in the health check is the kind of thing that
# only ever reproduces under load in production.
go test -mod=vendor -race -count=1 ./... || {
  echo "FAILED: relay tests" >&2
  exit 1
}
echo "  ok    relay tests pass (race detector on)"

# --- The compose file must not publish the datastores -----------------------
# P4.S02's stated anti-goal. `ports: "5432:5432"` on Postgres is one line, is the
# form every tutorial shows, and would put the relay's database on every
# interface of whatever machine runs it. Checked mechanically because it is a
# single-line regression that reads as normal.
compose="$SERVER/docker-compose.yml"
if [ -f "$compose" ]; then
  # Grab each service's block and confirm only `api` declares ports.
  offenders="$(awk '
    /^  [a-z][a-z0-9_-]*:$/ { service = $1; sub(":", "", service) }
    /^ *ports:/             { if (service != "api") print service }
  ' "$compose" | sort -u)"
  if [ -n "$offenders" ]; then
    echo "FAILED: these compose services publish ports to the host:" >&2
    printf '  %s\n' $offenders >&2
    echo "Only 'api' may, and only on 127.0.0.1 (docs/BACKEND.md §9)." >&2
    exit 1
  fi

  # And `api` must bind loopback. `ports: "8080:8080"` binds 0.0.0.0, which
  # publishes the relay to the LAN — on a laptop on a café network, to the room.
  if ! grep -qE '^\s*-\s*"127\.0\.0\.1:' "$compose"; then
    echo "FAILED: the api port mapping is not bound to 127.0.0.1" >&2
    exit 1
  fi
  echo "  ok    only api publishes a port, and only on loopback"

  # Redis persistence off. cache.AssertNoPersistence refuses to start against a
  # persistent Redis, but that check only fires when someone runs the stack;
  # this one fires on every verification.
  #
  # Comments are stripped and only the `redis:` service block is considered.
  # The first version of this check grepped the whole file, which passed after
  # the flags were deleted because the words also appear in the comment three
  # lines above them — the check was reading the documentation, not the
  # configuration. Caught by negative-testing it, which is the only reason it is
  # not still doing that.
  redis_block="$(awk '
    /^  [a-z][a-z0-9_-]*:$/ { inblock = ($1 == "redis:") }
    inblock                 { sub(/#.*/, ""); print }
  ' "$compose")"

  if ! printf '%s\n' "$redis_block" | grep -qE '^\s*-\s*--appendonly\s*$'; then
    echo "FAILED: the redis service does not pass --appendonly" >&2
    echo "Redis defaults to writing to disk; see docs/BACKEND.md §3." >&2
    exit 1
  fi
  if ! printf '%s\n' "$redis_block" | grep -qE '^\s*-\s*--save\s*$'; then
    echo "FAILED: the redis service does not pass --save" >&2
    echo "Redis defaults to writing to disk; see docs/BACKEND.md §3." >&2
    exit 1
  fi
  # A flag with the wrong value is worse than a missing one, because it reads as
  # protection. --appendonly must be followed by "no", --save by an empty string.
  if ! printf '%s\n' "$redis_block" | grep -A1 -E '^\s*-\s*--appendonly\s*$' | grep -qE '^\s*-\s*"no"\s*$'; then
    echo "FAILED: --appendonly is not set to \"no\"" >&2
    exit 1
  fi
  if ! printf '%s\n' "$redis_block" | grep -A1 -E '^\s*-\s*--save\s*$' | grep -qE '^\s*-\s*""\s*$'; then
    echo "FAILED: --save is not set to \"\" (empty disables RDB snapshotting)" >&2
    exit 1
  fi
  echo "  ok    Redis persistence disabled in compose (RDB and AOF)"
fi

# --- No committed secrets ---------------------------------------------------
# The repository is public. A .env reaching a commit is a credential disclosure
# that survives in history after the file is deleted.
if git -C "$REPO_ROOT" ls-files --error-unmatch server/.env >/dev/null 2>&1; then
  echo "FAILED: server/.env is tracked by git. It holds passwords." >&2
  exit 1
fi
echo "  ok    server/.env is not tracked"
