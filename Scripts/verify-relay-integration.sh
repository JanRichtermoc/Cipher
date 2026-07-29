#!/bin/bash
#
# Gate: the relay's integration suite, against a real Postgres and a real Redis.
#
# Copyright (C) 2026 Jan Richter
# SPDX-License-Identifier: AGPL-3.0-only
#
# Separate from Scripts/verify-relay.sh because this one needs a container
# runtime and that one does not. Keeping them apart means the fast gate stays
# fast and runs everywhere, while the slow gate can be run deliberately and in
# a CI job that has Docker.
#
# What it proves that unit tests cannot: single use is enforced by
# `DELETE ... RETURNING` being atomic under real concurrency, and expiry is
# evaluated against the database's clock. A fake store satisfies both by
# construction and demonstrates neither.
#
# The tests run INSIDE the compose network. Postgres and Redis are never
# published to the host — see docker-compose.test.yml for why that is worth an
# overlay file.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER="$REPO_ROOT/server"

# Floor, not an exact count, so adding a test does not fail the gate. It exists
# to catch the suite collapsing to zero, which is the failure that looks green.
MIN_INTEGRATION_TESTS=72

export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

if ! command -v docker >/dev/null 2>&1; then
  cat >&2 <<'EOF'
FAILED: docker is not on PATH, so the integration suite did not run.

  macOS:  install Docker Desktop, then start it
  Linux:  install docker and the compose plugin

Fatal rather than skipped, for the same reason Scripts/verify-relay.sh is fatal
without Go: a gate that passes when it could not run is worse than no gate.
EOF
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "FAILED: the docker daemon is not running." >&2
  echo "  macOS: open Docker Desktop and wait for the whale to settle." >&2
  exit 1
fi

cd "$SERVER"

# The compose files interpolate from .env, and every password is required with
# no default (see .env.example). Saying so here beats a wall of compose
# interpolation errors.
if [ ! -f .env ]; then
  cat >&2 <<'EOF'
FAILED: server/.env does not exist.

  cp server/.env.example server/.env

then fill in POSTGRES_PASSWORD and REDIS_PASSWORD. Generate each with:

  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; echo

(head is the producer, not the consumer — see server/.env.example for why the
more familiar `tr ... | head -c 32` breaks under set -o pipefail on Linux.)
EOF
  exit 1
fi

COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.test.yml)

# A distinct project name so this never adopts, restarts, or destroys a stack the
# developer has up for manual testing. Sharing one would mean running the tests
# wiped whatever they were in the middle of.
export COMPOSE_PROJECT_NAME=cipher-relay-test

cleanup() {
  # -v removes the Postgres volume. The suite creates accounts and invites, and
  # leaving them behind would let one run's rows influence the next — the class
  # of flake that is only ever reproducible on the machine that has run the
  # tests before.
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Start from nothing, in case a previous run was interrupted before its trap.
cleanup

echo "  starting postgres and redis (not published to the host)"
"${COMPOSE[@]}" up -d --wait postgres redis

# Confirm the anti-goal holds for the stack that is actually RUNNING, not just
# for the file that describes it. verify-relay.sh already reads the compose file;
# this asks the container runtime, which is the thing that would actually be
# listening.
#
# The obvious spelling of this check does not work. `docker compose port postgres
# 5432` looks like it should fail when nothing is published, and it does not: it
# exits 0 and prints "invalid IP:0". Written as `if docker compose port ...; then
# fail`, it therefore reports every unpublished datastore as published — which is
# what the first version of this did, and it failed the build on a correct stack.
#
# HostConfig.PortBindings is the runtime's own record of what was published. It
# is `{}` or `null` when nothing is, and it cannot be satisfied by a command that
# succeeds while saying nothing useful.
for service in postgres redis; do
  container="$("${COMPOSE[@]}" ps -q "$service")"
  if [ -z "$container" ]; then
    echo "FAILED: the $service container is not running." >&2
    exit 1
  fi

  bindings="$(docker inspect "$container" --format '{{json .HostConfig.PortBindings}}')"
  case "$bindings" in
  "{}" | "null" | "") ;;
  *)
    echo "FAILED: $service publishes ports to the host: $bindings" >&2
    echo "Only 'api' may, and only on 127.0.0.1 (docs/BACKEND.md §9)." >&2
    exit 1
    ;;
  esac
done
echo "  ok    neither datastore is reachable from the host"

echo "  running the integration suite inside the network"

# -v so the run can be counted. A suite excluded by its build tag, or emptied by
# a bad file move, compiles to zero tests and reports "ok" — which is the same
# silent pass that docs/AUDIT.md 1.9, 5.12 and 6.7 all record. "ok" is not
# evidence; a count is.
LOG="$(mktemp)"
trap 'rm -f "$LOG"; cleanup' EXIT

if ! "${COMPOSE[@]}" run --rm --quiet-pull tests \
  go test -tags=integration -count=1 -race -v ./internal/integration/... >"$LOG" 2>&1; then
  cat "$LOG" >&2
  echo "FAILED: relay integration suite" >&2
  exit 1
fi

passed="$(grep -c '^--- PASS' "$LOG" || true)"
if [ "$passed" -lt "$MIN_INTEGRATION_TESTS" ]; then
  cat "$LOG" >&2
  echo "FAILED: only $passed integration tests ran; at least $MIN_INTEGRATION_TESTS are expected." >&2
  echo "A suite that runs nothing reports success. Check the build tag and the package path." >&2
  exit 1
fi

echo "  ok    integration suite passed ($passed tests, race detector on)"
