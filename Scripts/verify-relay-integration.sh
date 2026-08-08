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
MIN_INTEGRATION_TESTS=104

# A floor is not enough on its own, and that gap is AUDIT 6.14: the count says how
# many tests ran, never which. A rename, a build-tag mistake in one file, or a
# deleted case keeps the total above the floor as long as anything else grew, and
# the property nobody is testing any more is invisible.
#
# These are the cases whose absence would be a security regression rather than a
# coverage regression — the ones that pin single-use redemption, account scoping,
# the rate limits AUDIT 3.1 depends on, and the transaction and bound work from
# 5.22/5.23/5.27. Each must appear in the run as a PASS, by name.
#
# Adding a test does not belong here. Add a name only when its absence would mean a
# control has stopped being checked at all.
REQUIRED_INTEGRATION_TESTS=(
  TestRedeemConsumesTheInvite
  TestRedeemedInviteIsDeletedNotFlagged
  TestRedeemEndpointThrottlesBruteForce
  TestTokenIsNotStoredInPlaintext
  TestAcknowledgementIsScopedToTheCaller
  TestAnAccountOnlyEverReadsItsOwnQueue
  TestPublishThenFetchRoundTrips
  TestRedeemRefusesARegistrationIdOutsideTheProtocolRange
  TestPublishRefusesAPreKeyIdAboveTheProtocolCeiling
  TestRedeemRefusesATrailingSecondValue
  TestBlobDeleteKeepsTheRowWhenTheBytesCannotBeRemoved
  TestBlobQuotaChargesAPartialMegabyteAsAWholeOne
  # The abandonment sweep (AUDIT 5.28). These four are the only checks of it
  # anywhere: no read path filters accounts, so a sweep that stopped deleting —
  # or one that started deleting active accounts — produces no other symptom
  # than rows that outlive the policy, or users who silently lose their account.
  TestAbandonedAccountsAreDeleted
  TestAnActiveAccountSurvivesTheAbandonmentSweep
  TestSweepingAnAccountTakesItsMessagesAndTokens
  TestAuthenticatingRefreshesTheActivityDate
  # The publication body limit (AUDIT 5.32). These two are the only place the
  # middleware chain main builds is exercised at all: every other publish test
  # runs against a bare ServeMux, so the limit that refused every real client
  # publication is invisible to them. Losing either restores that blindness.
  TestTheShippedClientsPublicationIsAccepted
  TestABodyAtTheValidatorsMaximumIsReadable
  # Push-token hardening (P7.S03, THREAT_MODEL.md §3.3). Nothing writes this
  # table until P8, so these are the only thing standing between the column and
  # a plaintext device token: no read path would notice, and the symptom of
  # losing them is a value that looks fine until a database is dumped. The
  # refusal is listed beside the encryption on purpose — a relay with no key
  # must refuse, never fall back to storing the token in the clear.
  TestAPushTokenIsStoredEncrypted
  TestARelayWithNoKeyRefusesToStoreAToken
  TestDeletingTheAccountTakesItsPushToken
  TestStalePushTokensAreSweptAndFreshOnesAreNot
)

# A host port distinct from the development stack's 8080, so running this never
# collides with a stack the developer has up.
API_TEST_PORT="${API_TEST_PORT:-18080}"

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

# --- The real image must actually start ------------------------------------
#
# The suite below runs the package under a golang container, not under the image
# the Dockerfile produces — so it cannot see a defect that lives in the image. It
# did not: the api container crash-looped on
# "mkdir /var/lib/cipher/blobs/tmp: permission denied", because Docker creates a
# named volume owned by root and the relay runs as 65532, while every integration
# test passed. Found only by running the stack by hand.
#
# Building and health-checking the real service closes that gap for the price of
# a cached image build.
echo "  starting the api image and waiting for it to report healthy"
if ! API_PORT="$API_TEST_PORT" "${COMPOSE[@]}" up -d --build --wait api; then
  "${COMPOSE[@]}" logs api >&2
  echo "FAILED: the api container did not become healthy." >&2
  exit 1
fi

# Asked over HTTP as well as through the container health check, so a container
# reported healthy by a probe that is itself broken cannot pass this.
if ! curl -fsS --max-time 10 "http://127.0.0.1:${API_TEST_PORT}/health" >/dev/null; then
  "${COMPOSE[@]}" logs api >&2
  echo "FAILED: the api image is running but /health did not answer." >&2
  exit 1
fi
echo "  ok    the real image starts and serves /health"

# --- The shipping binary must have no known vulnerability -------------------
#
# Here rather than in verify-all.sh because it needs the image, and the image
# needs Docker — the same reason the suite below lives in this script. The image
# was just built, so this costs a cached rebuild and one scan.
#
# It is a different question from Scripts/verify-vulns.sh, which scans the source
# under the toolchain go.mod declares. The Dockerfile's build stage pins a
# different Go, so that gate is not looking at the standard library the release
# actually carries. AUDIT 5.28.
"$REPO_ROOT/Scripts/verify-image-vulns.sh" || {
  echo "FAILED: the binary the relay image ships has a known vulnerability." >&2
  exit 1
}

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

# And the named ones actually ran. `--- PASS: Name` rather than a bare grep for the
# name: the name also appears in a FAIL line, in a skip, and in any log line that
# happens to mention it, and "the string is somewhere in the output" is not the
# same claim as "the test passed".
missing=()
for required in "${REQUIRED_INTEGRATION_TESTS[@]}"; do
  grep -qE "^--- PASS: ${required}( |\\(|$)" "$LOG" || missing+=("$required")
done
if [ "${#missing[@]}" -ne 0 ]; then
  cat "$LOG" >&2
  echo "FAILED: ${#missing[@]} required integration test(s) did not pass by name:" >&2
  printf '  %s\n' "${missing[@]}" >&2
  echo "The count floor was satisfied, which is exactly why this check exists (AUDIT 6.14)." >&2
  exit 1
fi

echo "  ok    integration suite passed ($passed tests, race detector on)"
echo "  ok    all ${#REQUIRED_INTEGRATION_TESTS[@]} required tests passed by name"
