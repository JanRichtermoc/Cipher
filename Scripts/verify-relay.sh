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

# ...and that the committed vendor tree is byte-identical to what those modules
# contain, which is a different question `go mod verify` does not ask.
#
# `go mod verify` checks the module *cache* against go.sum. A `-mod=vendor` build
# then trusts `vendor/` without comparing it to anything at all — so an edit in
# there, deliberate or accidental, is invisible to every other gate. Found for
# real: `github.com/google/uuid`'s vendored copy had had its doc comments
# reformatted at some point (a stray `gofmt -w .` over the whole tree is the
# likely cause, since this script deliberately excludes vendor/ from the format
# check), so the bytes in the diff were not upstream's bytes. Comments only, this
# time. AUDIT 1.12.
#
# Re-vendors into a temporary directory and compares. Needs a warm module cache
# or the network; `go mod verify` above already needs the cache, so this adds no
# new requirement.
VENDOR_CHECK="$(mktemp -d)"
trap 'rm -rf "$VENDOR_CHECK"' EXIT
if ! go mod vendor -o "$VENDOR_CHECK" >/dev/null 2>&1; then
  echo "FAILED: could not re-vendor to verify the committed tree" >&2
  exit 1
fi
# `.DS_Store` is excluded, and only that. It is untracked (`.gitignore:47`) and
# Finder recreates it in any directory a developer opens, so failing on it would
# make this gate cry wolf on every macOS machine — which is how a gate gets
# deleted (AUDIT R2). Nothing else is excluded: an ignore list is where a real
# modification would eventually hide.
if ! diff -r -q -x .DS_Store "$VENDOR_CHECK" vendor >/dev/null 2>&1; then
  cat >&2 <<'EOF'
FAILED: server/vendor/ is not byte-identical to the modules go.mod selects.

  A -mod=vendor build reads that tree and nothing compares it to upstream, so a
  modified dependency would ship unnoticed. Restore it:

    cd server && go mod vendor

  Then read the resulting diff before committing it — that is the review this
  gate exists to force.
EOF
  diff -r -q -x .DS_Store "$VENDOR_CHECK" vendor | head -20 >&2 || true
  exit 1
fi
echo "  ok    vendor/ is byte-identical to the selected modules"

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

# service_block prints one service's lines with comments stripped.
#
# Stripping first is load-bearing and not tidiness. This file explains each
# control in prose directly above the directive that implements it, so a check
# that reads the whole file matches the paragraph after the setting is deleted —
# which is exactly how the Redis persistence check below passed against a compose
# file that had lost both flags (AUDIT 6.7, R3).
service_block() {
  awk -v want="$2:" '
    /^  [a-z][a-z0-9_-]*:$/ { inblock = ($1 == want) }
    inblock                 { sub(/#.*/, ""); print }
  ' "$1"
}

# block_has greps one service block for a pattern.
block_has() {
  service_block "$1" "$2" | grep -qE "$3"
}

# check_compose holds every compose invariant. It *returns* rather than exits, so
# the self-test below can run it against deliberately broken copies.
check_compose() {
  local file="$1"

  # Only `api` may publish a port.
  local offenders
  offenders="$(awk '
    /^  [a-z][a-z0-9_-]*:$/ { service = $1; sub(":", "", service) }
    /^ *ports:/             { if (service != "api") print service }
  ' "$file" | sort -u)"
  if [ -n "$offenders" ]; then
    echo "these compose services publish ports to the host: $offenders" >&2
    echo "Only 'api' may, and only on 127.0.0.1 (docs/BACKEND.md §9)." >&2
    return 1
  fi

  # And `api` must bind loopback. `ports: "8080:8080"` binds 0.0.0.0, which
  # publishes the relay to the LAN — on a laptop on a café network, to the room.
  if ! grep -qE '^\s*-\s*"127\.0\.0\.1:' "$file"; then
    echo "the api port mapping is not bound to 127.0.0.1" >&2
    return 1
  fi

  # Every RELAY_* the service reads is either forwarded to the container or listed
  # below as deliberately left at its default. RELAY_PUSH_TOKEN_KEY was read by
  # config.Load and forwarded by nothing, so setting it in .env had no effect at
  # all and the symptom was a refusal that reads like a code bug (AUDIT 6.24). A
  # new variable must be classified rather than silently dropped.
  local declared forwarded unclassified
  declared="$(grep -oE '"RELAY_[A-Z_]+"' "$REPO_ROOT/server/internal/config/config.go" |
    tr -d '"' | sort -u)"
  forwarded="$(service_block "$file" api | grep -oE '^\s+RELAY_[A-Z_]+:' |
    tr -d ' :' | sort -u)"
  # Timeouts and size limits, whose defaults are the deployment's policy. Written
  # out rather than derived from what the file happens to contain: deriving it
  # would make the rule "whatever is missing is fine" (AUDIT R5).
  local unforwarded_by_design="RELAY_IDLE_TIMEOUT
RELAY_MAX_REQUEST_BYTES
RELAY_READ_HEADER_TIMEOUT
RELAY_READ_TIMEOUT
RELAY_SHUTDOWN_GRACE
RELAY_WRITE_TIMEOUT"
  unclassified="$(comm -23 \
    <(comm -23 <(printf '%s\n' "$declared") <(printf '%s\n' "$forwarded")) \
    <(printf '%s\n' "$unforwarded_by_design" | sort -u))"
  if [ -n "$unclassified" ]; then
    echo "these RELAY_* variables are read by internal/config and reach no container:" >&2
    printf '  %s\n' $unclassified >&2
    echo "Forward them in the api service, or add them to unforwarded_by_design with a reason." >&2
    return 1
  fi

  # Redis persistence off. cache.AssertNoPersistence refuses to start against a
  # persistent Redis, but that check only fires when someone runs the stack;
  # this one fires on every verification.
  local redis_block
  redis_block="$(service_block "$file" redis)"

  if ! printf '%s\n' "$redis_block" | grep -qE '^\s*-\s*--appendonly\s*$'; then
    echo "the redis service does not pass --appendonly" >&2
    echo "Redis defaults to writing to disk; see docs/BACKEND.md §3." >&2
    return 1
  fi
  if ! printf '%s\n' "$redis_block" | grep -qE '^\s*-\s*--save\s*$'; then
    echo "the redis service does not pass --save" >&2
    echo "Redis defaults to writing to disk; see docs/BACKEND.md §3." >&2
    return 1
  fi
  # A flag with the wrong value is worse than a missing one, because it reads as
  # protection. --appendonly must be followed by "no", --save by an empty string.
  if ! printf '%s\n' "$redis_block" | grep -A1 -E '^\s*-\s*--appendonly\s*$' | grep -qE '^\s*-\s*"no"\s*$'; then
    echo "--appendonly is not set to \"no\"" >&2
    return 1
  fi
  if ! printf '%s\n' "$redis_block" | grep -A1 -E '^\s*-\s*--save\s*$' | grep -qE '^\s*-\s*""\s*$'; then
    echo "--save is not set to \"\" (empty disables RDB snapshotting)" >&2
    return 1
  fi

  # A memory ceiling on the container without one inside Redis is not a limit,
  # it is a choice of who does the killing. Redis holds every rate-limit bucket
  # and has no persistence, so an OOM kill hands every caller a fresh allowance
  # — the harm AUDIT 5.24 records, reachable by traffic instead of by a deploy.
  # noeviction is required explicitly: allkeys-lru would discard those same
  # buckets under pressure and look like healthy operation while doing it.
  if ! printf '%s\n' "$redis_block" | grep -qE '^\s*-\s*--maxmemory\s*$'; then
    echo "the redis service sets no --maxmemory, so the OOM killer is its only limit" >&2
    return 1
  fi
  if ! printf '%s\n' "$redis_block" | grep -A1 -E '^\s*-\s*--maxmemory-policy\s*$' | grep -qE '^\s*-\s*noeviction\s*$'; then
    echo "the redis --maxmemory-policy is not noeviction, so rate-limit buckets can be evicted" >&2
    return 1
  fi

  # Every service is confined, not only `api` (AUDIT 5.28). Postgres holds the
  # account rows, the public identity keys and every undelivered envelope, and
  # ran with Docker's default capability set and no resource ceiling while the
  # container holding a static binary and client-encrypted blobs was locked down.
  local service
  for service in api postgres redis; do
    if ! block_has "$file" "$service" '^\s*cap_drop:\s*\[\s*ALL\s*\]\s*$'; then
      echo "the $service service does not drop all capabilities" >&2
      return 1
    fi
    if ! block_has "$file" "$service" '^\s*-\s*no-new-privileges:true\s*$'; then
      echo "the $service service does not set no-new-privileges" >&2
      return 1
    fi
    if ! block_has "$file" "$service" '^\s*mem_limit:\s*[0-9]'; then
      echo "the $service service has no memory limit" >&2
      return 1
    fi
    if ! block_has "$file" "$service" '^\s*pids_limit:\s*[0-9]'; then
      echo "the $service service has no process limit" >&2
      return 1
    fi
  done

  return 0
}

# selftest_compose reintroduces each defect in a real copy of the file.
#
# Not in a hand-written fixture: the defects that have actually shipped here were
# in the wiring rather than in the logic, and a fixture proves the logic against
# a file the gate will never see (AUDIT R5).
selftest_compose() {
  local probe cases=0 defect
  probe="$(mktemp)"

  # Each entry deletes one line from the real file. A gate that no longer fires
  # on its own subject is a gate that has stopped working, whatever it prints.
  for defect in \
    's/^    cap_drop: \[ALL\]$//' \
    's/^      - no-new-privileges:true$//' \
    's/^    mem_limit: 1g$//' \
    's/^    pids_limit: 512$//' \
    's/^      - --maxmemory$//' \
    's/^      - noeviction$//' \
    's/^      - --appendonly$//' \
    's/^      - "no"$//'; do
    sed "$defect" "$compose" >"$probe"
    if check_compose "$probe" 2>/dev/null; then
      rm -f "$probe"
      echo "FAILED: the compose gate accepts a file with '$defect' applied" >&2
      exit 1
    fi
    cases=$((cases + 1))
  done

  # AUDIT 6.24: a variable the service reads that reaches no container. Deleting the
  # line is exactly how RELAY_PUSH_TOKEN_KEY came to be missing — it was never added.
  sed 's/^      RELAY_TRUSTED_PROXY: .*$//' "$compose" >"$probe"
  if check_compose "$probe" 2>/dev/null; then
    rm -f "$probe"
    echo "FAILED: the compose gate accepts a RELAY_* variable that reaches no container" >&2
    exit 1
  fi
  cases=$((cases + 1))

  # The positive control. Every case above asserts a failure, and a check_compose
  # that failed unconditionally would satisfy all of them — so the unmodified
  # file must still pass, through the same code path.
  #
  # stderr is NOT swallowed here, unlike the cases above. This control fires for
  # two quite different reasons — a gate that refuses everything, and a compose
  # file that genuinely regressed — and the message an operator needs is the
  # difference between them.
  if ! check_compose "$compose"; then
    rm -f "$probe"
    cat >&2 <<'EOF'
FAILED: the committed docker-compose.yml does not satisfy its own invariants.

  The specific reason is the line above. Either the compose file regressed, or a
  check was tightened without updating it. Both make every refusal this gate
  reports below meaningless, which is why the committed file is exercised here
  rather than only after the negative cases.
EOF
    exit 1
  fi
  cases=$((cases + 1))

  # And a comment naming a control must not stand in for the control. This file
  # explains cap_drop and no-new-privileges in prose above every block that sets
  # them, which is the shape AUDIT 6.7 records.
  sed 's/^    cap_drop: \[ALL\]$/    # cap_drop: [ALL]/' "$compose" >"$probe"
  if check_compose "$probe" 2>/dev/null; then
    rm -f "$probe"
    echo "FAILED: the compose gate is satisfied by a commented-out cap_drop" >&2
    exit 1
  fi
  cases=$((cases + 1))

  rm -f "$probe"
  echo "  ok    self-test: $cases cases — the compose gate still fires, and only when it should"
}

if [ -f "$compose" ]; then
  selftest_compose
  check_compose "$compose" || {
    echo "FAILED: docker-compose.yml (see the reason above)" >&2
    exit 1
  }
  echo "  ok    only api publishes a port, and only on loopback"
  echo "  ok    Redis persistence disabled and bounded in compose (RDB, AOF, maxmemory)"
  echo "  ok    every service drops capabilities, refuses new privileges, and is bounded"
fi

# --- No committed secrets ---------------------------------------------------
# The repository is public. A .env reaching a commit is a credential disclosure
# that survives in history after the file is deleted.
if git -C "$REPO_ROOT" ls-files --error-unmatch server/.env >/dev/null 2>&1; then
  echo "FAILED: server/.env is tracked by git. It holds passwords." >&2
  exit 1
fi
echo "  ok    server/.env is not tracked"
