#!/bin/bash
#
# The standing regression gate — every gate this project has, in one command.
#
# It exists because the checklist used to be eight lines of prose in the plan, and a
# checklist that is prose gets reordered, half-run, or skipped when it is inconvenient.
# This runs the mechanical items in dependency order and stops at the first failure.
#
# Deliberately SERIAL. The crypto test bundle is hosted by the app (AUDIT 6.6), so a run
# launches Cipher.app in the simulator; two concurrent `xcodebuild test` invocations against
# one simulator fail preflight with "RequestDenied ... Busy". Never add `&` here.
#
# Usage:
#   Scripts/verify-all.sh                 # everything
#   Scripts/verify-all.sh --fast          # skip the device Release build
#   Scripts/verify-all.sh --offline       # skip checks that need the network
#
# Environment:
#   CIPHER_TEST_SIMULATOR=<name>          # run against a different simulator
#   CIPHER_ALLOW_SIMULATOR_WIPE=1         # the account on it is expendable (AUDIT 6.17)
#
# Copyright (C) 2026 Jan Richter
# SPDX-License-Identifier: AGPL-3.0-only

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WORKSPACE="Cipher.xcworkspace"
SIMULATOR="${CIPHER_TEST_SIMULATOR:-iPhone 17 Pro}"

# `OS=latest` is not decoration. This machine has one iOS runtime, but the CI image ships
# 26.2, 26.4 and 26.5 while the app's deployment target is 26.5 — so two of the three cannot
# install it, and a bare `name=` destination leaves the choice to xcodebuild. Naming `latest`
# makes it deterministic without duplicating the deployment target anywhere.
DESTINATION="platform=iOS Simulator,name=$SIMULATOR,OS=latest"

FAST=0
OFFLINE=0

for arg in "$@"; do
  case "$arg" in
  --fast) FAST=1 ;;
  --offline) OFFLINE=1 ;;
  *)
    echo "unknown option: $arg" >&2
    exit 2
    ;;
  esac
done

STEP=0
TOTAL=19
[ "$FAST" -eq 1 ] && TOTAL=16

step() {
  STEP=$((STEP + 1))
  printf '\n=== [%d/%d] %s\n' "$STEP" "$TOTAL" "$1"
}

fail() {
  printf '\nFAILED: %s\n' "$1" >&2
  exit 1
}

# --- 1. Simulator safety (AUDIT 6.17) ----------------------------------------
# First, and ahead of anything slow, because this is the one gate whose failure is about the
# *developer's* data rather than the product's correctness — and the run it exists to stop is
# the one someone started in the background and walked away from.
#
# Gate 13 hosts the crypto tests inside Cipher.app (AUDIT 6.6), so they share its container
# and its Keychain, and they call `destroyAllState()`. Against a simulator holding a
# registered account that is a silent, mid-run, irreversible wipe: 68 "all local protocol
# state destroyed" lines, the app back at the invite screen, and a message already in flight
# to it left permanently undecryptable. Observed, then reproduced with `--fast`, which does
# not avoid it because gate 14 *is* the app-hosted run. This check therefore ignores `--fast`
# and `--offline` entirely.
#
# Refusing to run is deliberately the default, and that is also precisely the failure mode
# **R2** warns about — a gate that cries wolf is as dangerous as one that never fires,
# because it gets deleted. Two things keep this from becoming one. It fires only on an
# account that actually exists, never on a clean or absent container, and every one of those
# shapes is a positive control in the self-test below. And the refusal names both ways
# forward, so nobody's route past it is to comment it out: `CIPHER_TEST_SIMULATOR` to run
# somewhere else, or `CIPHER_ALLOW_SIMULATOR_WIPE=1` to say this account is expendable. The
# destructive path stays a deliberate, greppable act rather than the quiet default.
#
# CI never sees it: its simulator is created clean per run, so the check passes in silence.
step "simulator safety (AUDIT 6.17)"

# Needed to locate the data container. Hardcoded rather than read through
# `xcodebuild -showBuildSettings`, which costs seconds on a check whose whole value is
# failing within the first one. A stale constant would simply stop finding the container,
# and "no container" is indistinguishable from "no account" — so it is checked against the
# project below rather than trusted.
APP_BUNDLE_ID="cz.janrichtermoc.Cipher"

# True when a data container holds a Cipher installation's crypto state.
#
# Deliberately the same rule as `EncryptedFileRecordStore.containsPersistedState`: the root
# is private to CipherCrypto and every child counts as state, including an artifact a newer
# build wrote. The two agree because this has to predict what `destroyAllState` would take,
# and recognising only today's filenames is how a check decides there is nothing to lose.
#
# Pure, so the self-test can drive it over fabricated layouts with no simulator involved.
container_holds_account() {
  local data="${1:-}"
  [ -n "$data" ] || return 1
  local root="$data/Library/Application Support/CipherCrypto"
  [ -d "$root" ] || return 1
  [ -n "$(ls -A "$root" 2>/dev/null)" ]
}

# What to do about whatever the probe found. Pure — the at-risk list and the override in,
# the verdict out — so the destructive branch is provable by the self-test rather than only
# by a run that actually wiped something.
account_verdict() {
  local at_risk="${1:-}" override="${2:-0}"
  if [ -z "$at_risk" ]; then
    printf 'clear'
  elif [ "$override" = "1" ]; then
    printf 'override'
  else
    printf 'refuse'
  fi
}

# The probe decides whether someone's account is about to be destroyed, so a broken one is
# silent by construction: it looks exactly like "nothing here to lose". Proved on every run,
# before it is trusted (R2) — the same arrangement as the simulator-fault classifier below.
selftest_container_probe() {
  local probe cases=0
  probe="$(mktemp -d)"

  # Fires on a real account: a sealed store is exactly what gate 14 would take.
  mkdir -p "$probe/populated/Library/Application Support/CipherCrypto"
  : >"$probe/populated/Library/Application Support/CipherCrypto/records.sqlite3"
  container_holds_account "$probe/populated" ||
    fail "the account probe no longer sees a populated Cipher container"
  cases=$((cases + 1))

  # And on state this build does not recognise by name, for the same reason the store's own
  # rule does: a downgrade must not conclude that future ciphertext is nothing.
  mkdir -p "$probe/future/Library/Application Support/CipherCrypto/unknown.v2"
  container_holds_account "$probe/future" ||
    fail "the account probe misses state written by a newer build"
  cases=$((cases + 1))

  # Positive controls. Every shape that is *not* an account must be silent, or this becomes
  # the gate that cries wolf and is deleted for it.
  mkdir -p "$probe/empty/Library/Application Support/CipherCrypto"
  ! container_holds_account "$probe/empty" ||
    fail "the account probe fires on an empty container"
  cases=$((cases + 1))

  mkdir -p "$probe/fresh/Library/Application Support"
  ! container_holds_account "$probe/fresh" ||
    fail "the account probe fires on an app that never opened an engine"
  cases=$((cases + 1))

  ! container_holds_account "$probe/absent" ||
    fail "the account probe fires on a container that does not exist"
  cases=$((cases + 1))

  # An unresolvable container is "app not installed", not "account present". Getting this
  # backwards would refuse every run on a clean machine and teach people to set the override
  # permanently, which is the same as having no check.
  ! container_holds_account "" ||
    fail "the account probe treats an unresolvable container as an account"
  cases=$((cases + 1))

  # The verdict, including the one branch that permits an irreversible wipe. Proved here
  # rather than by running it: the only run that would exercise it for real is one that
  # destroyed an account, and "we tested it by losing something" is not evidence anyone
  # should have to accept.
  [ "$(account_verdict "" 0)" = "clear" ] ||
    fail "the verdict refuses a run with nothing at risk"
  cases=$((cases + 1))

  # The override must not invent a hazard where there is none, or a developer who leaves it
  # set permanently would see a warning on every clean run and stop reading it.
  [ "$(account_verdict "" 1)" = "clear" ] ||
    fail "the verdict warns about a wipe with nothing at risk"
  cases=$((cases + 1))

  [ "$(account_verdict "  UDID" 0)" = "refuse" ] ||
    fail "the verdict allows a run that would destroy a registered account"
  cases=$((cases + 1))

  [ "$(account_verdict "  UDID" 1)" = "override" ] ||
    fail "the acknowledged-wipe override does not work, which is how it gets removed instead"
  cases=$((cases + 1))

  rm -rf "$probe"
  echo "  ok    self-test: $cases cases — the account probe still fires, and only when it should"
}

selftest_container_probe

grep -q "PRODUCT_BUNDLE_IDENTIFIER = $APP_BUNDLE_ID;" Cipher.xcodeproj/project.pbxproj ||
  fail "the app bundle id is no longer $APP_BUNDLE_ID, so this check cannot find the simulator's container. Update APP_BUNDLE_ID — a check that cannot run is not a pass."

# Buffered, not piped into the loop: under `pipefail` a failing `simctl` in a pipeline would
# surface as a loop that simply found nothing, which is this check's silent-failure mode.
simulator_json="$(xcrun simctl list devices available -j 2>/dev/null)" || simulator_json=""
[ -n "$simulator_json" ] ||
  fail "could not enumerate simulators, so the AUDIT 6.17 safety check did not run. That is a failure, not a pass."

# Every device carrying this name, not only the newest runtime. `OS=latest` picks one and
# this does not need to predict which: refusing when any of them holds an account is the
# conservative answer, and the cost of guessing wrong is somebody's identity key.
named_simulators="$(
  printf '%s' "$simulator_json" | CIPHER_SIM_NAME="$SIMULATOR" python3 -c '
import json, os, sys

name = os.environ["CIPHER_SIM_NAME"]
for devices in (json.load(sys.stdin).get("devices") or {}).values():
    for device in devices:
        if device.get("name") == name and device.get("udid"):
            print(device["udid"])
'
)"

at_risk=""
while IFS= read -r udid; do
  [ -n "$udid" ] || continue
  container="$(xcrun simctl get_app_container "$udid" "$APP_BUNDLE_ID" data 2>/dev/null)" ||
    container=""
  if container_holds_account "$container"; then
    at_risk="$at_risk  $udid"$'\n'
  fi
done <<EOF
$named_simulators
EOF

if [ -z "$named_simulators" ]; then
  # Not a pass by inspection — there was nothing to inspect. Said out loud rather than
  # printed as "ok", because gate 14 will fail on the destination anyway and this line is
  # what explains why nothing was checked.
  echo "  —     no simulator named '$SIMULATOR' exists; nothing to protect"
else
  case "$(account_verdict "$at_risk" "${CIPHER_ALLOW_SIMULATOR_WIPE:-0}")" in
  clear)
    echo "  ok    no registered Cipher account on '$SIMULATOR' — gate 14 has nothing to destroy"
    ;;
  override)
    printf '  !     CIPHER_ALLOW_SIMULATOR_WIPE=1 — proceeding, and these WILL be wiped:\n%s' "$at_risk"
    ;;
  refuse)
    printf '\nA registered Cipher account is present on:\n%s\n' "$at_risk" >&2
    printf 'Gate 13 hosts the crypto tests inside Cipher.app and calls destroyAllState(),\n' >&2
    printf 'so running now destroys that identity key, its sealed records and its session\n' >&2
    printf 'credential — irreversibly, and mid-run (AUDIT 6.17).\n\n' >&2
    printf 'Either run somewhere else:\n' >&2
    printf '    CIPHER_TEST_SIMULATOR="<another installed simulator>" %s\n\n' "$0" >&2
    printf 'or say the account is expendable:\n' >&2
    printf '    CIPHER_ALLOW_SIMULATOR_WIPE=1 %s\n' "$0" >&2
    fail "refusing to destroy a registered account on '$SIMULATOR' (AUDIT 6.17)"
    ;;
  esac
fi

# --- 2. Supply chain --------------------------------------------------------
# First of the verification gates because a moved tag or a changed checksum invalidates
# everything after it: there is no point testing a binary whose provenance is in question.
# (Gate 1 verifies nothing about the product; it refuses to destroy the developer's data.)
step "supply chain"
# The self-test first, and it runs even offline: the pin checks are greps, and a
# grep that matches nothing reads exactly like a grep that found nothing wrong.
./Scripts/verify-supply-chain.sh --self-test || fail "supply chain self-test"
if [ "$OFFLINE" -eq 1 ]; then
  # --offline used to skip this gate entirely. The half that needs no network —
  # is the dependency pinned to the audited commit — has no reason to be skipped,
  # and it is the half AUDIT 1.14 is about.
  ./Scripts/verify-supply-chain.sh --pre-install || fail "supply chain pin"
  echo "  skipped the upstream checks (--offline); they MUST run before any release"
else
  ./Scripts/verify-supply-chain.sh || fail "supply chain"
fi

# --- 3. TLS pin gate ---------------------------------------------------------
# `verify-pins.sh` cannot run in full here: its live half needs the network and the
# staging host, and its `reuse_key` half needs SSH. That is why it is not a step of this
# script — but "cannot run in full" is not a reason to leave its *logic* unproven, which
# is what AUDIT 6.14 found. The self-test is offline and deterministic, so the checks that
# stand between a rotated leaf key and every installed client failing closed are exercised
# on every run, whoever runs it.
step "TLS pin gate logic (the live probe needs the staging host)"
./Scripts/verify-pins.sh --self-test || fail "the TLS pin gate cannot be trusted"

# --- 4. Target membership -----------------------------------------------------
# Two halves of one question — does the project build what is on disk — with opposite failure
# modes, so they run together. Cheap, so both run before anything is compiled.
#
# The app target uses synchronized folders, so a file can join the shipping bundle with no
# project-file edit. The three explicit-membership targets fail the other way: a file dropped
# into `CipherCrypto/`, `CipherCryptoTests/` or `CipherTests/` joins nothing until
# `bootstrap-targets.rb` is run by hand. For a source file that is loud, because the first
# reference to it will not compile. For a **test** file it is silent: an uncompiled
# `XCTestCase` produces no name, changes no total, and leaves this whole script green over a
# security test that never ran (AUDIT 6.19).
step "target membership (app manifest, and every explicit target)"
./Scripts/verify-app-target-manifest.sh || fail "app target manifest"
./Scripts/verify-target-membership.py --self-test ||
  fail "the target-membership gate cannot be trusted"
./Scripts/verify-target-membership.py ||
  fail "a Swift file is not compiled by the target that owns its directory (AUDIT 6.19)"

# --- 5. iPhone-only ----------------------------------------------------------
# Early, and before anything is compiled, because the answer is a property of the
# resolved build settings rather than of the artifact — and a twenty-minute Release
# build is a poor place to discover it. `TARGETED_DEVICE_FAMILY = 1` in the project
# text is not the property (AUDIT 6.13): Xcode defaults the two Designed-for-iPhone
# settings to YES, so the shipping binary ran on Apple silicon Macs and on visionOS
# while every document said iPhone.
step "the Release build is iPhone-only (AUDIT 6.13)"
./Scripts/verify-iphone-only.sh --self-test || fail "the iPhone-only gate cannot be trusted"
./Scripts/verify-iphone-only.sh || fail "the Release build is not iPhone-only"

# --- 6. No plaintext logging ------------------------------------------------
# A grep, not a proof. It catches the accidental `print(message)` during development, which
# is the realistic failure — not a determined attempt to exfiltrate. The crypto module has
# no business calling print/NSLog at all: it logs through CipherLog, which is redacted.
step "no plaintext logging in CipherCrypto"
if grep -rnE '(^|[^A-Za-z_.])(print|NSLog|debugPrint|dump)[[:space:]]*\(' \
  CipherCrypto/Sources --include='*.swift'; then
  fail "CipherCrypto must log only through CipherLog (see RedactingLogger.swift)"
fi
echo "  ok    no direct print/NSLog in the crypto module"

# --- 7. Invite-code-only identity -------------------------------------------
# Locked decision §0.2.7. Cipher collects no phone number, email address, server-side
# username or verification code, and that has to be a requirement rather than a property
# that happens to hold — every other messenger has the field, and "sign in with email"
# looks like three lines of work to someone who has not read THREAT_MODEL.md §3.4.
#
# Next to the logging grep because it is the same kind of check: source only, no build,
# a second to run. Unlike that grep it is not a grep — the prose documenting this decision
# names every string being forbidden, so comments are stripped by a per-language lexer
# first (AUDIT R3) and the self-test runs before any all-clear is believed (AUDIT R2).
step "invite-code-only identity (no phone, email, username or verification code)"
./Scripts/verify-identity-fields.py --self-test || fail "the identity-field gate cannot be trusted"
./Scripts/verify-identity-fields.py ||
  fail "an identity-shaped field reached the account model, auth API, wire format or relay schema (plan §0.2.7)"

# --- 8. Dependency vulnerabilities ------------------------------------------
# Next to the supply chain, because it answers the other half of that question:
# step 1 proves the dependencies are the ones we pinned, this one proves that
# what we pinned has no known reachable hole. `golang.org/x/text` sat here with a
# published CVE for two whole phases because nothing asked.
step "reachable vulnerabilities in the relay dependency tree"
if [ "$OFFLINE" -eq 1 ]; then
  echo "  skipped (--offline); this check MUST run before any release"
else
  ./Scripts/verify-vulns.sh || fail "a reachable dependency vulnerability (see the output above)"
fi

# --- 9. Relay ---------------------------------------------------------------
# Placed here, before anything that invokes xcodebuild, because it takes seconds
# and the iOS gates take half an hour. A relay defect discovered after a full
# simulator build is the same defect discovered thirty minutes later.
#
# Covers what needs no container: build, vet, gofmt, unit tests under the race
# detector, plus the compose invariants that P4.S02 names as anti-goals. The
# integration suite against a live Postgres and Redis is P4.S10.
step "relay: build, vet, tests, compose invariants"
./Scripts/verify-relay.sh || fail "relay (see docs/BACKEND.md)"

# --- 10. Deployment configuration ---------------------------------------------
# The relay's TLS vhost logged carefully and its two siblings inherited nginx's
# combined format into a directory the stock logrotate keeps for 14 days (AUDIT
# 5.29). The configuration was right where someone had thought about it and wrong
# in the two places nobody had. Reads the committed files, not the live box: a
# check that needs SSH cannot run in CI, and the box is compared to these files by
# an operator step in the runbook.
step "deployment configuration cannot log what the threat model forbids"
./Scripts/verify-nginx-config.py --self-test || fail "the nginx configuration gate cannot be trusted"
./Scripts/verify-nginx-config.py || fail "the nginx configuration would retain request metadata (AUDIT 5.29)"

# --- 11. Backup scope (P9.S05) ------------------------------------------------
# A backup is the one operation that can repeal the retention policy in silence:
# nothing fails and no test goes red, the deleted messages simply return at
# restore time. Beside the deployment gate above because it is the same class of
# defect — a decision that lives in an operational file and drifts away from the
# design it was meant to implement. Offline: it reads the migrations and the
# backup script, never a database and never the box.
step "backups cannot repeal the retention policy (BACKEND.md 4)"
./Scripts/verify-backup-scope.sh --self-test || fail "the backup-scope gate cannot be trusted"
./Scripts/verify-backup-scope.sh || fail "a schema table is unclassified, or a retention-critical table would be backed up (docs/BACKEND.md 4)"

# --- 12. Product and documentation honesty -----------------------------------
# Cipher must not present a control or security boundary it does not provide, in any
# language or canonical document. See the two focused scripts for what they check and why.
#
# The self-test runs first, every time. The check this replaced was a shell grep that
# reported "ok" for a while with a live claim in the tree — a broken command substitution
# meant it searched nothing, and passing is exactly what a broken check looks like. So the
# gate demonstrates it can still fail before its pass is believed.
step "product and documentation honesty"
./Scripts/verify-localization.py --self-test || fail "the localization gate cannot be trusted"
./Scripts/verify-localization.py || fail "a retired claim is rendered, or the string catalog has drifted (docs/AUDIT.md 5.4, 5.11)"
./Scripts/verify-doc-key-boundary.py --self-test || fail "the documentation key-boundary gate cannot be trusted"
./Scripts/verify-doc-key-boundary.py || fail "documentation collapsed public, private E2E, or operational server keys"

# --- 13. Third-party licence obligations (AUDIT 6.2) -------------------------
# libsignal is AGPL-3.0 and NOTICE.md obligation 3 is to surface its acknowledgements in the
# app. Placed beside the honesty gate above rather than near the build gates, because the
# failure it catches is the same kind: something the product claims, or is obliged to say,
# quietly stopping being true. A pod update that changed a licence would otherwise ship the
# previous one with nobody looking.
step "third-party licences ship with the app (AUDIT 6.2)"
./Scripts/verify-acknowledgements.sh || fail "the app does not ship libsignal's licence — NOTICE.md obligation 3"

# --- 14. Module boundary -----------------------------------------------------
# No LibSignalClient type may appear in CipherCrypto's public API. Runs before the tests
# because it needs only a build, and because a leaked handle type is a concurrency defect
# that no amount of green tests would surface.
step "module boundary (no libsignal type in the public API)"
# Two different verdicts, because this message asserts a finding about the code and one of
# them is not one (AUDIT 6.25). Exit 78 means the gate could not run — it has already said
# why on stderr — and reporting that as "a type is exposed" sends a reviewer hunting a leak
# that does not exist. That is what happened on 2026-08-11, when two simulators sharing a
# name made `-destination name=…` ambiguous.
boundary_rc=0
./Scripts/verify-api-boundary.sh || boundary_rc=$?
case "$boundary_rc" in
0) ;;
78) fail "the module-boundary gate could not run — see its message above (AUDIT 6.25)" ;;
*) fail "a LibSignalClient type is exposed in CipherCrypto's public API" ;;
esac

# --- 15. Crypto tests --------------------------------------------------------
# App-hosted (AUDIT 6.6) and therefore serial. This also covers LockedDecisionsTests, which
# is what stops the six locked protocol decisions from being quietly "fixed".
step "tests: CipherCrypto + Cipher (app-hosted, serial)"

LOG=/tmp/cipher-verify-tests.log

run_tests() {
  xcodebuild test \
    -workspace "$WORKSPACE" \
    -scheme Cipher \
    -destination "$DESTINATION" \
    2>&1 | tee "$LOG" |
    grep -E "^Test Case.*failed|^✘|error:|Executed [0-9]+ tests|Test run with|TEST (SUCCEEDED|FAILED)" ||
    true
}

# A simulator still winding down from a previous build refuses the launch with
# "Application failed preflight checks ... Busy". That is the documented cost of hosting
# the tests in the app (AUDIT 6.6) — it is an infrastructure failure, not a test failure,
# and reporting it as red trains people to re-run red builds until they go green.
#
# Retried exactly once, and only when the log shows a launch failure AND no test actually
# failed. A real failure is never retried: that would be how a flaky test hides.
#
# The pattern list is the gate. It was written from the failures seen at the time and
# missed one that has since been observed: "cannot be located on disk", which CoreSimulator
# reports when the freshly installed app is not yet visible to the launch. That is the same
# class of fault — the simulator, not the code — but it fell through to the retry's `else`,
# so an infrastructure failure was reported as a test failure and, worse, was not retried.
# A missing pattern here is silent by construction: it looks exactly like a real failure.
#
# Three more were added on 2026-08-09, from a run of this very script that reported a red
# build for a DerivedData directory that disappeared mid-run. CoreSimulator says "Simulator
# device failed to install the application" — the list had "Failed to install the requested
# application", which is a different sentence from a different layer. Second time this list
# has been wrong in the same direction, which is why every entry is a string somebody read
# in a log rather than one somebody expected.
simulator_infrastructure_patterns='Application failed preflight checks|Simulator device failed to launch|RequestDenied|cannot be located on disk|Unable to boot device|Failed to install the requested application|The request was denied by service delegate|Simulator device failed to install the application|Cannot launch simulated executable|Failed to install or launch the test runner'

simulator_was_busy() {
  local log="${1:-$LOG}"
  grep -qE "$simulator_infrastructure_patterns" "$log" &&
    ! grep -q "^Test Case.*failed" "$log"
}

# The classifier decides whether a red run is retried, so a broken one either hides a real
# failure behind a retry or reports an infrastructure fault as a test failure. It has never
# been exercised — every pattern in it was added from a log someone happened to read.
# Proved here, on every run, before it is trusted (AUDIT R2).
selftest_simulator_classifier() {
  local probe cases=0
  probe="$(mktemp)"

  # Faults observed from real runs, written out as literals rather than derived from the
  # pattern list. Deriving them from the list is the trap: the loop would then test
  # whatever the list happens to contain, so *deleting* a pattern also deletes its own
  # test and the suite stays green — which is the exact defect 6.14 is about, reproduced
  # inside its own fix. The first version of this self-test did that.
  local fault
  for fault in \
    "2026-01-01 Application failed preflight checks for ... Busy" \
    "Simulator device failed to launch com.cipher.app" \
    "RequestDenied: The request was denied by service delegate" \
    "The application ... cannot be located on disk" \
    "Unable to boot device in current state: Booted" \
    "Failed to install the requested application" \
    "Simulator device failed to install the application." \
    "Cannot launch simulated executable: no file found at /path/Cipher.app" \
    "Cipher encountered an error (Failed to install or launch the test runner."; do
    printf '%s\n' "$fault" >"$probe"
    simulator_was_busy "$probe" ||
      fail "the simulator-fault classifier no longer recognises an observed fault: $fault"
    cases=$((cases + 1))
  done

  # And a real test failure must never be retried, even when the log also carries an
  # infrastructure line: retrying a genuine failure is how a flaky test hides.
  printf 'Test Case failed\n' >"$probe"
  ! simulator_was_busy "$probe" ||
    fail "the classifier treats a test failure as an infrastructure fault"
  cases=$((cases + 1))

  printf 'Application failed preflight checks\nTest Case failed\n' >"$probe"
  ! simulator_was_busy "$probe" ||
    fail "the classifier would retry a run that contains a real test failure"
  cases=$((cases + 1))

  # A clean log is not an infrastructure fault either.
  printf 'Executed 10 tests, with 0 failures\n' >"$probe"
  ! simulator_was_busy "$probe" ||
    fail "the classifier fires on a log with no fault in it"
  cases=$((cases + 1))

  rm -f "$probe"
  echo "  ok    self-test: $cases cases — the simulator-fault classifier still fires, and only when it should"
}

# Settle the simulator deterministically rather than hoping. `simctl shutdown` returns
# before the device has finished transitioning, so retrying straight after it hits the
# same "Busy" preflight — which is how the first version of this retry failed twice in a
# row and reported a red build for an infrastructure problem.
settle_simulator() {
  xcrun simctl shutdown all >/dev/null 2>&1 || true
  xcrun simctl boot "$SIMULATOR" >/dev/null 2>&1 || true
  # Blocks until the device reports booted; bounded by the step's own runtime.
  xcrun simctl bootstatus "$SIMULATOR" -b >/dev/null 2>&1 || true
}

selftest_simulator_classifier

run_tests
attempt=1
while [ "$attempt" -le 2 ] && ! grep -q "TEST SUCCEEDED" "$LOG" && simulator_was_busy; do
  echo "  !     simulator was busy (AUDIT 6.6); settling it and retrying (attempt $attempt of 2)"
  settle_simulator
  run_tests
  attempt=$((attempt + 1))
done

grep -q "TEST SUCCEEDED" "$LOG" ||
  fail "CipherCrypto tests (full log: $LOG)"

# The locked decisions must actually have run, not merely not-failed. A suite that silently
# stops including them would otherwise pass this gate.
grep -q "LockedDecisionsTests" "$LOG" ||
  fail "LockedDecisionsTests did not run — the §0.2 protocol decisions are unguarded"

# Both suites, not just one. The Cipher scheme attaches CipherCryptoTests *and* CipherTests,
# so one simulator launch covers both (AUDIT 6.6 makes extra launches expensive). A scheme
# edit that quietly dropped either would otherwise leave this gate green over half the tests.
grep -q "SessionCredentialTests" "$LOG" ||
  fail "CipherTests did not run — the auth gate is unguarded (P3.S01)"
grep -q "AppLockTests" "$LOG" ||
  fail "AppLockTests did not run — the app lock is unguarded (P3.S02)"

# And the Swift Testing suites, which the three assertions above cannot cover: they run under
# a different runner and report through different lines, so `Executed N tests` never counts
# them and `** TEST SUCCEEDED **` prints whether or not any of them ran. Certificate pinning
# lives *only* here — the control that stands between this client and a substituted relay has
# no XCTest anywhere — so a scheme or membership edit that dropped these files would have left
# this gate green over it. AUDIT 6.19.
#
# By display name, as literals. Renaming a suite is meant to fail this and be updated
# deliberately; deriving the list from the sources would make the check follow whatever the
# sources happen to contain, which is the defect AUDIT R5 records.
for suite in "Certificate pinning" "Invite redemption" "Relay transport bounds"; do
  grep -qF "Suite \"$suite\" passed" "$LOG" ||
    fail "the Swift Testing suite \"$suite\" did not run (AUDIT 6.19; full log: $LOG)"
done

# --- 16. App builds ----------------------------------------------------------
# Hosting the tests in the app means a broken app target blocks the security suite, so the
# app build is part of the gate rather than an afterthought.
step "Cipher app builds (simulator)"
xcodebuild build \
  -workspace "$WORKSPACE" \
  -scheme Cipher \
  -destination "$DESTINATION" \
  -configuration Debug \
  2>&1 | grep -E "error:|BUILD (SUCCEEDED|FAILED)" | sort -u | grep -q "BUILD SUCCEEDED" ||
  fail "Cipher app build"
echo "  ok    app builds"

# --- 17. Release device build ------------------------------------------------
# Release + arm64 is where optimisation-dependent and warnings-as-errors problems appear.
# Signing is disabled: this checks that it compiles and links, not that it is distributable.
if [ "$FAST" -eq 0 ]; then
  step "Release arm64 device build"
  xcodebuild build \
    -workspace "$WORKSPACE" \
    -scheme Cipher \
    -sdk iphoneos \
    -destination 'generic/platform=iOS' \
    -configuration Release \
    CODE_SIGNING_ALLOWED=NO \
    2>&1 | grep -E "error:|BUILD (SUCCEEDED|FAILED)" | sort -u | grep -q "BUILD SUCCEEDED" ||
    fail "Release device build"
  echo "  ok    release arm64 builds"

  # --- 17. No debug affordance or retired claim survives into Release --------
  # Fencing the *buttons* that drive a debug switch is not the same as fencing the switch:
  # `debugSkipToMain` was a live authentication bypass in Release for exactly that reason
  # (AUDIT 5.6). This asserts against the built artifact, which is the only place the
  # question is actually settled — source-level greps miss whatever the compiler kept.
  #
  # The whole bundle, not just the executable. `#if DEBUG` fences *code*; resources compile
  # in regardless, and cs.lproj/Localizable.strings was shipping "Skip to App", "Unlock &
  # Show Main" and "Demo Controls" into Release while the executable was clean (AUDIT 5.11).
  # Anything that names a debug affordance to an attacker reading the IPA counts.
  step "Release bundle carries no debug affordance or retired claim"
  APP="$(ls -d "$HOME/Library/Developer/Xcode/DerivedData/Cipher-"*/Build/Products/Release-iphoneos/Cipher.app 2>/dev/null | head -1)"
  [ -n "$APP" ] && [ -d "$APP" ] || fail "could not locate the Release bundle to audit"

  # Xcode 26 emits Localizable.strings as binary plists. A recursive grep sees the English
  # key in the executable but not a Czech value in that plist, so the old "whole bundle"
  # audit was not actually multilingual (AUDIT 5.30). Decode every compiled string table
  # once, failing closed if one cannot be read, and search that text alongside raw files.
  localized_bundle_text=""
  localized_bundle_files=0
  while IFS= read -r strings_file; do
    decoded_strings="$(plutil -convert json -o - "$strings_file" 2>/dev/null)" ||
      fail "could not decode compiled localization table ${strings_file#$APP/}"
    localized_bundle_text+="$decoded_strings"$'\n'
    localized_bundle_files=$((localized_bundle_files + 1))
  done < <(find "$APP" -type f -name '*.strings' -print)
  [ "$localized_bundle_files" -gt 0 ] || fail "the Release bundle contains no localization tables"

  bundle_hits() {
    local needle="$1"
    grep -rlaF "$needle" "$APP" 2>/dev/null || true
    if [[ "$localized_bundle_text" == *"$needle"* ]]; then
      echo "compiled localization tables"
    fi
  }

  email_address_pattern='[[:alnum:]._%+-]+@[[:alnum:].-]+\.[[:alpha:]]{2,}'
  bundle_email_hits() {
    # This is a product-copy rule, not a dependency-byte rule. Opaque libsignal bytes can
    # resemble an address but the framework renders no UI. Scan Cipher's executable and
    # first-party resources, pruning Frameworks; the security-symbol denylist above still
    # audits the complete bundle.
    find "$APP" -path "$APP/Frameworks" -prune -o -type f \
      -exec grep -laE "$email_address_pattern" {} + 2>/dev/null || true
    if printf '%s' "$localized_bundle_text" | grep -Eq "$email_address_pattern"; then
      echo "compiled localization tables"
    fi
  }

  # Two positive controls, first. Every check below is "found nothing", and "found nothing"
  # is also what a broken search looks like. The symbol proves raw bundle search works; the
  # Czech Settings translation proves binary localization decoding works. See AUDIT R2.
  if ! bundle_hits "ChatsListView" >/dev/null; then
    fail "the Release bundle audit found no ChatsListView — the search itself is broken, so its all-clear would be meaningless"
  fi
  if ! bundle_hits "Nastavení" >/dev/null; then
    fail "the Release bundle audit found no Czech Settings translation — compiled-localization search is broken"
  fi
  if ! printf '%s%s%s\n' "probe" "@" "example.invalid" | grep -Eq "$email_address_pattern"; then
    fail "the Release bundle email-address detector is broken"
  fi

  leaked=0
  for sym in \
    debugSkipToMain resetDemoState UICatalogView NewGroupView createGroup \
    CallsListView ActiveCallView IncomingCallView AttachmentSheet GroupInfoView \
    MediaGalleryGrid previewCalls previewChatID \
    "Skip to App" "Unlock & Show Main" "Demo Controls" "UI Catalog" "Reset Onboarding" \
    "Leave & Reset Demo" "Simulate incoming call" "Hold to record" \
    "Recording… release to cancel" \
    "Keys stay on your device" "Klíče zůstávají na zařízení" \
    "Your identity key is generated on your iPhone" "Váš identitní klíč se vytvoří na vašem iPhonu" \
    "The relay only sees ciphertext" "Relay vidí jen šifrovaný text" \
    "never plaintext, never your keys" "nikdy otevřený text, nikdy vaše klíče" \
    "Keys never leave your devices" "Klíče neopouštějí vaše zařízení" \
    "Choose Photo" "Vybrat fotku" \
    "Contact support" "Kontaktovat podporu"; do
    if hits="$(bundle_hits "$sym")" && [ -n "$hits" ]; then
      echo "  !     '$sym' is present in: $(printf '%s\n' "$hits" | sed "s|$APP/||" | tr '\n' ' ')"
      leaked=1
    fi
  done
  if hits="$(bundle_email_hits)" && [ -n "$hits" ]; then
    echo "  !     an email address is present in: $(printf '%s\n' "$hits" | sed "s|$APP/||" | tr '\n' ' ')"
    leaked=1
  fi
  [ "$leaked" -eq 0 ] || fail "a debug affordance or retired claim ships in Release (AUDIT 5.6, 5.11, 5.19, 5.30)"
  echo "  ok    no debug affordance or retired claim anywhere in the Release bundle"

  # --- 18. Required-reason APIs are declared ---------------------------------
  # Same bundle, different question. libsignal is a *dynamic* framework, so its whole symbol
  # surface ships whether Cipher calls it or not — a required-reason API can appear with no
  # source change on our side, and the first sign would otherwise be App Review.
  step "Required-reason APIs declared (AUDIT 6.1)"
  ./Scripts/verify-privacy-manifest.sh "$APP" || fail "privacy manifest (see docs/PRIVACY_MANIFEST.md)"
fi

# --- Manual items -----------------------------------------------------------
cat <<'EOF'

All mechanical gates passed.

Still your job — these are judgement, not greps (plan, Standing regression checklist 7-9):
  7. Groups / sender-key still rejected everywhere they could have crept in
  8. Identity change: receive trusted, send refused until acceptIdentity names the exact key
  9. docs/AUDIT.md and the plan's STATUS block updated if anything changed status
EOF
