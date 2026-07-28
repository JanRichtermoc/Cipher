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
TOTAL=10
[ "$FAST" -eq 1 ] && TOTAL=7

step() {
  STEP=$((STEP + 1))
  printf '\n=== [%d/%d] %s\n' "$STEP" "$TOTAL" "$1"
}

fail() {
  printf '\nFAILED: %s\n' "$1" >&2
  exit 1
}

# --- 1. Supply chain --------------------------------------------------------
# First because a moved tag or a changed checksum invalidates everything after it:
# there is no point testing a binary whose provenance is in question.
step "supply chain"
if [ "$OFFLINE" -eq 1 ]; then
  echo "  skipped (--offline); this check MUST run before any release"
else
  ./Scripts/verify-supply-chain.sh || fail "supply chain"
fi

# --- 2. App target manifest -------------------------------------------------
# The app target uses synchronized folders, so a file can join the shipping bundle with no
# project-file edit. Cheap, so it runs before anything is compiled.
step "app target manifest"
./Scripts/verify-app-target-manifest.sh || fail "app target manifest"

# --- 3. No plaintext logging ------------------------------------------------
# A grep, not a proof. It catches the accidental `print(message)` during development, which
# is the realistic failure — not a determined attempt to exfiltrate. The crypto module has
# no business calling print/NSLog at all: it logs through CipherLog, which is redacted.
step "no plaintext logging in CipherCrypto"
if grep -rnE '(^|[^A-Za-z_.])(print|NSLog|debugPrint|dump)[[:space:]]*\(' \
  CipherCrypto/Sources --include='*.swift'; then
  fail "CipherCrypto must log only through CipherLog (see RedactingLogger.swift)"
fi
echo "  ok    no direct print/NSLog in the crypto module"

# --- 4. UI honesty and localization drift -----------------------------------
# Cipher must not present a control implying protection it does not provide, in any
# language. See Scripts/verify-localization.py for what it checks and why.
#
# The self-test runs first, every time. The check this replaced was a shell grep that
# reported "ok" for a while with a live claim in the tree — a broken command substitution
# meant it searched nothing, and passing is exactly what a broken check looks like. So the
# gate demonstrates it can still fail before its pass is believed.
step "UI honesty and localization drift"
./Scripts/verify-localization.py --self-test || fail "the localization gate cannot be trusted"
./Scripts/verify-localization.py || fail "a retired claim is rendered, or the string catalog has drifted (docs/AUDIT.md 5.4, 5.11)"

# --- 5. Module boundary -----------------------------------------------------
# No LibSignalClient type may appear in CipherCrypto's public API. Runs before the tests
# because it needs only a build, and because a leaked handle type is a concurrency defect
# that no amount of green tests would surface.
step "module boundary (no libsignal type in the public API)"
./Scripts/verify-api-boundary.sh || fail "a LibSignalClient type is exposed in CipherCrypto's public API"

# --- 6. Crypto tests --------------------------------------------------------
# App-hosted (AUDIT 6.6) and therefore serial. This also covers LockedDecisionsTests, which
# is what stops the six locked protocol decisions from being quietly "fixed".
step "CipherCrypto tests (app-hosted, serial)"

LOG=/tmp/cipher-verify-tests.log

run_tests() {
  xcodebuild test \
    -workspace "$WORKSPACE" \
    -scheme CipherCrypto \
    -destination "$DESTINATION" \
    2>&1 | tee "$LOG" | grep -E "^Test Case.*failed|error:|Executed [0-9]+ tests|TEST (SUCCEEDED|FAILED)" || true
}

# A simulator still winding down from a previous build refuses the launch with
# "Application failed preflight checks ... Busy". That is the documented cost of hosting
# the tests in the app (AUDIT 6.6) — it is an infrastructure failure, not a test failure,
# and reporting it as red trains people to re-run red builds until they go green.
#
# Retried exactly once, and only when the log shows a launch failure AND no test actually
# failed. A real failure is never retried: that would be how a flaky test hides.
simulator_was_busy() {
  grep -qE "Application failed preflight checks|Simulator device failed to launch|RequestDenied" "$LOG" &&
    ! grep -q "^Test Case.*failed" "$LOG"
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
grep -q "LockedDecisionsTests" /tmp/cipher-verify-tests.log ||
  fail "LockedDecisionsTests did not run — the §0.2 protocol decisions are unguarded"

# --- 5. App builds ----------------------------------------------------------
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

# --- 6. Release device build ------------------------------------------------
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

  # --- 8. No debug affordance survives into a shipping bundle ----------------
  # Fencing the *buttons* that drive a debug switch is not the same as fencing the switch:
  # `debugSkipToMain` was a live authentication bypass in Release for exactly that reason
  # (AUDIT 5.6). This asserts against the built artifact, which is the only place the
  # question is actually settled — source-level greps miss whatever the compiler kept.
  #
  # The whole bundle, not just the executable. `#if DEBUG` fences *code*; resources compile
  # in regardless, and cs.lproj/Localizable.strings was shipping "Skip to App", "Unlock &
  # Show Main" and "Demo Controls" into Release while the executable was clean (AUDIT 5.11).
  # Anything that names a debug affordance to an attacker reading the IPA counts.
  step "Release bundle carries no debug affordance"
  APP="$(ls -d "$HOME/Library/Developer/Xcode/DerivedData/Cipher-"*/Build/Products/Release-iphoneos/Cipher.app 2>/dev/null | head -1)"
  [ -n "$APP" ] && [ -d "$APP" ] || fail "could not locate the Release bundle to audit"

  leaked=0
  for sym in \
    debugSkipToMain resetDemoState UICatalogView NewGroupView createGroup \
    "Skip to App" "Unlock & Show Main" "Demo Controls" "UI Catalog" "Reset Onboarding" \
    "Leave & Reset Demo"; do
    # -a: treat every file as text, so Mach-O, Assets.car and .strings are all searched.
    if hits="$(grep -rlaF "$sym" "$APP" 2>/dev/null)" && [ -n "$hits" ]; then
      echo "  !     '$sym' is present in: $(printf '%s\n' "$hits" | sed "s|$APP/||" | tr '\n' ' ')"
      leaked=1
    fi
  done
  [ "$leaked" -eq 0 ] || fail "a debug affordance ships in Release (AUDIT 5.6, 5.11)"
  echo "  ok    no debug affordance anywhere in the Release bundle"

  # --- 9. Required-reason APIs are declared ----------------------------------
  # Same bundle, different question. libsignal is a *dynamic* framework, so its whole symbol
  # surface ships whether Cipher calls it or not — a required-reason API can appear with no
  # source change on our side, and the first sign would otherwise be App Review.
  step "Required-reason APIs declared (AUDIT 6.1)"
  ./Scripts/verify-privacy-manifest.sh "$APP" || fail "privacy manifest (see docs/PRIVACY_MANIFEST.md)"
fi

# --- Manual items -----------------------------------------------------------
cat <<'EOF'

All mechanical gates passed.

Still your job — these are judgement, not greps (plan, Standing regression checklist 6-8):
  6. Groups / sender-key still rejected everywhere they could have crept in
  7. Identity change: receive trusted, send refused until acceptIdentity names the exact key
  8. docs/AUDIT.md and the plan's STATUS block updated if anything changed status
EOF
