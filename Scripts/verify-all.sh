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
TOTAL=13
[ "$FAST" -eq 1 ] && TOTAL=10

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

# --- 4. Invite-code-only identity -------------------------------------------
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

# --- 5. Dependency vulnerabilities ------------------------------------------
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

# --- 6. Relay ---------------------------------------------------------------
# Placed here, before anything that invokes xcodebuild, because it takes seconds
# and the iOS gates take half an hour. A relay defect discovered after a full
# simulator build is the same defect discovered thirty minutes later.
#
# Covers what needs no container: build, vet, gofmt, unit tests under the race
# detector, plus the compose invariants that P4.S02 names as anti-goals. The
# integration suite against a live Postgres and Redis is P4.S10.
step "relay: build, vet, tests, compose invariants"
./Scripts/verify-relay.sh || fail "relay (see docs/BACKEND.md)"

# --- 7. Product and documentation honesty -----------------------------------
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

# --- 8. Module boundary -----------------------------------------------------
# No LibSignalClient type may appear in CipherCrypto's public API. Runs before the tests
# because it needs only a build, and because a leaked handle type is a concurrency defect
# that no amount of green tests would surface.
step "module boundary (no libsignal type in the public API)"
./Scripts/verify-api-boundary.sh || fail "a LibSignalClient type is exposed in CipherCrypto's public API"

# --- 9. Crypto tests --------------------------------------------------------
# App-hosted (AUDIT 6.6) and therefore serial. This also covers LockedDecisionsTests, which
# is what stops the six locked protocol decisions from being quietly "fixed".
step "tests: CipherCrypto + Cipher (app-hosted, serial)"

LOG=/tmp/cipher-verify-tests.log

run_tests() {
  xcodebuild test \
    -workspace "$WORKSPACE" \
    -scheme Cipher \
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
grep -q "LockedDecisionsTests" "$LOG" ||
  fail "LockedDecisionsTests did not run — the §0.2 protocol decisions are unguarded"

# Both suites, not just one. The Cipher scheme attaches CipherCryptoTests *and* CipherTests,
# so one simulator launch covers both (AUDIT 6.6 makes extra launches expensive). A scheme
# edit that quietly dropped either would otherwise leave this gate green over half the tests.
grep -q "SessionCredentialTests" "$LOG" ||
  fail "CipherTests did not run — the auth gate is unguarded (P3.S01)"
grep -q "AppLockTests" "$LOG" ||
  fail "AppLockTests did not run — the app lock is unguarded (P3.S02)"

# --- 10. App builds ----------------------------------------------------------
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

# --- 11. Release device build ------------------------------------------------
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

  # --- 12. No debug affordance or retired claim survives into Release --------
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

  # --- 13. Required-reason APIs are declared ---------------------------------
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
