#!/bin/bash
#
# Supply-chain verification gate.
#
# Asserts that what the build actually consumes still matches the reviewed pins in
# Vendor/libsignal/PINS.env. Run in CI on every build and before every release.
#
# This exists because the pins are the only authenticity control we have for
# libsignal on iOS: Signal does not sign or attest the iOS FFI binary, and a git
# tag is mutable upstream.
#
# # Two modes, and the reason there are two (AUDIT 1.14)
#
#   --pre-install   Offline. The checks that must hold *before* `pod install`.
#   (no argument)   Everything, including the three that need the network.
#
# The ordering was the finding. CocoaPods resolves the dependency and runs the
# podspec — including its script phase — as part of `pod install`, and this gate
# ran afterwards. While the Podfile named a *tag*, that meant a moved tag bought
# build-time execution in a job holding a repository token, and the gate could
# only report it after the fact. The Podfile now names the audited commit, so
# there is no resolution left to influence; `--pre-install` is what keeps that
# true, by refusing before CocoaPods runs if the pin has been loosened back to a
# tag or points somewhere PINS.env did not authorise.
#
# Copyright (C) 2026 Jan Richter
# SPDX-License-Identifier: AGPL-3.0-only

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PINS="$ROOT/Vendor/libsignal/PINS.env"

fail() { printf '  FAIL  %s\n' "$*" >&2; FAILED=1; }
pass() { printf '  ok    %s\n' "$*"; }
FAILED=0

MODE=full
case "${1:-}" in
  ""|--full)     MODE=full ;;
  --pre-install) MODE=pre ;;
  --self-test)   MODE=selftest ;;
  *)
    echo "usage: $0 [--pre-install | --self-test]" >&2
    exit 2
    ;;
esac

[ -f "$PINS" ] || { echo "missing $PINS" >&2; exit 1; }
# shellcheck disable=SC1090
set -a; . "$PINS"; set +a

# --- Offline checks ---------------------------------------------------------
#
# Parameterised by root so --self-test can run them against fabricated trees. A
# grep that matches nothing looks exactly like a grep that found nothing wrong
# (AUDIT R2), and these are all greps.

# strip_ruby_comments removes `#` to end of line.
#
# **Required, not tidiness (AUDIT R3).** The Podfile now carries a paragraph
# explaining why the pin is a commit and not a tag, and that paragraph contains
# the word this check forbids. A scanner that read comments would fire on the
# documentation of the rule it enforces.
#
# It also truncates at a `#` inside a string — Ruby interpolation, say. That can
# only ever *remove* text, so it cannot manufacture a match; the pin lines it
# cares about contain no `#`.
strip_ruby_comments() { sed 's/#.*//' "$1"; }

# check_podfile_pins_a_commit refuses a Podfile that would let CocoaPods resolve
# a mutable reference.
#
# The whole file is scanned rather than one pod's block: LibSignalClient is the
# only dependency, so "no tag anywhere" is exact today, and a second pod would be
# a supply-chain review in its own right. The failure direction if one is ever
# added is refusal, which is the safe one.
check_podfile_pins_a_commit() {
  local root="$1"
  local podfile="$root/Podfile"
  local code
  if [ ! -f "$podfile" ]; then
    fail "no Podfile at $podfile"
    return
  fi
  code="$(strip_ruby_comments "$podfile")"

  if printf '%s\n' "$code" | grep -qE '(^|[^_[:alnum:]])tag:'; then
    fail "the Podfile resolves a dependency by TAG — a tag is mutable upstream, and CocoaPods runs what it resolves"
  elif ! printf '%s\n' "$code" | grep -qE '(^|[^_[:alnum:]])commit:'; then
    fail "the Podfile does not pin a commit"
  elif ! printf '%s\n' "$code" | grep -q "LIBSIGNAL_COMMIT"; then
    fail "the Podfile pins a commit that does not come from PINS.env"
  else
    pass "the Podfile resolves libsignal by commit, from PINS.env"
  fi
}

# check_libsignal_is_the_only_pod enforces THREAT_MODEL.md §4.1.
#
# The comment above check_podfile_pins_a_commit has always said that libsignal
# being the only dependency is what makes "no tag anywhere" exact, and that a
# second pod "would be a supply-chain review in its own right" — but nothing
# made that true. This does. §4.1 is a standing prohibition ("No analytics. No
# telemetry. No third-party SDKs"), and §4.4 forbids a crash reporter that could
# capture plaintext; both are enforced here at the only place a dependency can
# enter the app, which is cheaper and more exact than trying to recognise every
# reporter SDK by name (P8.S08).
#
# Refuses a Podfile with **no** pod line as well as one with too many: a check
# whose "nothing forbidden found" answer is also its "I read nothing" answer is
# not a check (AUDIT R2).
check_libsignal_is_the_only_pod() {
  local root="$1"
  local podfile="$root/Podfile"
  local code names extra
  if [ ! -f "$podfile" ]; then
    fail "no Podfile at $podfile"
    return
  fi
  # Comments stripped first, so the paragraph above — which names the very thing
  # it forbids — cannot trip it (AUDIT R3).
  code="$(strip_ruby_comments "$podfile")"

  # A Podfile is Ruby and `pod` is a method, so `pod 'X'`, `pod "X"` and `pod('X')`
  # are all the same declaration. The first version of this matched only the
  # space-separated form and therefore reported "LibSignalClient is the only
  # declared dependency" for a Podfile containing `pod('FirebaseCrashlytics')` —
  # a false negative, which is the direction that ships the SDK. Found in review.
  #
  # `[^_[:alnum:]]` before the keyword keeps `podspec` and `my_pod` from matching.
  names="$(printf '%s\n' "$code" \
    | grep -oE "(^|[^_[:alnum:]])pod[[:space:]]*\(?[[:space:]]*['\"][^'\"]+['\"]" \
    | grep -oE "['\"][^'\"]+['\"]" | tr -d "\"'" | sort -u)"

  if [ -z "$names" ]; then
    fail "the Podfile declares no pod at all — this check read nothing, which is not a pass"
    return
  fi

  extra="$(printf '%s\n' "$names" | grep -v '^LibSignalClient$' || true)"
  if [ -n "$extra" ]; then
    fail "the Podfile declares a dependency other than LibSignalClient: $(printf '%s' "$extra" | tr '\n' ',') — every dependency is an exfiltration path and a supply-chain risk (THREAT_MODEL.md §4.1), and a crash reporter is specifically forbidden (§4.4)"
  else
    pass "LibSignalClient is the only declared dependency"
  fi
}

# check_lock_records_the_audited_commit asserts what the last resolution actually
# produced, which is a different question from what the Podfile asks for.
check_lock_records_the_audited_commit() {
  local root="$1"
  local lock="$root/Podfile.lock"
  if [ ! -f "$lock" ]; then
    fail "no Podfile.lock at $lock"
    return
  fi

  if grep -q ':tag:' "$lock"; then
    fail "Podfile.lock still records a :tag: — re-run 'bundle exec pod install'"
  elif ! grep -q ":commit: ${LIBSIGNAL_COMMIT}" "$lock"; then
    fail "Podfile.lock does not pin ${LIBSIGNAL_COMMIT}"
  elif ! grep -q "LibSignalClient (${LIBSIGNAL_VERSION})" "$lock"; then
    fail "Podfile.lock does not record LibSignalClient ${LIBSIGNAL_VERSION}"
  else
    pass "Podfile.lock pins ${LIBSIGNAL_COMMIT}"
  fi
}

check_no_retired_snapshot() {
  local root="$1"
  if [ -e "$root/libsignal-main.zip" ]; then
    fail "libsignal-main.zip is back — an unsigned, unpinned branch snapshot must not be used"
  else
    pass "no unpinned libsignal snapshot in the tree"
  fi
}

run_offline_checks() {
  check_podfile_pins_a_commit "$1"
  check_libsignal_is_the_only_pod "$1"
  check_lock_records_the_audited_commit "$1"
  check_no_retired_snapshot "$1"
}

# --- Self-test --------------------------------------------------------------
#
# Every offline check, made to fail against its own defect and then to pass
# against a correct tree. Without this the three greps above are three ways to
# report a clean tree they never read.
if [ "$MODE" = selftest ]; then
  tmp="$(mktemp -d)"
  cases=0
  failures=0

  # expect <want: pass|fail> <description> — runs the offline checks over $tmp.
  # Redirection, never command substitution: `$(...)` runs in a subshell, so the
  # FAILED the checks set would not reach this function and every negative case
  # would read as accepted. That is how the first version of this self-test
  # reported eight passes over five checks that had not run.
  outfile="$(mktemp)"
  trap 'rm -rf "$tmp" "$outfile"' EXIT

  expect() {
    local want="$1"
    local what="$2"
    cases=$((cases + 1))
    FAILED=0
    run_offline_checks "$tmp" >"$outfile" 2>&1 || true
    if [ "$want" = fail ] && [ "$FAILED" -eq 0 ]; then
      printf '  FAIL  self-test: %s was accepted\n' "$what" >&2
      cat "$outfile" >&2
      failures=$((failures + 1))
    elif [ "$want" = pass ] && [ "$FAILED" -ne 0 ]; then
      printf '  FAIL  self-test: %s was refused\n' "$what" >&2
      cat "$outfile" >&2
      failures=$((failures + 1))
    fi
  }

  good_podfile() {
    cat >"$tmp/Podfile" <<EOF
pod 'LibSignalClient', git: PINS['LIBSIGNAL_GIT_URL'], commit: PINS['LIBSIGNAL_COMMIT']
EOF
  }
  good_lock() {
    cat >"$tmp/Podfile.lock" <<EOF
PODS:
  - LibSignalClient (${LIBSIGNAL_VERSION})
CHECKOUT OPTIONS:
  LibSignalClient:
    :commit: ${LIBSIGNAL_COMMIT}
EOF
  }

  good_podfile; good_lock
  expect pass "a correct tree"

  # The finding itself.
  printf "pod 'LibSignalClient', git: X, tag: PINS['LIBSIGNAL_TAG']\n" >"$tmp/Podfile"
  expect fail "a Podfile resolving by tag"

  # R3: the prose explaining the rule names the thing it forbids.
  cat >"$tmp/Podfile" <<'EOF'
# `tag:` was the defect — a tag is mutable and CocoaPods runs what it resolves.
pod 'LibSignalClient', git: PINS['LIBSIGNAL_GIT_URL'], commit: PINS['LIBSIGNAL_COMMIT']
EOF
  expect pass "a Podfile whose comment names a tag"

  # A hard-coded commit is not the audited one; PINS.env must be the source.
  printf "pod 'LibSignalClient', git: X, commit: 'deadbeef'\n" >"$tmp/Podfile"
  expect fail "a Podfile pinning a commit from outside PINS.env"

  good_podfile
  printf 'CHECKOUT OPTIONS:\n  LibSignalClient:\n    :tag: %s\n' "$LIBSIGNAL_TAG" >"$tmp/Podfile.lock"
  expect fail "a lockfile still recording a tag"

  printf 'PODS:\n  - LibSignalClient (%s)\nCHECKOUT OPTIONS:\n    :commit: %s\n' \
    "$LIBSIGNAL_VERSION" "0000000000000000000000000000000000000000" >"$tmp/Podfile.lock"
  expect fail "a lockfile pinning an unaudited commit"

  # THREAT_MODEL.md §4.1 / §4.4, both directions. A second pod is refused, and so
  # is a Podfile with none at all — otherwise "found nothing forbidden" and "read
  # nothing" would be the same verdict.
  cat >"$tmp/Podfile" <<EOF
pod 'LibSignalClient', git: PINS['LIBSIGNAL_GIT_URL'], commit: PINS['LIBSIGNAL_COMMIT']
pod 'FirebaseCrashlytics'
EOF
  expect fail "a second pod beside libsignal"

  # The parenthesised form is Ruby's other calling convention for the same DSL
  # method, and the first version of this check matched only the space-separated
  # one — so `pod('FirebaseCrashlytics')` was reported as "LibSignalClient is the
  # only declared dependency". Found in review, and pinned here so it cannot
  # return: a false negative here ships the SDK.
  cat >"$tmp/Podfile" <<EOF
pod 'LibSignalClient', git: PINS['LIBSIGNAL_GIT_URL'], commit: PINS['LIBSIGNAL_COMMIT']
pod('FirebaseCrashlytics')
EOF
  expect fail "a second pod declared with parentheses"

  : >"$tmp/Podfile"
  expect fail "a Podfile declaring no pod at all"

  good_podfile

  good_lock
  : >"$tmp/libsignal-main.zip"
  expect fail "a retired branch snapshot"
  rm -f "$tmp/libsignal-main.zip"

  expect pass "a correct tree again, after every defect was removed"

  if [ "$failures" -ne 0 ]; then
    echo "SELF-TEST FAILED ($failures of $cases)" >&2
    exit 1
  fi
  echo "  ok    self-test: $cases cases — every offline check still fails on its defect"
  exit 0
fi

echo "Verifying libsignal supply chain against $PINS"

# --- The pin itself, offline and before anything resolves it ----------------
echo "[pin] the dependency is pinned to an immutable commit"
run_offline_checks "$ROOT"

if [ "$MODE" = pre ]; then
  echo
  if [ "$FAILED" -ne 0 ]; then
    echo "SUPPLY CHAIN PRE-INSTALL CHECK FAILED — not running CocoaPods" >&2
    exit 1
  fi
  echo "Pin verified; safe to resolve dependencies."
  exit 0
fi

# --- Upstream, which needs the network --------------------------------------

# The tag must still resolve to the commit we reviewed.
#
# Since the Podfile pins the commit, this no longer stands between a moved tag
# and code execution here — it is an **alarm that upstream changed**, which is
# still worth having: a moved release tag means the bytes behind v0.99.1 are not
# the bytes this project reviewed, and that is a fact to learn from a gate rather
# than from a diff months later.
echo "[upstream] tag -> commit"
RESOLVED="$(git ls-remote "$LIBSIGNAL_GIT_URL" "refs/tags/${LIBSIGNAL_TAG}^{}" | awk '{print $1}')"
if [ -z "$RESOLVED" ]; then
  fail "could not resolve ${LIBSIGNAL_TAG} at ${LIBSIGNAL_GIT_URL} (network?)"
elif [ "$RESOLVED" != "$LIBSIGNAL_COMMIT" ]; then
  fail "tag ${LIBSIGNAL_TAG} now resolves to ${RESOLVED}, expected ${LIBSIGNAL_COMMIT} — THE TAG MOVED"
else
  pass "${LIBSIGNAL_TAG} -> ${LIBSIGNAL_COMMIT}"
fi

# The published checksum for that release must be unchanged.
echo "[upstream] published checksum"
UPSTREAM_SHA="$(curl -fsSL --max-time 30 \
  "https://github.com/signalapp/libsignal/releases/download/${LIBSIGNAL_TAG}/libsignal-client-ios-build-${LIBSIGNAL_TAG}.tar.gz.sha256" \
  2>/dev/null | awk '{print $1}' || true)"
if [ -z "$UPSTREAM_SHA" ]; then
  fail "could not fetch the published .sha256 asset (network?)"
elif [ "$UPSTREAM_SHA" != "$LIBSIGNAL_FFI_PREBUILD_CHECKSUM" ]; then
  fail "published checksum ${UPSTREAM_SHA} != pinned ${LIBSIGNAL_FFI_PREBUILD_CHECKSUM}"
else
  pass "checksum matches the official release asset"
fi

# The cached artifact the build actually links, if present, must hash correctly.
# We verify independently rather than trusting the pod's own check, which uses a
# bare Python `assert` and is stripped under `python -O`.
echo "[local] cached artifact"
CACHED="$HOME/Library/Caches/org.signal.libsignal/libsignal-client-ios-build-v${LIBSIGNAL_VERSION}.tar.gz"
if [ -f "$CACHED" ]; then
  ACTUAL="$(shasum -a 256 "$CACHED" | awk '{print $1}')"
  if [ "$ACTUAL" != "$LIBSIGNAL_FFI_PREBUILD_CHECKSUM" ]; then
    fail "cached artifact hashes to ${ACTUAL}, expected ${LIBSIGNAL_FFI_PREBUILD_CHECKSUM}"
  else
    pass "cached artifact hash verified"
  fi
else
  pass "no cached artifact yet (will be fetched and verified at build time)"
fi

echo
if [ "$FAILED" -ne 0 ]; then
  echo "SUPPLY CHAIN VERIFICATION FAILED" >&2
  exit 1
fi
echo "Supply chain verified."
