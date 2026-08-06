#!/bin/bash
#
# Gate: the Release build is actually iPhone-only.
#
# Copyright (C) 2026 Jan Richter
# SPDX-License-Identifier: AGPL-3.0-only
#
# # Why the project text is not the property (AUDIT 6.13, 6.14)
#
# `TARGETED_DEVICE_FAMILY = 1` was set, and grepping the project file for it said
# "iPhone-only". Release nonetheless resolved `SUPPORTS_MAC_DESIGNED_FOR_IPHONE_IPAD`
# and `SUPPORTS_XR_DESIGNED_FOR_IPHONE_IPAD` to YES, because those are separate
# settings that Xcode defaults on — so the shipping binary could run on an Apple
# silicon Mac and on visionOS while every document said iPhone. A gate that reads
# the project file would have agreed with the documents and been wrong.
#
# This asks the build system what it resolved, which is the only place the question
# is settled: defaults, xcconfigs, the Pods integration and per-configuration
# overrides all feed into it, and none of them are visible in a grep.
#
# # Why it is a security gate and not packaging hygiene
#
# Every storage and lock decision in this project was argued about an iPhone — the
# Keychain accessibility class (AUDIT 2.1), the app-switcher redaction (4.5), the
# local-only pasteboard (4.6), and an app lock built on device-owner authentication.
# None of them were analysed on macOS, where the container, the keychain and the
# window server behave differently. A build that runs there ships controls nobody
# reasoned about for it.
#
#   Usage: Scripts/verify-iphone-only.sh
#          Scripts/verify-iphone-only.sh --self-test
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKSPACE="$ROOT/Cipher.xcworkspace"
SCHEME="Cipher"
CONFIGURATION="Release"

fail() { echo "FAILED: $*" >&2; exit 1; }

# The settings that together mean "iPhone, and nowhere else", with the value each
# must resolve to. Every one is asserted; a missing key is a failure, never a pass.
REQUIRED_SETTINGS=(
  "TARGETED_DEVICE_FAMILY=1"
  "SUPPORTS_MACCATALYST=NO"
  "SUPPORTS_MAC_DESIGNED_FOR_IPHONE_IPAD=NO"
  "SUPPORTS_XR_DESIGNED_FOR_IPHONE_IPAD=NO"
)

# setting_value pulls one resolved value out of captured `-showBuildSettings` output.
#
# Prints nothing and returns 1 when the key is absent. That distinction is the whole
# point: an absent key and a correct value look identical to a grep that only checks
# for the wrong one, and "the setting is not mentioned" is exactly what a renamed or
# removed build setting looks like.
setting_value() {
  local settings="$1" key="$2" line
  line="$(printf '%s\n' "$settings" | grep -E "^[[:space:]]*${key} = " | head -1)" || true
  [ -n "$line" ] || return 1
  printf '%s' "${line#*= }"
}

# check_settings asserts every required setting in captured output.
check_settings() {
  local settings="$1" failures=0 entry key want got
  for entry in "${REQUIRED_SETTINGS[@]}"; do
    key="${entry%%=*}"
    want="${entry#*=}"
    if ! got="$(setting_value "$settings" "$key")"; then
      echo "  FAIL  $key is not in the resolved settings at all" >&2
      failures=$((failures + 1))
      continue
    fi
    if [ "$got" != "$want" ]; then
      echo "  FAIL  $key resolved to '$got', must be '$want'" >&2
      failures=$((failures + 1))
    else
      echo "  ok    $key = $got"
    fi
  done
  return "$failures"
}

# --- self-test ----------------------------------------------------------------
#
# Offline and deterministic: the checks are string comparisons over captured text,
# so the text is supplied directly. Without this the gate is a grep whose all-clear
# looks the same as a grep that read nothing (AUDIT R2).
if [ "${1:-}" = "--self-test" ]; then
  cases=0
  good="    TARGETED_DEVICE_FAMILY = 1
    SUPPORTS_MACCATALYST = NO
    SUPPORTS_MAC_DESIGNED_FOR_IPHONE_IPAD = NO
    SUPPORTS_XR_DESIGNED_FOR_IPHONE_IPAD = NO"

  expect() {
    local want="$1" desc="$2" settings="$3" rc=0
    cases=$((cases + 1))
    check_settings "$settings" >/dev/null 2>&1 || rc=$?
    if [ "$want" = pass ] && [ "$rc" -ne 0 ]; then
      fail "self-test: $desc was refused ($rc failing settings)"
    fi
    if [ "$want" = fail ] && [ "$rc" -eq 0 ]; then
      fail "self-test: $desc was accepted"
    fi
  }

  expect pass "a correct Release configuration" "$good"

  # The finding itself, in both halves. These are the values the project actually
  # resolved before this gate existed.
  expect fail "Designed for iPhone on Mac enabled" \
    "${good/SUPPORTS_MAC_DESIGNED_FOR_IPHONE_IPAD = NO/SUPPORTS_MAC_DESIGNED_FOR_IPHONE_IPAD = YES}"
  expect fail "XR compatibility enabled" \
    "${good/SUPPORTS_XR_DESIGNED_FOR_IPHONE_IPAD = NO/SUPPORTS_XR_DESIGNED_FOR_IPHONE_IPAD = YES}"
  expect fail "Mac Catalyst enabled" \
    "${good/SUPPORTS_MACCATALYST = NO/SUPPORTS_MACCATALYST = YES}"
  expect fail "iPad included in the device family" \
    "${good/TARGETED_DEVICE_FAMILY = 1/TARGETED_DEVICE_FAMILY = 1,2}"

  # A key that is simply absent must fail. This is the case a "grep for YES" check
  # gets wrong, and the one a renamed build setting produces.
  for key in TARGETED_DEVICE_FAMILY SUPPORTS_MACCATALYST \
             SUPPORTS_MAC_DESIGNED_FOR_IPHONE_IPAD SUPPORTS_XR_DESIGNED_FOR_IPHONE_IPAD; do
    expect fail "$key missing entirely" "$(printf '%s\n' "$good" | grep -v "$key")"
  done

  # And empty output — a failed xcodebuild invocation — is not an all-clear.
  expect fail "empty settings output" ""

  echo "  ok    self-test: $cases cases — every iPhone-only setting is asserted, and a missing one fails"
  exit 0
fi

[ -d "$WORKSPACE" ] || fail "cannot find $WORKSPACE"

# Buffered into a variable, never piped into an early-exiting consumer: xcodebuild
# raises NSFileHandleOperationException on a closed pipe and a *succeeding* command
# becomes a failed pipeline under `pipefail` (AUDIT R1, which has bitten this repo
# twice).
settings="$(xcodebuild -workspace "$WORKSPACE" -scheme "$SCHEME" \
              -configuration "$CONFIGURATION" \
              -destination 'generic/platform=iOS' \
              -showBuildSettings 2>/dev/null)" \
  || fail "could not read $CONFIGURATION build settings for $SCHEME"

[ -n "$settings" ] || fail "xcodebuild returned no build settings — the probe did not work"

echo "  $CONFIGURATION settings for scheme $SCHEME:"
if ! check_settings "$settings"; then
  echo "" >&2
  echo "  A build that resolves these values runs somewhere this project's storage and" >&2
  echo "  lock decisions were never analysed for. See docs/AUDIT.md 6.13." >&2
  fail "the $CONFIGURATION build is not iPhone-only"
fi

echo "  ok    the $CONFIGURATION build is iPhone-only"
