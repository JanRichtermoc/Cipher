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
# Copyright (C) 2026 Jan Richter
# SPDX-License-Identifier: AGPL-3.0-only

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PINS="$ROOT/Vendor/libsignal/PINS.env"

fail() { printf '  FAIL  %s\n' "$*" >&2; FAILED=1; }
pass() { printf '  ok    %s\n' "$*"; }
FAILED=0

[ -f "$PINS" ] || { echo "missing $PINS" >&2; exit 1; }
# shellcheck disable=SC1090
set -a; . "$PINS"; set +a

echo "Verifying libsignal supply chain against $PINS"

# 1. The tag must still resolve to the commit we reviewed. Tags are mutable; this
#    is what catches an upstream tag being moved.
echo "[1/5] tag -> commit"
RESOLVED="$(git ls-remote "$LIBSIGNAL_GIT_URL" "refs/tags/${LIBSIGNAL_TAG}^{}" | awk '{print $1}')"
if [ -z "$RESOLVED" ]; then
  fail "could not resolve ${LIBSIGNAL_TAG} at ${LIBSIGNAL_GIT_URL} (network?)"
elif [ "$RESOLVED" != "$LIBSIGNAL_COMMIT" ]; then
  fail "tag ${LIBSIGNAL_TAG} now resolves to ${RESOLVED}, expected ${LIBSIGNAL_COMMIT} — THE TAG MOVED"
else
  pass "${LIBSIGNAL_TAG} -> ${LIBSIGNAL_COMMIT}"
fi

# 2. The published checksum for that release must be unchanged.
echo "[2/5] published checksum"
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

# 3. The cached artifact the build actually links, if present, must hash correctly.
#    We verify independently rather than trusting the pod's own check, which uses a
#    bare Python `assert` and is stripped under `python -O`.
echo "[3/5] cached artifact"
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

# 4. Podfile.lock must agree with the pins.
echo "[4/5] Podfile.lock"
LOCK="$ROOT/Podfile.lock"
if ! grep -q ":tag: ${LIBSIGNAL_TAG}" "$LOCK"; then
  fail "Podfile.lock does not pin ${LIBSIGNAL_TAG}"
elif ! grep -q "LibSignalClient (${LIBSIGNAL_VERSION})" "$LOCK"; then
  fail "Podfile.lock does not record LibSignalClient ${LIBSIGNAL_VERSION}"
else
  pass "Podfile.lock agrees with PINS.env"
fi

# 5. The retired snapshot must stay gone.
echo "[5/5] retired artifacts"
if [ -e "$ROOT/libsignal-main.zip" ]; then
  fail "libsignal-main.zip is back — an unsigned, unpinned branch snapshot must not be used"
else
  pass "no unpinned libsignal snapshot in the tree"
fi

echo
if [ "$FAILED" -ne 0 ]; then
  echo "SUPPLY CHAIN VERIFICATION FAILED" >&2
  exit 1
fi
echo "Supply chain verified."
