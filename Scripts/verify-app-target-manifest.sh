#!/bin/bash
#
# App-target file manifest gate.
#
# The app target uses fileSystemSynchronizedGroups, so ANY file dropped under
# Cipher/ silently joins the shipping bundle with no review signal. That is
# convenient for UI work and unacceptable without a check for a security-critical
# app: a debug helper, a test fixture, or a scratch file could ship unnoticed.
#
# This gate snapshots the set of files that compile into the app and fails on any
# unreviewed change. Security-critical code does not live here at all — it lives in
# CipherCrypto/, which uses explicit target membership.
#
# Tracked: .swift (code), plus .xcprivacy and .entitlements — the two non-code files
# whose contents are security or privacy claims about the shipping app, and which
# would otherwise change without anyone having to say so. Other resources are not
# tracked; that residual is recorded in docs/AUDIT.md (6.5).
#
# To accept a legitimate change:  Scripts/verify-app-target-manifest.sh --update
#
# Copyright (C) 2026 Jan Richter
# SPDX-License-Identifier: AGPL-3.0-only

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$ROOT/Scripts/app-target-manifest.txt"

current() {
  cd "$ROOT"
  find Cipher -type f \
    \( -name '*.swift' -o -name '*.xcprivacy' -o -name '*.entitlements' \) \
    | LC_ALL=C sort
}

if [ "${1:-}" = "--update" ]; then
  current > "$MANIFEST"
  echo "Updated $MANIFEST ($(wc -l < "$MANIFEST" | tr -d ' ') files)."
  echo "Review the diff before committing — every line here compiles into the shipping app."
  exit 0
fi

if [ ! -f "$MANIFEST" ]; then
  echo "missing $MANIFEST — run: Scripts/verify-app-target-manifest.sh --update" >&2
  exit 1
fi

if DIFF="$(diff -u "$MANIFEST" <(current) 2>&1)"; then
  echo "App target manifest verified ($(wc -l < "$MANIFEST" | tr -d ' ') files)."
  exit 0
fi

cat >&2 <<EOF
APP TARGET MANIFEST CHANGED

Files compiled into the shipping app have changed. Because this target uses
synchronized folders, this happened without an explicit project-file edit.

$DIFF

If this is intended, run:
    Scripts/verify-app-target-manifest.sh --update
and commit the manifest alongside the change so it appears in review.
EOF
exit 1
