#!/bin/bash
#
# Module-boundary gate: no LibSignalClient type may appear in CipherCrypto's public API.
#
# ## Why this matters more than tidiness
#
# Most libsignal types own a Rust pointer freed from `deinit` — `ProtocolAddress` and
# `PreKeyBundle` are `NativeHandleOwner`s. Every FFI call in this module is required to run
# on the crypto queue, and a value held by the UI can be released on any thread at all. A
# handle that escapes turns the module's central concurrency argument from "enforced by the
# type system plus `assertIsolated`" into "true as long as nobody holds one too long".
#
# The second reason is substitutability: libsignal is deliberately `0.x` and promises nothing
# between releases (AUDIT 1.4). If its types appear here, every bump is an app-wide refactor
# and the contract tests stop being the one place a breaking change surfaces.
#
# ## Why this reads the built module rather than grepping sources
#
# A grep over `public func` would have missed the leak this found on its first run:
# `Envelope.payloadType(for:)` took a `CiphertextMessage.MessageType`, and no reviewer had
# noticed across two phases. `swift-api-digester` dumps what the compiler actually exports,
# including inherited and synthesised members, so the answer is the module's real surface and
# not an approximation of it.
#
# Usage: Scripts/verify-api-boundary.sh          (builds if needed, then checks)
#
# Copyright (C) 2026 Jan Richter
# SPDX-License-Identifier: AGPL-3.0-only

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SIMULATOR="${CIPHER_TEST_SIMULATOR:-iPhone 17 Pro}"
OUT="${TMPDIR:-/tmp}/cipher-api-surface.json"

BUILD_LOG="${TMPDIR:-/tmp}/cipher-api-boundary-build.log"

# Overridable so the clean-machine path — the one CI takes and a developer machine never
# does — can be exercised deliberately. It was not, and the first CI run paid for it: the
# unmatched `Cipher-*` glob was passed through to `find` literally, `find` failed, and under
# `set -euo pipefail` the script aborted at that line with no output at all. verify-all.sh
# then printed its own failure message, which read like a boundary violation. A check that
# cannot run must say so; it must never look like the thing it was checking for.
DERIVED_DATA="${CIPHER_DERIVED_DATA:-$HOME/Library/Developer/Xcode/DerivedData}"

# When the override is set, xcodebuild is pointed at the same place — otherwise the script
# would search one directory and build into another, and the "clean machine" rehearsal would
# prove nothing about the path CI actually takes. Unset, this is empty and Xcode uses its own
# location, which is what CI and a developer machine both want.
DERIVED_DATA_ARG=()
[ -n "${CIPHER_DERIVED_DATA:-}" ] && DERIVED_DATA_ARG=(-derivedDataPath "$DERIVED_DATA")

# Two layouts, because they are genuinely different: Xcode's own root nests products under
# `Cipher-<hash>/`, while `-derivedDataPath` puts `Build/` straight underneath.
#
# A `for` over a non-matching glob iterates once with the literal and the `-d` test then
# fails, so this cannot abort. It insists on the framework actually being present rather than
# on a directory merely existing.
find_built_module() {
  local candidate
  for candidate in \
    "$DERIVED_DATA"/Cipher-*/Build/Products/Debug-iphonesimulator \
    "$DERIVED_DATA"/Build/Products/Debug-iphonesimulator; do
    if [ -d "$candidate/CipherCrypto.framework" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

BUILT="$(find_built_module || true)"

if [ -z "$BUILT" ]; then
  echo "  …    no built module found; building CipherCrypto (first run on a clean machine)"
  if ! xcodebuild build -workspace Cipher.xcworkspace -scheme CipherCrypto \
    -destination "platform=iOS Simulator,name=$SIMULATOR,OS=latest" \
    -configuration Debug ${DERIVED_DATA_ARG[@]+"${DERIVED_DATA_ARG[@]}"} \
    >"$BUILD_LOG" 2>&1; then
    echo "  !     could not build CipherCrypto; last lines of $BUILD_LOG:" >&2
    tail -25 "$BUILD_LOG" >&2
    exit 1
  fi

  BUILT="$(find_built_module || true)"
  [ -n "$BUILT" ] || {
    echo "  !     CipherCrypto built, but no CipherCrypto.framework under $DERIVED_DATA" >&2
    echo "        This gate cannot run. That is a failure, not a pass." >&2
    exit 1
  }
fi

# The deployment target has to match what the module was built against, or the digester
# refuses to load it. Read it from the project rather than pinned here — a target bump would
# otherwise turn this gate off silently, and a gate that stops running looks exactly like a
# gate that passes.
TARGET_VERSION="$(xcodebuild -workspace Cipher.xcworkspace -scheme CipherCrypto \
  -destination "platform=iOS Simulator,name=$SIMULATOR,OS=latest" -showBuildSettings 2>/dev/null |
  awk -F' = ' '/ IPHONEOS_DEPLOYMENT_TARGET /{print $2; exit}' || true)"
[ -n "$TARGET_VERSION" ] || {
  echo "  !     could not read IPHONEOS_DEPLOYMENT_TARGET" >&2
  exit 1
}

xcrun swift-api-digester -dump-sdk -module CipherCrypto \
  -target "arm64-apple-ios${TARGET_VERSION}-simulator" \
  -I "$BUILT" -F "$BUILT" \
  -sdk "$(xcrun --sdk iphonesimulator --show-sdk-path)" \
  -o "$OUT" 2>/dev/null

[ -s "$OUT" ] || {
  echo "  !     the API dump is empty — the check did not run, which is not the same as passing" >&2
  exit 1
}

python3 - "$OUT" <<'PY'
import json, re, sys

root = json.load(open(sys.argv[1]))
root = root.get("ABIRoot", root)


def walk(node):
    if isinstance(node, dict):
        if node.get("printedName"):
            yield node
        for child in node.get("children") or []:
            yield from walk(child)


decls = list(walk(root))
if not decls:
    sys.exit("  !     no declarations found — the dump parsed but is empty; check the digester invocation")

# Anything qualified with the module name is unambiguous. Bare names are not searched for:
# `PublicKey` and `Direction` are ordinary words and matching them raw produces noise that
# trains people to ignore this gate.
leaks = sorted({d["printedName"] for d in decls if re.search(r"\bLibSignalClient\.", d["printedName"])})

if leaks:
    print(f"  !     {len(leaks)} LibSignalClient type(s) in CipherCrypto's public API:")
    for leak in leaks:
        print(f"        {leak}")
    print("        Make the declaration internal, or add a boundary value type for it.")
    sys.exit(1)

print(f"  ok    {len(decls)} public declarations, none exposing a LibSignalClient type")
PY
