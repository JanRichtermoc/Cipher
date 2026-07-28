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

BUILT="$(find "$HOME/Library/Developer/Xcode/DerivedData/Cipher-"*/Build/Products/Debug-iphonesimulator \
  -maxdepth 1 -type d -name 'Debug-iphonesimulator' 2>/dev/null | head -1)"

if [ -z "$BUILT" ] || [ ! -d "$BUILT/CipherCrypto.framework" ]; then
  echo "  …    building CipherCrypto first"
  xcodebuild build -workspace Cipher.xcworkspace -scheme CipherCrypto \
    -destination "platform=iOS Simulator,name=$SIMULATOR,OS=latest" \
    -configuration Debug >/dev/null 2>&1 || {
    echo "  !     could not build CipherCrypto" >&2
    exit 1
  }
  BUILT="$(find "$HOME/Library/Developer/Xcode/DerivedData/Cipher-"*/Build/Products/Debug-iphonesimulator \
    -maxdepth 1 -type d -name 'Debug-iphonesimulator' 2>/dev/null | head -1)"
fi

# The deployment target has to match what the module was built against, or the digester
# refuses to load it. Read it from the project rather than pinned here — a target bump would
# otherwise turn this gate off silently, and a gate that stops running looks exactly like a
# gate that passes.
TARGET_VERSION="$(xcodebuild -workspace Cipher.xcworkspace -scheme CipherCrypto \
  -destination "platform=iOS Simulator,name=$SIMULATOR,OS=latest" -showBuildSettings 2>/dev/null |
  awk -F' = ' '/ IPHONEOS_DEPLOYMENT_TARGET /{print $2; exit}')"
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
