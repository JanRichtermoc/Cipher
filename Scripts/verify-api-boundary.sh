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

# CANNOT_RUN separates "the boundary is violated" from "this check never ran" (AUDIT 6.25).
#
# Every exit below that means the second one uses it, and verify-all.sh prints a different
# message for it. The distinction is not cosmetic: the caller's message asserts a finding
# about the *code*, so an aborted gate accusing CipherCrypto of exposing a libsignal type
# sends a reviewer looking for a leak that does not exist — which is the failure this
# script's own header already forbids, arriving through the one path that skipped it.
readonly CANNOT_RUN=78

cannot_run() {
  printf '  !     %s\n' "$1" >&2
  printf '        This gate could not run. That is a failure, not a pass, and it is NOT a\n' >&2
  printf '        finding about the API boundary (AUDIT 6.25).\n' >&2
  exit "$CANNOT_RUN"
}

# show_tail prints the last lines of a captured stderr file, if it has any.
#
# The tool's own message is the only thing that says *why*, and this gate used to discard
# it: `2>/dev/null` on a command substitution, which under `set -e` also aborted the script
# before the guard written to catch that very case could run. Two duplicate simulators
# named alike is enough to trigger it, and the operator saw exit 64 and no output at all.
show_tail() {
  [ -s "$1" ] || return 0
  printf '        %s\n' "--- last lines of the tool's own output ---" >&2
  tail -15 "$1" >&2
}

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

# --- Self-test: the gate must be able to say "I could not run" ---------------
#
# Reintroducing the defect in the *real* script rather than a fixture (AUDIT R5), by naming a
# simulator that does not exist — which is the same failure a duplicated device name produced
# on the development machine, and which reaches the identical code path.
#
# Two assertions, because either alone passes for the wrong reason: the exit status must be
# CANNOT_RUN so verify-all can tell this apart from a real leak, **and** stderr must be
# non-empty, since the whole finding is that this exited 64 saying nothing at all.
#
# Guarded against recursion by CIPHER_API_BOUNDARY_SELFTEST, and run before the real check so
# a gate that has stopped being able to fail is caught even when the boundary itself is fine.
if [ -z "${CIPHER_API_BOUNDARY_SELFTEST:-}" ]; then
  probe_rc=0
  probe_out="$(CIPHER_API_BOUNDARY_SELFTEST=1 \
    CIPHER_TEST_SIMULATOR="Cipher No Such Simulator" "$0" 2>&1)" || probe_rc=$?

  if [ "$probe_rc" -ne "$CANNOT_RUN" ]; then
    echo "  !     self-test: an unresolvable simulator exited $probe_rc, want $CANNOT_RUN" >&2
    echo "        The gate can no longer distinguish 'could not run' from a boundary" >&2
    echo "        violation, which is AUDIT 6.25 returning." >&2
    exit 1
  fi
  case "$probe_out" in
  *"could not run"*) ;;
  *)
    echo "  !     self-test: the gate exited $CANNOT_RUN without saying why." >&2
    echo "        Silence is the defect 6.25 records; the message is the fix." >&2
    exit 1
    ;;
  esac
  echo "  ok    self-test: a gate that cannot run says so, and is distinguishable from a leak"
fi

BUILT="$(find_built_module || true)"

if [ -z "$BUILT" ]; then
  echo "  …    no built module found; building CipherCrypto (first run on a clean machine)"
  if ! xcodebuild build -workspace Cipher.xcworkspace -scheme CipherCrypto \
    -destination "platform=iOS Simulator,name=$SIMULATOR,OS=latest" \
    -configuration Debug ${DERIVED_DATA_ARG[@]+"${DERIVED_DATA_ARG[@]}"} \
    >"$BUILD_LOG" 2>&1; then
    tail -25 "$BUILD_LOG" >&2
    cannot_run "could not build CipherCrypto (full log: $BUILD_LOG)"
  fi

  BUILT="$(find_built_module || true)"
  [ -n "$BUILT" ] ||
    cannot_run "CipherCrypto built, but no CipherCrypto.framework under $DERIVED_DATA"
fi

# The deployment target has to match what the module was built against, or the digester
# refuses to load it. Read it from the project rather than pinned here — a target bump would
# otherwise turn this gate off silently, and a gate that stops running looks exactly like a
# gate that passes.
# Buffered, not piped. `awk … {exit}` stops reading and xcodebuild aborts on the closed pipe
# rather than tolerating it (NSFileHandleOperationException, not a quiet SIGPIPE death), so
# under `pipefail` a successful read becomes a failed pipeline. The `|| true` this replaced
# hid that — and would equally have hidden a real failure to read the settings at all.
#
# **Assigned inside `if !`, not bare** (AUDIT 6.25, and R5's "`set -e` turns a bare call into
# a silent exit"). `SETTINGS="$(xcodebuild …)"` on its own line aborts the whole script the
# moment xcodebuild exits non-zero, so the TARGET_VERSION guard below — written for exactly
# this — was unreachable for the likeliest failure. A command that fails inside an `if`
# condition does not trip `set -e`, so the handler runs. Its stderr is captured rather than
# discarded, because the tool's own message is the only thing that says which of the many
# ways this can fail actually happened: two simulators sharing a name makes `-destination
# name=…` ambiguous and xcodebuild exits 64 saying so.
TOOL_ERR="$(mktemp)"
trap 'rm -f "$TOOL_ERR"' EXIT

if ! SETTINGS="$(xcodebuild -workspace Cipher.xcworkspace -scheme CipherCrypto \
  -destination "platform=iOS Simulator,name=$SIMULATOR,OS=latest" \
  -showBuildSettings 2>"$TOOL_ERR")"; then
  show_tail "$TOOL_ERR"
  cannot_run "xcodebuild -showBuildSettings failed for simulator \"$SIMULATOR\""
fi

TARGET_VERSION="$(printf '%s\n' "$SETTINGS" |
  awk -F' = ' '/ IPHONEOS_DEPLOYMENT_TARGET /{print $2; exit}')"
[ -n "$TARGET_VERSION" ] ||
  cannot_run "could not read IPHONEOS_DEPLOYMENT_TARGET from the build settings"

if ! SDK_PATH="$(xcrun --sdk iphonesimulator --show-sdk-path 2>"$TOOL_ERR")" ||
  [ -z "$SDK_PATH" ]; then
  show_tail "$TOOL_ERR"
  cannot_run "could not resolve the iphonesimulator SDK path"
fi

# Same treatment: a digester that fails must say so rather than abort into silence, and the
# emptiness check below only ever caught "ran, produced nothing".
if ! xcrun swift-api-digester -dump-sdk -module CipherCrypto \
  -target "arm64-apple-ios${TARGET_VERSION}-simulator" \
  -I "$BUILT" -F "$BUILT" \
  -sdk "$SDK_PATH" \
  -o "$OUT" 2>"$TOOL_ERR"; then
  show_tail "$TOOL_ERR"
  cannot_run "swift-api-digester failed to dump CipherCrypto's API surface"
fi

[ -s "$OUT" ] ||
  cannot_run "the API dump is empty — the check did not run, which is not the same as passing"

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
    # 78, matching the shell's CANNOT_RUN: a dump with no declarations is a check that did
    # not run, and it must not reach the caller as a boundary finding (AUDIT 6.25).
    print("  !     no declarations found — the dump parsed but is empty; check the digester "
          "invocation", file=sys.stderr)
    print("        This gate could not run. That is a failure, not a pass, and it is NOT a\n"
          "        finding about the API boundary (AUDIT 6.25).", file=sys.stderr)
    sys.exit(78)

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
