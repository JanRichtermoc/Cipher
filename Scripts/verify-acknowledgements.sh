#!/bin/bash
# Acknowledgements gate (P8.S07, AUDIT 6.2).
#
# libsignal is AGPL-3.0. `NOTICE.md` obligation 3 is to surface its
# acknowledgements in the app's About screen, and an obligation the app fails to
# meet is a licence violation rather than a missing feature.
#
# CocoaPods generates the licence text into
# `Pods/Target Support Files/Pods-Cipher/Pods-Cipher-acknowledgements.plist`,
# which is not in the app bundle: nothing under `Pods/` is. The shipped copy is
# `Cipher/Acknowledgements.plist`, which the app target picks up through its
# synchronized group.
#
# A copy drifts. That is what this gate exists to prevent — it is the same
# arrangement `PINS.env` and the app-target manifest use: derive it, commit it,
# and fail when the committed bytes stop matching what generated them. A pod
# update that changes a licence therefore fails here rather than shipping the
# previous one.
#
# It also refuses a file that matches and says nothing, because two empty plists
# match perfectly.
#
# To accept a legitimate change:  Scripts/verify-acknowledgements.sh --update
#
# Copyright (C) 2026 Jan Richter
# SPDX-License-Identifier: AGPL-3.0-only

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GENERATED="$ROOT/Pods/Target Support Files/Pods-Cipher/Pods-Cipher-acknowledgements.plist"
SHIPPED="$ROOT/Cipher/Acknowledgements.plist"

fail() { echo "FAILED: $*" >&2; exit 1; }

# The dependency whose licence obliges this at all. Named rather than inferred:
# a gate that only checked "some library is listed" would pass a plist that had
# lost the one entry the obligation is about.
REQUIRED_LIBRARY="LibSignalClient"
REQUIRED_LICENCE_MARKER="GNU AFFERO GENERAL PUBLIC LICENSE"

# Reads the plist and reports whether the required entry is present and carries a
# licence body. Pure over a path, so the self-test can drive it over fixtures.
#
# Python rather than PlistBuddy: PlistBuddy exits 0 and prints an error to stdout
# for a missing key, which is the "trusted an exit code that carries no meaning"
# shape AUDIT R2 collects.
entry_is_sound() {
    python3 - "$1" "$REQUIRED_LIBRARY" "$REQUIRED_LICENCE_MARKER" <<'PY'
import plistlib, sys
path, library, marker = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(path, "rb") as handle:
        entries = plistlib.load(handle).get("PreferenceSpecifiers") or []
except Exception:
    sys.exit(2)
for entry in entries:
    if entry.get("Title") == library:
        text = entry.get("FooterText") or ""
        # A title with no licence under it is the failure that looks like success.
        sys.exit(0 if marker in text and len(text) > 1000 else 3)
sys.exit(4)
PY
}

if [ "${1:-}" = "--update" ]; then
    [ -f "$GENERATED" ] || fail "no generated acknowledgements at $GENERATED — run 'bundle exec pod install' first"
    cp "$GENERATED" "$SHIPPED"
    echo "  ok    updated $SHIPPED from the pod's generated file"
    exit 0
fi

# ---------------------------------------------------------------------------
# Self-test. A gate that has never been made to fail is not a gate (AUDIT R2),
# and this one's failure mode is silence: a missing entry and a present one both
# look like a plist.
# ---------------------------------------------------------------------------
selftest() {
    local probe cases=0 rc
    probe="$(mktemp -d)"
    trap 'rm -rf "$probe"' RETURN

    python3 - "$probe" <<'PY'
import plistlib, os, sys
probe = sys.argv[1]

def write(name, specifiers):
    with open(os.path.join(probe, name), "wb") as handle:
        plistlib.dump({"PreferenceSpecifiers": specifiers}, handle)

# The positive control is *synthetic*, not the committed file. Deriving it from the
# data under test is the R5 defect: with the shipped file as the control, a genuinely
# broken shipped file makes the self-test report that the checker is broken — blaming
# the instrument for what it correctly detected, and burying the real message.
write("good.plist", [
    {"Title": "Acknowledgements", "FooterText": "This application makes use of…"},
    {"Title": "LibSignalClient",
     "FooterText": "GNU AFFERO GENERAL PUBLIC LICENSE\n" + ("licence body. " * 200)},
])

# The library is gone entirely.
write("missing.plist", [{"Title": "Acknowledgements", "FooterText": "x"}])
# Present, but with no licence under it — the shape that looks correct.
write("empty.plist", [{"Title": "LibSignalClient", "FooterText": ""}])
# Present with a body that is not the licence.
write("wrong.plist", [{"Title": "LibSignalClient", "FooterText": "MIT-ish, trust me" * 100}])
# Present with the right marker but truncated to a fragment.
write("truncated.plist", [{"Title": "LibSignalClient",
                           "FooterText": "GNU AFFERO GENERAL PUBLIC LICENSE"}])
PY

    entry_is_sound "$probe/good.plist" ||
        fail "the acknowledgements checker rejects a well-formed plist; its negative cases prove nothing"
    cases=$((cases + 1))

    for case in missing empty wrong truncated; do
        rc=0
        entry_is_sound "$probe/$case.plist" || rc=$?
        [ "$rc" -ne 0 ] || fail "the checker accepted the '$case' fixture"
        cases=$((cases + 1))
    done

    # Not a plist at all.
    printf 'not a plist' >"$probe/garbage.plist"
    rc=0
    entry_is_sound "$probe/garbage.plist" || rc=$?
    [ "$rc" -ne 0 ] || fail "the checker accepted a file that is not a plist"
    cases=$((cases + 1))

    echo "  ok    self-test: $cases cases — the acknowledgements checker still fires, and only when it should"
}

selftest

# ---------------------------------------------------------------------------
# The gate itself
# ---------------------------------------------------------------------------
[ -f "$SHIPPED" ] ||
    fail "Cipher/Acknowledgements.plist is missing — the About screen has nothing to render (NOTICE.md obligation 3, AUDIT 6.2)"

entry_is_sound "$SHIPPED" ||
    fail "Cipher/Acknowledgements.plist does not carry $REQUIRED_LIBRARY's licence text. libsignal is AGPL-3.0 and NOTICE.md obligation 3 requires it to be surfaced in the app."

if [ -f "$GENERATED" ]; then
    if ! cmp -s "$GENERATED" "$SHIPPED"; then
        echo "  the shipped acknowledgements differ from what CocoaPods generated:" >&2
        diff <(python3 -c "
import plistlib,sys
print('\n'.join(sorted(e.get('Title','') for e in plistlib.load(open(sys.argv[1],'rb'))['PreferenceSpecifiers'])))
" "$GENERATED") <(python3 -c "
import plistlib,sys
print('\n'.join(sorted(e.get('Title','') for e in plistlib.load(open(sys.argv[1],'rb'))['PreferenceSpecifiers'])))
" "$SHIPPED") >&2 || true
        fail "run 'Scripts/verify-acknowledgements.sh --update' and review the diff — a dependency's licence may have changed"
    fi
    echo "  ok    the shipped acknowledgements are byte-identical to the pod's generated file"
else
    # Not a pass by inspection: there was nothing to compare against. Said out
    # loud rather than printed as "ok", the same way gate 1 reports a simulator
    # it could not find.
    echo "  —     Pods/ is absent, so drift against the generated file was not checked"
fi

echo "  ok    $REQUIRED_LIBRARY's licence ships in the app bundle"
