#!/usr/bin/env python3
#
# UI-honesty and localization-drift gate.
#
# Cipher must not present a control implying protection it does not provide. That is a
# property of *copy*, so nothing in the type system can hold it — this can.
#
# It replaces an earlier shell grep that anchored each claim to the opening quote of a
# string. That worked for `Text("connection is secure")` and missed the same claim sitting
# mid-sentence inside a translation, which is exactly where the claims survived: removing a
# string from the English UI leaves its translations behind, and the Czech bundle shipped a
# "connection is secure" line and a Secure Enclave claim after the English strings were gone.
#
# Four checks, in increasing order of subtlety:
#
#   A. ORPHAN       a catalog key no source renders. Harmless today, and the thing a
#                   re-added key silently inherits tomorrow.
#   B. DEBUG-ONLY   a string used only behind `#if DEBUG` must not carry a translation.
#      TRANSLATION  Xcode drops `extractionState: stale` keys from en.lproj but emits every
#                   translated stringUnit regardless, so cs.lproj/Localizable.strings was
#                   shipping "Skip to App", "Unlock & Show Main", "Demo Controls", "UI
#                   Catalog" and "Reset Onboarding" into the Release bundle. The code was
#                   fenced; the copy naming it was not (AUDIT 5.11).
#   C. DENY         a retired claim, in any language, anywhere in the string.
#   D. GUARD        a term that is honest only in a specific sentence. "Face ID" cannot be
#                   banned outright — the disclaimers that replaced the false promises
#                   legitimately say the app does *not* ask for it — and no keyword list
#                   tells a denial from a promise. So every occurrence is registered by
#                   exact text. A translation is different exact text and must be
#                   registered separately: that is the point, because it forces someone to
#                   read the translation and confirm the negation survived it.
#
# Add to DENY whenever a claim is retired. Remove from it only in the change that makes the
# claim true.
#
# Usage: Scripts/verify-localization.py     (exit 0 clean, 1 on any finding)
#
# Copyright (C) 2026 Jan Richter
# SPDX-License-Identifier: AGPL-3.0-only

import json
import os
import re
import sys

CATALOG = "Cipher/Localizable.xcstrings"
SOURCE_ROOT = "Cipher"
SKIP_DIRS = {"Assets.xcassets", "Preview Content"}

# Phrases that must not reach a user in any language. Czech forms sit next to their English
# originals: a claim is not retired until every rendering of it is gone.
DENY = [
    ("Secure Enclave", "libsignal identity keys are exportable software keys (P10.S05)"),
    ("bezpečné enklávě", "Czech rendering of the Secure Enclave claim"),
    ("connection is secure", "nothing verifies the connection until P5.S12"),
    ("spojení je bezpečn", "Czech rendering of the connection claim"),
    ("Mark as Verified", "no fingerprint comparison exists behind it until P5.S12"),
    ("Označit jako ověřen", "Czech rendering of the verification claim"),
]

# Terms honest only in a sentence someone has read. Every occurrence — each translation
# included — must appear verbatim in ACKNOWLEDGED.
GUARD = [
    ("Face ID", "no LocalAuthentication anywhere until P3.S02"),
    ("Touch ID", "no LocalAuthentication anywhere until P3.S02"),
    ("passcode", "the app does not ask for the device passcode until P3.S02"),
]

# Reviewed and correct as written. Each of these *denies* the capability it names.
ACKNOWLEDGED = {
    "This is a privacy screen, not a security control: unlocking does not yet ask for "
    "Face ID or your passcode, and the app does not re-lock when you switch away from it.",
    "This screen does not ask for Face ID or your passcode yet. It hides your chats from "
    "view; it does not keep anyone out.",
}

# A catalog key holds format specifiers where the source has interpolation; the two are
# compared with both reduced to this placeholder.
WILD = "\x00"
SPECIFIER = re.compile(r"%(?:\d+\$)?(?:@|lld|llu|ld|lu|lf|[dufs])")
DIRECTIVE = re.compile(r"#(if|elseif|else|endif)\b([^\n]*)")


def scan_literals(text, path):
    """Yield (literal, debug_only, line) for every single-line string literal in a Swift file.

    Interpolations collapse to WILD. Comments are skipped: the explanation of why a control
    was removed sits next to the removal and necessarily quotes the old wording. `\"\"\"`
    blocks are skipped wholesale — no localized string is written as one.

    `#if DEBUG` regions are tracked so check B can tell a shipping string from one the
    compiler drops. Any condition mentioning DEBUG that this does not understand exactly is
    a hard error rather than a guess: misreading one as shipping would silently disable
    check B for the rest of that file.
    """
    out = []
    stack = []  # one bool per open #if: True if the *current* branch is DEBUG-only
    debug_depth = 0

    i, n, line, at_line_start = 0, len(text), 1, True
    while i < n:
        c = text[i]

        if at_line_start and c == "#" and (m := DIRECTIVE.match(text, i)):
            kind, cond = m.group(1), m.group(2).strip()
            if kind == "if":
                if "DEBUG" in cond and cond != "DEBUG":
                    raise SystemExit(
                        f"{path}:{line}: unhandled '#if {cond}'. Teach scan_literals about "
                        f"it — guessing would silently disable the DEBUG-only check."
                    )
                stack.append(cond == "DEBUG")
            elif kind in ("else", "elseif") and stack:
                # The complement of `#if DEBUG` ships; the complement of anything else was
                # already treated as shipping, so both branches settle to False.
                debug_depth -= stack[-1]
                stack[-1] = False
            elif kind == "endif":
                if not stack:
                    raise SystemExit(f"{path}:{line}: #endif without #if")
                debug_depth -= stack.pop()
            if kind == "if":
                debug_depth += stack[-1]
            i, at_line_start = m.end(), False
            continue

        if c == "/" and text[i : i + 2] == "//":
            j = text.find("\n", i)
            i = n if j == -1 else j
            continue

        if c == "/" and text[i : i + 2] == "/*":
            j = text.find("*/", i + 2)
            end = n if j == -1 else j + 2
            line += text.count("\n", i, end)
            i, at_line_start = end, False
            continue

        if c == '"':
            if text[i : i + 3] == '"""':
                j = text.find('"""', i + 3)
                end = n if j == -1 else j + 3
                line += text.count("\n", i, end)
                i, at_line_start = end, False
                continue
            start_line, j, buf = line, i + 1, []
            while j < n:
                if text[j] == "\\":
                    if text[j + 1 : j + 2] == "(":
                        depth, k = 1, j + 2
                        while k < n and depth:
                            depth += (text[k] == "(") - (text[k] == ")")
                            k += 1
                        buf.append(WILD)
                        j = k
                        continue
                    buf.append(text[j : j + 2])
                    j += 2
                    continue
                if text[j] in ('"', "\n"):
                    break
                buf.append(text[j])
                j += 1
            if j < n and text[j] == '"':
                lit = "".join(buf).replace('\\"', '"').replace("\\\\", "\\")
                out.append((lit, debug_depth > 0, start_line))
            i, at_line_start = j + 1, False
            continue

        if c == "\n":
            line += 1
            at_line_start = True
        elif c not in " \t":
            at_line_start = False
        i += 1

    if stack:
        raise SystemExit(f"{path}: unbalanced #if/#endif")
    return out


def collect_sources():
    """literal -> (debug_only, "path:line"). One shipping use makes a literal ship."""
    found = {}
    for root, dirs, files in os.walk(SOURCE_ROOT):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            if not name.endswith(".swift"):
                continue
            path = os.path.join(root, name)
            with open(path, encoding="utf-8") as fh:
                for lit, debug_only, line in scan_literals(fh.read(), path):
                    prev = found.get(lit)
                    if prev is None or (prev[0] and not debug_only):
                        found[lit] = (debug_only, f"{path}:{line}")
    return found


def main():
    if not os.path.exists(CATALOG):
        sys.exit(f"missing {CATALOG}")

    literals = collect_sources()
    catalog = json.load(open(CATALOG, encoding="utf-8"))
    findings = analyse(literals, catalog)

    if findings:
        print(f"  !     {len(findings)} finding(s)")
        for f in findings:
            print(f"        {f}")
        sys.exit(1)

    print(
        f"  ok    {len(catalog['strings'])} catalog keys, {len(literals)} source literals — "
        f"no orphan, no debug-only translation, no retired claim in any language"
    )


def analyse(literals, catalog):
    """Return every finding. Split out of main() so --self-test can drive it directly."""
    source_language = catalog.get("sourceLanguage", "en")
    strings = catalog["strings"]
    findings = []

    for key in sorted(strings):
        localizations = strings[key].get("localizations", {})
        normalized = SPECIFIER.sub(WILD, key)
        entry = literals.get(normalized)

        # A — orphan.
        if entry is None:
            findings.append(
                f"{CATALOG}: orphaned key {key!r}\n"
                f"          no source renders it, and its translations are what a future "
                f"re-add would inherit. Delete the entry."
            )
            continue

        # B — a DEBUG-only string carrying a translation ships that translation in Release.
        if entry[0]:
            translated = sorted(l for l in localizations if l != source_language)
            if translated:
                findings.append(
                    f"{CATALOG}: {key!r} ({entry[1]})\n"
                    f"          used only behind #if DEBUG, yet translated into "
                    f"{', '.join(translated)}. Xcode emits translated units even for keys "
                    f"it drops from {source_language}.lproj, so this ships in the Release "
                    f"bundle (AUDIT 5.11). Delete the translation."
                )

    # C and D, over every rendering: source literals, catalog keys, and localized values.
    renderings = [(where, "source", lit) for lit, (_, where) in literals.items()]
    renderings += [(CATALOG, source_language, key) for key in strings]
    renderings += [
        (CATALOG, lang, unit["value"])
        for key, entry in strings.items()
        for lang, loc in entry.get("localizations", {}).items()
        if (unit := loc.get("stringUnit")) and "value" in unit
    ]

    for where, lang, value in sorted(set(renderings)):
        folded = value.casefold()
        for phrase, why in DENY:
            if phrase.casefold() in folded:
                findings.append(
                    f"{where} [{lang}]: {value!r}\n"
                    f"          claims {phrase!r} — {why}"
                )
        if value in ACKNOWLEDGED:
            continue
        for term, why in GUARD:
            if term.casefold() in folded:
                findings.append(
                    f"{where} [{lang}]: {value!r}\n"
                    f"          mentions {term!r} ({why}) and is not ACKNOWLEDGED. Read it: "
                    f"if it denies the capability, register it verbatim in this script; if "
                    f"it promises it, delete it."
                )

    return findings


# --- self-test ---------------------------------------------------------------------------
#
# A gate is only worth its exit code if it can be shown to fail. The lint this replaces
# reported "ok" for a while with a live claim in the tree, because a broken command
# substitution meant it searched nothing — and passing is what a broken check looks like.
#
# Each case below reintroduces one defect and asserts the matching check fires. Run by
# verify-all.sh immediately before the real check, so the gate proves itself on every run.

SELF_TESTS = [
    (
        "A: orphaned catalog key",
        {"Live": (False, "X.swift:1")},
        {"Live": {}, "Retired": {"localizations": {"cs": {"stringUnit": {"value": "Odešlé"}}}}},
        "orphaned key 'Retired'",
    ),
    (
        "B: DEBUG-only string carrying a translation",
        {"Skip to App": (True, "X.swift:1")},
        {"Skip to App": {"localizations": {"cs": {"stringUnit": {"value": "Přeskočit do aplikace"}}}}},
        "used only behind #if DEBUG",
    ),
    (
        "C: retired claim in the source language",
        {"Keys live in the Secure Enclave": (False, "X.swift:1")},
        {"Keys live in the Secure Enclave": {}},
        "'Secure Enclave'",
    ),
    (
        # The case the previous grep missed: the claim is mid-sentence, in a translation
        # only, with no English original left to grep for.
        "C: retired claim surviving in a translation only",
        {"Compare the digits.": (False, "X.swift:1")},
        {
            "Compare the digits.": {
                "localizations": {
                    "cs": {"stringUnit": {"value": "Pokud sedí, vaše spojení je bezpečné."}}
                }
            }
        },
        "'spojení je bezpečn'",
    ),
    (
        "D: guarded term in an unregistered string",
        {"Unlock with Face ID": (False, "X.swift:1")},
        {"Unlock with Face ID": {}},
        "not ACKNOWLEDGED",
    ),
    (
        # An acknowledged sentence is registered by exact text, so a reworded or translated
        # one is a different string and must be read again.
        "D: an acknowledged sentence, reworded",
        {"This screen asks for Face ID.": (False, "X.swift:1")},
        {"This screen asks for Face ID.": {}},
        "not ACKNOWLEDGED",
    ),
]


def self_test():
    """Prove each check still fails on its defect. Silent unless something is wrong."""
    failures = 0

    for name, literals, strings, expected in SELF_TESTS:
        findings = analyse(literals, {"sourceLanguage": "en", "strings": strings})
        if not any(expected in f for f in findings):
            failures += 1
            print(f"  FAIL  {name}")
            print(f"        expected a finding containing {expected!r}, got: {findings}")

    # Positive control: the checks must also stay silent on clean input, or "it fails on
    # everything" would masquerade as "it detects everything".
    clean = analyse(
        {"Send": (False, "X.swift:1"), "Cancel": (False, "X.swift:2")},
        {
            "sourceLanguage": "en",
            "strings": {
                "Send": {"localizations": {"cs": {"stringUnit": {"value": "Odeslat"}}}},
                "Cancel": {},
            },
        },
    )
    if clean:
        failures += 1
        print("  FAIL  positive control: clean input is silent")
        print(f"        expected no findings, got: {clean}")

    # The DEBUG fence tracker is the one piece with real parsing in it.
    parsed = dict(
        (lit, dbg) for lit, dbg, _ in scan_literals(
            'let a = "ships"\n'
            "#if DEBUG\n"
            'let b = "debug"\n'
            "#else\n"
            'let c = "release branch"\n'
            "#endif\n"
            '// let d = "comment"\n'
            'let e = "interp \\(x) here"\n',
            "<self-test>",
        )
    )
    expected_parse = {
        "ships": False,
        "debug": True,
        "release branch": False,
        f"interp {WILD} here": False,
    }
    if parsed != expected_parse:
        failures += 1
        print("  FAIL  #if DEBUG / #else / comment / interpolation parsing")
        print(f"        expected {expected_parse}, got {parsed}")

    if failures:
        sys.exit(f"  !     {failures} self-test failure(s): this gate cannot be trusted")
    print(f"  ok    self-test: {len(SELF_TESTS) + 2} cases — every check still fails on its defect")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()
    else:
        main()
