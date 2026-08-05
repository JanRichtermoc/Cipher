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
    ("Invite codes are not implemented yet", "the relay issues real invite codes (AUDIT 5.30)"),
    ("Zvací kódy zatím nejsou hotové", "Czech rendering of the retired invite claim"),
    ("there is no server yet", "the relay exists and authenticated invite issuance is implemented"),
    ("server zatím neexistuje", "Czech rendering of the retired no-server claim"),
    ("Keys stay on your device", "public identity and prekey material is published to the relay"),
    ("Klíče zůstávají na zařízení", "Czech rendering of the undifferentiated key-custody claim"),
    ("Your identity key is generated on your iPhone", "only the private identity key stays local"),
    ("Váš identitní klíč se vytvoří na vašem iPhonu", "Czech rendering of the undifferentiated identity-key claim"),
    ("The relay only sees ciphertext", "the relay also receives public keys and routing metadata"),
    ("Relay vidí jen šifrovaný text", "Czech rendering of the ciphertext-only visibility claim"),
    ("never plaintext, never your keys", "the relay receives public keys, but never private keys or plaintext"),
    ("nikdy otevřený text, nikdy vaše klíče", "Czech rendering of the undifferentiated relay-key claim"),
    ("Keys never leave your devices", "public keys leave the device; private keys do not"),
    ("Klíče neopouštějí vaše zařízení", "Czech rendering of the undifferentiated key-custody claim"),
    ("Choose Photo", "profile photos have no picker, storage, or delivery mechanism (AUDIT 5.30)"),
    ("Vybrat fotku", "Czech rendering of the retired no-op profile-photo control"),
    ("Contact support", "Cipher has no configured support channel (AUDIT 5.30)"),
    ("Kontaktovat podporu", "Czech rendering of the retired placeholder support control"),
    (
        "Preview build: messages are not encrypted yet",
        "the production messaging path encrypts through CipherCrypto (AUDIT 5.3)",
    ),
    (
        "Ukázkové sestavení: zprávy zatím nejsou šifrované",
        "Czech rendering of the retired pre-encryption build warning",
    ),
    ("Show Preview", "notification previews do not exist until P8.S03 (AUDIT 5.30)"),
    ("Zobrazit náhled", "Czech rendering of the inert notification-preview control"),
    (
        "So you know when a friend messages you",
        "onboarding cannot promise notifications before push exists (AUDIT 5.30)",
    ),
    (
        "Ať víte, když vám kamarád napíše",
        "Czech rendering of the premature notification promise",
    ),
]

# Terms honest only in a sentence someone has read. Every occurrence — each translation
# included — must appear verbatim in ACKNOWLEDGED.
# Czech forms sit beside their English originals, exactly as DENY does. Without them this
# list was half a check: "Face ID" is a product name and survives translation, so it fired
# on Czech copy, while "passcode" becomes "kód zařízení" and slipped through — so a Czech
# string could promise a device-owner check with nothing behind it and the gate would agree.
# Found when check E's translations were added and only two of the four fired.
GUARD = [
    ("Face ID", "no LocalAuthentication anywhere until P3.S02"),
    ("Touch ID", "no LocalAuthentication anywhere until P3.S02"),
    ("passcode", "the app does not ask for the device passcode until P3.S02"),
    ("kód zařízení", "Czech rendering of the device-passcode claim"),
    ("kódu zařízení", "Czech rendering of the device-passcode claim, inflected"),
]

# Reviewed and correct as written. Each of these *denies* the capability it names.
ACKNOWLEDGED = {
    # P3.S02 made the lock real: `AppSession.unlock(reason:)` only clears the lock after a
    # successful `.deviceOwnerAuthentication`, and `RootView` re-locks on every move out of
    # the foreground. These promise exactly what now happens, which is the only condition on
    # which an entry may be added here.
    "Unlock with Face ID or your device passcode.",
    "Set a device passcode to use the app lock.",
    "Could not verify it is you. Try again.",
    "Require Face ID or your device passcode to reopen Cipher.",
    # The Czech renderings of the four above, added with check E. Each is a translation of
    # an already-acknowledged string and promises the same thing it does — which is the only
    # basis on which anything joins this set.
    "Odemkněte pomocí Face ID nebo kódu zařízení.",
    "Pro zámek aplikace nastavte kód zařízení.",
    "Nepodařilo se ověřit vaši totožnost. Zkuste to znovu.",
    "Vyžadovat Face ID nebo kód zařízení pro opětovné otevření Cipheru.",
}

# Markers that identify a string as a *safety warning* rather than ordinary UI copy: text
# whose whole job is to stop someone trusting this build with something that matters.
#
# Check E requires every one of these to be translated into every language the catalog
# otherwise supports. The failure it prevents is the exact inverse of AUDIT 5.4 and is
# easier to miss: 5.4 was Czech shipping a *retired claim*, and this is Czech shipping the
# whole interface while the warnings stay in English. A user then reads the app in their own
# language and the one paragraph telling them not to rely on it in a foreign one — which
# selects precisely the sentence they are least likely to read carefully.
WARNING_MARKERS = [
    "not implemented yet",
    "not encrypted yet",
    "are not deleted yet",
    "does not send notifications yet",
    "do not use",
    "do not treat",
    "nothing reads this setting",
    "none of these settings",
]

# A catalog key holds format specifiers where the source has interpolation; the two are
# compared with both reduced to this placeholder.
WILD = "\x00"
SPECIFIER = re.compile(r"%(?:\d+\$)?(?:@|lld|llu|ld|lu|lf|[dufs])")
DIRECTIVE = re.compile(r"#(if|elseif|else|endif)\b([^\n]*)")
EMAIL_ADDRESS = re.compile(
    r"(?i)(?<![a-z0-9._%+-])[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}(?![a-z0-9.-])"
)


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
    # One (current, complement) pair per open #if. Two values because `#else` has to know
    # what the *other* branch means: the complement of `#if DEBUG` ships, the complement of
    # `#if !DEBUG` is debug-only, and the complement of anything else is unknown and
    # therefore treated as shipping.
    stack = []
    debug_depth = 0

    i, n, line, at_line_start = 0, len(text), 1, True
    while i < n:
        c = text[i]

        if at_line_start and c == "#" and (m := DIRECTIVE.match(text, i)):
            kind, cond = m.group(1), m.group(2).strip()
            if kind == "if":
                if cond == "DEBUG":
                    branches = (True, False)
                elif cond == "!DEBUG":
                    branches = (False, True)
                elif "DEBUG" in cond:
                    raise SystemExit(
                        f"{path}:{line}: unhandled '#if {cond}'. Teach scan_literals about "
                        f"it — guessing would silently disable the DEBUG-only check."
                    )
                else:
                    branches = (False, False)
                stack.append(branches)
                debug_depth += branches[0]
            elif kind == "else" and stack:
                current, complement = stack[-1]
                debug_depth -= current
                stack[-1] = (complement, current)
                debug_depth += complement
            elif kind == "elseif" and stack:
                # An unknown intermediate condition: assume it ships, and leave nothing for a
                # later `#else` to flip back to debug-only on a guess.
                debug_depth -= stack[-1][0]
                stack[-1] = (False, False)
            elif kind == "endif":
                if not stack:
                    raise SystemExit(f"{path}:{line}: #endif without #if")
                debug_depth -= stack.pop()[0]
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
        if EMAIL_ADDRESS.search(value):
            findings.append(
                f"{where} [{lang}]: contains an email address\n"
                f"          Cipher has no configured support mailbox and does not use email "
                f"for identity (AUDIT 5.30; plan §0.2.7)"
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

    # E — a safety warning that is not translated everywhere the interface is.
    #
    # The set of languages is taken from the catalog rather than configured, so adding a
    # language automatically extends the requirement instead of quietly exempting it.
    supported = {
        lang
        for entry in strings.values()
        for lang in entry.get("localizations", {})
        if lang != source_language
    }
    for key in sorted(strings):
        folded = key.casefold()
        marker = next((m for m in WARNING_MARKERS if m in folded), None)
        if marker is None:
            continue
        # A DEBUG-only warning must NOT be translated — check B forbids exactly that — so
        # this requirement applies only to strings that ship.
        entry = literals.get(SPECIFIER.sub(WILD, key))
        if entry is None or entry[0]:
            continue
        missing = sorted(supported - set(strings[key].get("localizations", {})))
        if missing:
            findings.append(
                f"{CATALOG}: {key!r}\n"
                f"          is a safety warning (matches {marker!r}) but has no "
                f"{', '.join(missing)} translation, while the rest of the interface does. "
                f"A reader gets the app in their language and the warning in "
                f"{source_language} — the inverse of AUDIT 5.4 and the sentence they can "
                f"least afford to skim. Translate it."
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
        "C: retired invite implementation claim",
        {"Invite codes are not implemented yet.": (False, "X.swift:1")},
        {"Invite codes are not implemented yet.": {}},
        "'Invite codes are not implemented yet'",
    ),
    (
        "C: retired Czech invite implementation claim",
        {"Invite issuance is unavailable in the client.": (False, "X.swift:1")},
        {
            "Invite issuance is unavailable in the client.": {
                "localizations": {
                    "cs": {"stringUnit": {"value": "Zvací kódy zatím nejsou hotové."}}
                }
            }
        },
        "'Zvací kódy zatím nejsou hotové'",
    ),
    (
        "C: retired no-server claim",
        {"There is no server yet.": (False, "X.swift:1")},
        {"There is no server yet.": {}},
        "'there is no server yet'",
    ),
    (
        "C: retired Czech no-server claim",
        {"Invite issuance is unavailable in the client.": (False, "X.swift:1")},
        {
            "Invite issuance is unavailable in the client.": {
                "localizations": {
                    "cs": {"stringUnit": {"value": "Server zatím neexistuje."}}
                }
            }
        },
        "'server zatím neexistuje'",
    ),
    (
        "C: retired local-key claim",
        {"Keys stay on your device": (False, "X.swift:1")},
        {"Keys stay on your device": {}},
        "'Keys stay on your device'",
    ),
    (
        "C: retired Czech local-key claim",
        {"Private keys stay local.": (False, "X.swift:1")},
        {
            "Private keys stay local.": {
                "localizations": {
                    "cs": {"stringUnit": {"value": "Klíče zůstávají na zařízení"}}
                }
            }
        },
        "'Klíče zůstávají na zařízení'",
    ),
    (
        "C: retired identity-key claim",
        {"Your identity key is generated on your iPhone.": (False, "X.swift:1")},
        {"Your identity key is generated on your iPhone.": {}},
        "'Your identity key is generated on your iPhone'",
    ),
    (
        "C: retired Czech identity-key claim",
        {"The private identity key stays local.": (False, "X.swift:1")},
        {
            "The private identity key stays local.": {
                "localizations": {
                    "cs": {"stringUnit": {"value": "Váš identitní klíč se vytvoří na vašem iPhonu."}}
                }
            }
        },
        "'Váš identitní klíč se vytvoří na vašem iPhonu'",
    ),
    (
        "C: retired relay-ciphertext-only claim",
        {"The relay only sees ciphertext": (False, "X.swift:1")},
        {"The relay only sees ciphertext": {}},
        "'The relay only sees ciphertext'",
    ),
    (
        "C: retired Czech relay-ciphertext-only claim",
        {"The relay cannot decrypt messages.": (False, "X.swift:1")},
        {
            "The relay cannot decrypt messages.": {
                "localizations": {
                    "cs": {"stringUnit": {"value": "Relay vidí jen šifrovaný text"}}
                }
            }
        },
        "'Relay vidí jen šifrovaný text'",
    ),
    (
        "C: retired relay-key claim",
        {"Never plaintext, never your keys.": (False, "X.swift:1")},
        {"Never plaintext, never your keys.": {}},
        "'never plaintext, never your keys'",
    ),
    (
        "C: retired Czech relay-key claim",
        {"The relay never receives private keys.": (False, "X.swift:1")},
        {
            "The relay never receives private keys.": {
                "localizations": {
                    "cs": {"stringUnit": {"value": "Nikdy otevřený text, nikdy vaše klíče."}}
                }
            }
        },
        "'nikdy otevřený text, nikdy vaše klíče'",
    ),
    (
        "C: retired keys-never-leave claim",
        {"Keys never leave your devices.": (False, "X.swift:1")},
        {"Keys never leave your devices.": {}},
        "'Keys never leave your devices'",
    ),
    (
        "C: retired Czech keys-never-leave claim",
        {"Private keys stay local.": (False, "X.swift:1")},
        {
            "Private keys stay local.": {
                "localizations": {
                    "cs": {"stringUnit": {"value": "Klíče neopouštějí vaše zařízení."}}
                }
            }
        },
        "'Klíče neopouštějí vaše zařízení'",
    ),
    (
        "C: retired no-op profile-photo control",
        {"Choose Photo": (False, "X.swift:1")},
        {"Choose Photo": {}},
        "'Choose Photo'",
    ),
    (
        "C: retired Czech no-op profile-photo control",
        {"Profile": (False, "X.swift:1")},
        {
            "Profile": {
                "localizations": {
                    "cs": {"stringUnit": {"value": "Vybrat fotku"}}
                }
            }
        },
        "'Vybrat fotku'",
    ),
    (
        "C: retired placeholder support control",
        {"Contact support": (False, "X.swift:1")},
        {"Contact support": {}},
        "'Contact support'",
    ),
    (
        "C: retired Czech placeholder support control",
        {"Help": (False, "X.swift:1")},
        {
            "Help": {
                "localizations": {
                    "cs": {"stringUnit": {"value": "Kontaktovat podporu"}}
                }
            }
        },
        "'Kontaktovat podporu'",
    ),
    (
        "C: retired pre-encryption build warning",
        {"Preview build: messages are not encrypted yet.": (False, "X.swift:1")},
        {"Preview build: messages are not encrypted yet.": {}},
        "'Preview build: messages are not encrypted yet'",
    ),
    (
        "C: retired Czech pre-encryption build warning",
        {"Messaging is encrypted.": (False, "X.swift:1")},
        {
            "Messaging is encrypted.": {
                "localizations": {
                    "cs": {
                        "stringUnit": {
                            "value": "Ukázkové sestavení: zprávy zatím nejsou šifrované."
                        }
                    }
                }
            }
        },
        "'Ukázkové sestavení: zprávy zatím nejsou šifrované'",
    ),
    (
        "C: retired notification-preview control",
        {"Show Preview": (False, "X.swift:1")},
        {"Show Preview": {}},
        "'Show Preview'",
    ),
    (
        "C: retired Czech notification-preview control",
        {"Notification privacy": (False, "X.swift:1")},
        {
            "Notification privacy": {
                "localizations": {
                    "cs": {"stringUnit": {"value": "Zobrazit náhled"}}
                }
            }
        },
        "'Zobrazit náhled'",
    ),
    (
        "C: premature onboarding notification promise",
        {"So you know when a friend messages you.": (False, "X.swift:1")},
        {"So you know when a friend messages you.": {}},
        "'So you know when a friend messages you'",
    ),
    (
        "C: premature Czech onboarding notification promise",
        {"Notifications are future work.": (False, "X.swift:1")},
        {
            "Notifications are future work.": {
                "localizations": {
                    "cs": {
                        "stringUnit": {"value": "Ať víte, když vám kamarád napíše."}
                    }
                }
            }
        },
        "'Ať víte, když vám kamarád napíše'",
    ),
    (
        "C: retired placeholder support address",
        {"person" + "@" + "example.invalid": (False, "X.swift:1")},
        {"person" + "@" + "example.invalid": {}},
        "contains an email address",
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
    (
        # E — the inverse of AUDIT 5.4, and the easier one to miss. The interface is
        # translated, the warning is not, so the reader gets the app in their language and
        # the one paragraph telling them not to rely on it in another.
        "E: safety warning untranslated while the interface is translated",
        {
            "Send": (False, "X.swift:1"),
            "Safety numbers are not implemented yet.": (False, "X.swift:2"),
        },
        {
            "Send": {"localizations": {"cs": {"stringUnit": {"value": "Odeslat"}}}},
            "Safety numbers are not implemented yet.": {},
        },
        "has no cs translation",
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
            "#if !DEBUG\n"
            'let f = "release only"\n'
            "#else\n"
            'let g = "the inverse else is debug-only"\n'
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
        # `#if !DEBUG` inverts: the branch ships, and its `#else` is the debug-only one.
        # Getting this backwards would mark shipping strings as debug-only and vice versa.
        "release only": False,
        "the inverse else is debug-only": True,
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
