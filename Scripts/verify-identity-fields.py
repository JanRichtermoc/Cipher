#!/usr/bin/env python3
#
# Invite-code-only identity gate — plan §0.2.7, THREAT_MODEL.md §3.4, BACKEND.md §2.1.
#
# Cipher collects no phone number, no email address, no server-side username and no
# verification code. An account exists because an invite code was redeemed, and the ACI
# the server mints is an opaque UUID. That is a REQUIREMENT, not a coincidence: an
# identifier that is never collected cannot be leaked, correlated against another
# service, subpoenaed, or used to enumerate the user base — and a phone or email flow
# would additionally drag an SMS or mail provider into a design that has no third
# parties in it at all.
#
# It is also the easiest property in this repository to lose by accident, because every
# other messenger has the field and "sign in with email" looks like three lines of
# work. So this gate refuses an identity-shaped field name in the four places one would
# have to appear before it could do any harm:
#
#   RELAY SCHEMA    server/internal/store/migrations   the columns a seizure reads
#   ACCOUNT MODEL   server/internal/store              the row an account *is*
#   AUTH API        server/internal/{api,auth,invite}  the request that creates or
#                   Cipher/Networking                  presents an account, both halves
#   WIRE FORMAT     CipherCrypto/Sources/Wire          who a message says it is from
#
# …plus the rest of `server/` as a catch-all beneath those four, so a relay package
# added later is scanned the day it appears rather than being a blind spot nobody
# remembers to close. Every existing package was measured clean before this was widened,
# so the breadth costs nothing.
#
# ## What is deliberately NOT in scope
#
# The local profile — display name, username, "about" — is out of scope and is not
# forbidden. It never leaves the device, `ProfileArchive` seals it, and BACKEND.md §2.1
# already records those columns as absent from the server on purpose. The property
# being locked is what Cipher *collects*, not what someone types for themselves. A gate
# that also banned the local field would be banning the wrong thing and would be
# deleted the first time it was inconvenient.
#
# `ServiceIdentifier.Kind.pni` is likewise not a finding. A PNI is a UUID in a second
# namespace, not a phone number, and the case exists so that a PNI-addressed envelope
# is *rejected rather than misparsed*. Cipher never issues one. See AUDIT 5.31.
#
# ## Why comments are stripped first (AUDIT R3, R2)
#
# The prose documenting this decision names every string the gate forbids:
# `0001_init.sql` says no "phone, or email exists anywhere", `invite/code.go` says
# "no phone number, no email, no username lookup", `ServiceIdentifier.swift` documents
# the PNI namespace it refuses to issue. A naive grep fires on the documentation of the
# very control it is checking, and a gate that cries wolf is as dangerous as one that
# never fires — it gets deleted.
#
# So comments are removed before matching, by a per-language lexer that knows a `//`
# inside a string literal is *not* a comment. That distinction is load-bearing in both
# directions: struct tags (`json:"email"`) are string literals and are exactly what
# must still be caught, and a stripper that truncated at a quoted `//` would blind the
# scanner to every field declared after it on that line.
#
# ## Matching is on identifier tokens, not substrings
#
# `phoneNumber`, `phone_number`, `PhoneNumber` and `"phone"` are the same field spelled
# four ways, while `RelayMailbox` and `iphoneos` are not findings at all. Names are
# therefore split into words (camelCase and snake_case both) and matched as whole
# tokens, or as adjacent pairs where the compound is what makes it an identifier
# (`verification` + `code`).
#
# ## Positive controls (AUDIT R2)
#
# Every verdict here is "found nothing", which is also what a broken scanner looks
# like. Nothing is believed until three controls pass:
#
#   A. the scan still finds a token that IS present, in every real scanned file group,
#      so an over-eager stripper, a moved path or an empty file list fails loudly
#      instead of passing vacuously. Runs on every invocation, not just --self-test.
#   B. --self-test proves the matcher still fires on a forbidden field in code position,
#      in each of the three languages and through each string form they have.
#   C. --self-test proves it does NOT fire on the same word inside a comment, which is
#      the R3 trap, and proves control A itself fails when handed a crippled scanner.
#
# Usage:
#   Scripts/verify-identity-fields.py              exit 0 clean, 1 on any finding
#   Scripts/verify-identity-fields.py --self-test  prove the gate can still fail
#
# Copyright (C) 2026 Jan Richter
# SPDX-License-Identifier: AGPL-3.0-only

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SWIFT = "swift"
GO = "go"
SQL = "sql"

# (surface, directory relative to the repo root, {extension: language}).
#
# The surface name is what the failure message says was breached, because "an email
# column appeared in the relay schema" and "an email field appeared in the wire format"
# are different incidents with different blast radii.
#
# **Ordered most specific first**, and a file is claimed by the first entry that contains
# it. `server` is therefore a catch-all beneath the four named relay surfaces rather than
# a duplicate of them: the relay as a whole must never carry a human identifier, and
# scanning only the four directories would leave a package added later silently
# unscanned. Measured before it was written this way — every existing package is clean —
# so this costs nothing and removes a blind spot rather than describing one.
SCOPE = [
    ("relay schema", "server/internal/store/migrations", {".sql": SQL}),
    ("account model", "server/internal/store", {".go": GO}),
    ("auth API (relay)", "server/internal/api", {".go": GO}),
    ("auth API (relay)", "server/internal/auth", {".go": GO}),
    ("auth API (relay)", "server/internal/invite", {".go": GO}),
    ("relay (other)", "server", {".go": GO, ".sql": SQL}),
    ("auth API (client)", "Cipher/Networking", {".swift": SWIFT}),
    ("wire format", "CipherCrypto/Sources/Wire", {".swift": SWIFT}),
]

# A single identifier word that makes the name an identity field on its own.
FORBIDDEN_TOKENS = {
    "phone": "a phone number is an identifier Cipher never collects (THREAT_MODEL.md §3.4)",
    "telephone": "a phone number is an identifier Cipher never collects (THREAT_MODEL.md §3.4)",
    "msisdn": "a phone number is an identifier Cipher never collects (THREAT_MODEL.md §3.4)",
    "e164": "a phone number is an identifier Cipher never collects (THREAT_MODEL.md §3.4)",
    "email": "an email address is an identifier Cipher never collects (THREAT_MODEL.md §3.4)",
    "emails": "an email address is an identifier Cipher never collects (THREAT_MODEL.md §3.4)",
    "mailto": "an email address is an identifier Cipher never collects (THREAT_MODEL.md §3.4)",
    "sms": "an SMS flow needs a phone number and an SMS provider — a third party this design has none of",
    "smtp": "a mail flow needs an email address and a mail provider — a third party this design has none of",
    "otp": "a one-time passcode implies a phone or mail channel to deliver it on",
    "username": "a server-side username is a searchable handle and an enumeration target (BACKEND.md §2.1)",
    "usernames": "a server-side username is a searchable handle and an enumeration target (BACKEND.md §2.1)",
    "twilio": "an SMS provider is a third party this design deliberately has none of",
    "sendgrid": "a mail provider is a third party this design deliberately has none of",
    "mailgun": "a mail provider is a third party this design deliberately has none of",
}

# Two adjacent identifier words where the compound, not either half, is the identifier.
# `verify` and `code` are each ordinary here — signature verification, invite codes —
# and only their adjacency names a delivered one-time secret.
FORBIDDEN_PAIRS = {
    ("user", "name"): "a server-side username is a searchable handle and an enumeration target (BACKEND.md §2.1)",
    ("verification", "code"): "a verification code implies an out-of-band channel — an SMS or mail provider",
    ("verify", "code"): "a verification code implies an out-of-band channel — an SMS or mail provider",
    ("confirmation", "code"): "a confirmation code implies an out-of-band channel — an SMS or mail provider",
    ("e", "mail"): "an email address is an identifier Cipher never collects (THREAT_MODEL.md §3.4)",
    ("e", "164"): "a phone number is an identifier Cipher never collects (THREAT_MODEL.md §3.4)",
    ("mobile", "number"): "a phone number is an identifier Cipher never collects (THREAT_MODEL.md §3.4)",
    ("contact", "discovery"): "server-side contact discovery is a standing prohibition (THREAT_MODEL.md §3.4)",
}

# Control A. A token that is present in *code* — never only in a comment — in one real
# file of every scanned surface. If the stripper starts eating code, a path moves, or a
# file stops being read, this fails and says so, rather than the scan reporting a clean
# tree it never looked at.
SENTINELS = [
    ("server/internal/store/migrations/0001_init.sql", "registration"),
    ("server/internal/store/sessions.go", "session"),
    ("server/internal/api/invite.go", "redeem"),
    ("server/internal/auth/token.go", "token"),
    ("server/internal/invite/code.go", "code"),
    ("server/cmd/relay/main.go", "relay"),
    ("Cipher/Networking/InviteRedemption.swift", "redeem"),
    ("CipherCrypto/Sources/Wire/ServiceIdentifier.swift", "uuid"),
]


# --- Comment stripping ------------------------------------------------------
#
# Replaces comment bytes with spaces rather than deleting them, so every byte offset
# and every line number in the stripped text still names the same place in the file.


class _Lang:
    """What a comment and a string literal look like in one language."""

    def __init__(self, line, block, block_nests, quotes, backtick=False,
                 doubled_quote=False, dollar_quote=False, swift_raw=False,
                 triple_quote=False):
        self.line = line                    # line-comment prefixes
        self.block = block                  # (open, close) or None
        self.block_nests = block_nests      # Swift and PostgreSQL nest; Go does not
        self.quotes = quotes                # backslash-escaped string delimiters
        self.backtick = backtick            # Go raw strings
        self.doubled_quote = doubled_quote  # SQL '' and "" escaping
        self.dollar_quote = dollar_quote    # PostgreSQL $tag$ ... $tag$
        self.swift_raw = swift_raw          # Swift #"..."#
        self.triple_quote = triple_quote    # Swift """ ... """


LANGS = {
    SWIFT: _Lang(line=["//"], block=("/*", "*/"), block_nests=True, quotes=['"'],
                 swift_raw=True, triple_quote=True),
    GO: _Lang(line=["//"], block=("/*", "*/"), block_nests=False, quotes=['"', "'"],
              backtick=True),
    SQL: _Lang(line=["--"], block=("/*", "*/"), block_nests=True, quotes=[],
               doubled_quote=True, dollar_quote=True),
}

_DOLLAR_TAG = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$")


def strip_comments(text, lang):
    """Blank out every comment, leaving string literals and all offsets intact."""
    spec = LANGS[lang]
    out = list(text)
    i = 0
    n = len(text)

    def blank(start, end):
        for k in range(start, end):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        ch = text[i]

        # Line comment.
        hit = next((p for p in spec.line if text.startswith(p, i)), None)
        if hit:
            end = text.find("\n", i)
            end = n if end == -1 else end
            blank(i, end)
            i = end
            continue

        # Block comment, nesting where the language nests.
        if spec.block and text.startswith(spec.block[0], i):
            op, cl = spec.block
            depth = 1
            j = i + len(op)
            while j < n and depth:
                if spec.block_nests and text.startswith(op, j):
                    depth += 1
                    j += len(op)
                elif text.startswith(cl, j):
                    depth -= 1
                    j += len(cl)
                else:
                    j += 1
            blank(i, j)
            i = j
            continue

        # Swift raw string: #"..."#, ##"..."##, and their multiline forms. The closing
        # delimiter carries the same number of hashes, which is the entire point of the
        # syntax — a shorter run inside the literal must not end it.
        if spec.swift_raw and ch == "#":
            h = 0
            while i + h < n and text[i + h] == "#":
                h += 1
            if i + h < n and text[i + h] == '"':
                triple = text.startswith('"""', i + h)
                open_q = '"""' if triple else '"'
                close = open_q + ("#" * h)
                j = text.find(close, i + h + len(open_q))
                i = n if j == -1 else j + len(close)
                continue
            i += h
            continue

        # Swift multiline string.
        if spec.triple_quote and text.startswith('"""', i):
            j = i + 3
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text.startswith('"""', j):
                    j += 3
                    break
                j += 1
            i = j
            continue

        # Go raw string. No escapes and it may span lines — and it must be consumed
        # rather than walked through, because a struct tag is a raw string and a `//`
        # inside one would otherwise blank the rest of the line, hiding every field
        # declared after it.
        if spec.backtick and ch == "`":
            j = text.find("`", i + 1)
            i = n if j == -1 else j + 1
            continue

        # Backslash-escaped string.
        if ch in spec.quotes:
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == ch:
                    j += 1
                    break
                if text[j] == "\n":
                    # Unterminated: a single-quoted Swift/Go literal cannot span lines,
                    # and running to end-of-file from a stray quote would blind the rest
                    # of the scan. Give up on the literal, not on the file.
                    break
                j += 1
            i = j
            continue

        # SQL dollar-quoting, before the doubled-quote forms: a $$ body may contain
        # anything at all, including apostrophes that would otherwise open a string.
        if spec.dollar_quote and ch == "$":
            m = _DOLLAR_TAG.match(text, i)
            if m:
                tag = m.group(0)
                j = text.find(tag, m.end())
                i = n if j == -1 else j + len(tag)
                continue

        # SQL strings and quoted identifiers: '' and "" are escapes, not terminators.
        if spec.doubled_quote and ch in ("'", '"'):
            j = i + 1
            while j < n:
                if text[j] == ch:
                    if j + 1 < n and text[j + 1] == ch:
                        j += 2
                        continue
                    j += 1
                    break
                j += 1
            i = j
            continue

        i += 1

    return "".join(out)


# --- Tokenizing and matching ------------------------------------------------

# camelCase, PascalCase, snake_case and SCREAMING_CASE all reduce to the same words.
# `[A-Z]+(?![a-z])` takes an acronym run without stealing the capital that starts the
# next word, so `SMSCode` is (sms, code) and not (smsc, ode).
WORD = re.compile(r"[A-Z]+(?![a-z])|[A-Z][a-z0-9]*|[a-z0-9]+")


def words(line):
    return [m.group(0).lower() for m in WORD.finditer(line)]


def scan_text(text, lang, path, surface):
    """Findings in one already-read file. Split out so --self-test can drive it."""
    findings = []
    for number, line in enumerate(strip_comments(text, lang).split("\n"), 1):
        tokens = words(line)
        for index, token in enumerate(tokens):
            reason = FORBIDDEN_TOKENS.get(token)
            if reason:
                findings.append((surface, path, number, token, reason, line.strip()))
            if index + 1 < len(tokens):
                pair = (token, tokens[index + 1])
                reason = FORBIDDEN_PAIRS.get(pair)
                if reason:
                    findings.append((surface, path, number, " ".join(pair), reason,
                                     line.strip()))
    return findings


def collect_files():
    """Every in-scope file, as (surface, relative path, language).

    SCOPE is ordered most specific first and a file is claimed once, so the catch-all
    entries scan what the named ones did not rather than re-reporting it.
    """
    found = []
    empty = []
    claimed = set()
    for surface, root, extensions in SCOPE:
        absolute = os.path.join(ROOT, root)
        if not os.path.isdir(absolute):
            empty.append(f"{root} (missing)")
            continue
        before = len(found)
        for dirpath, dirnames, filenames in os.walk(absolute):
            # `vendor` is upstream code, not ours to hold to this rule, and it is already
            # pinned byte-for-byte by verify-relay.sh (AUDIT 1.12).
            dirnames[:] = [d for d in sorted(dirnames) if d != "vendor"]
            for name in sorted(filenames):
                extension = os.path.splitext(name)[1]
                if extension not in extensions:
                    continue
                relative = os.path.relpath(os.path.join(dirpath, name), ROOT)
                if relative in claimed:
                    continue
                claimed.add(relative)
                found.append((surface, relative, extensions[extension]))
        if len(found) == before:
            empty.append(f"{root} (no matching files)")
    return found, empty


def read(relative):
    with open(os.path.join(ROOT, relative), encoding="utf-8", errors="replace") as handle:
        return handle.read()


def positive_control(strip=strip_comments):
    """Control A. Returns a list of failure messages; empty means the scan can see."""
    failures = []
    for relative, token in SENTINELS:
        absolute = os.path.join(ROOT, relative)
        if not os.path.isfile(absolute):
            failures.append(f"{relative}: sentinel file is gone — the scan's scope has "
                            f"moved and its all-clear would cover nothing")
            continue
        extension = os.path.splitext(relative)[1]
        lang = {".sql": SQL, ".go": GO, ".swift": SWIFT}[extension]
        with open(absolute, encoding="utf-8", errors="replace") as handle:
            stripped = strip(handle.read(), lang)
        if token not in words(stripped):
            failures.append(f"{relative}: '{token}' is in this file's code and the scan "
                            f"cannot see it — the comment stripper is eating code, so a "
                            f"clean result here would be meaningless")
    return failures


def main():
    files, empty = collect_files()

    if empty:
        print("  !     a scanned surface produced no files: " + ", ".join(empty),
              file=sys.stderr)
        print("  !     an identity field could be added there and this gate would agree",
              file=sys.stderr)
        sys.exit(1)

    for failure in positive_control():
        print(f"  !     {failure}", file=sys.stderr)
        sys.exit(1)

    findings = []
    for surface, relative, lang in files:
        findings.extend(scan_text(read(relative), lang, relative, surface))

    if findings:
        print("\nAn identity-shaped field reached a surface that must never carry one.\n",
              file=sys.stderr)
        for surface, path, number, token, reason, line in findings:
            print(f"  {path}:{number}: '{token}' in the {surface}", file=sys.stderr)
            print(f"      {reason}", file=sys.stderr)
            print(f"      {line}", file=sys.stderr)
        print("\nThis is locked decision 7 (plan §0.2.7). Cipher's only identifier is an "
              "invite\ncode redeemed for an opaque ACI. An identifier that is never "
              "collected cannot be\nleaked, correlated, subpoenaed, or used to enumerate "
              "the user base, and a phone or\nmail flow would put an SMS or mail provider "
              "inside a design that has no third\nparties. If this is genuinely intended, "
              "it is a threat-model change: argue it in\nTHREAT_MODEL.md §3.4 first.\n",
              file=sys.stderr)
        sys.exit(1)

    print(f"  ok    {len(files)} files across {len({s for s, _, _ in files})} surfaces "
          f"carry no phone, email, username or verification-code field")


# --- Self-test --------------------------------------------------------------
#
# (name, language, source, expected forbidden tokens found)

SELF_TESTS = [
    # B — the matcher fires on a field in code position, in every language.
    ("sql: a column is caught", SQL,
     "CREATE TABLE accounts (\n    email TEXT NOT NULL\n);\n", ["email"]),
    ("go: a struct field is caught", GO,
     'type req struct {\n\tEmail string `json:"email"`\n}\n', ["email", "email"]),
    ("swift: a property is caught", SWIFT,
     "struct R {\n    let phoneNumber: String\n}\n", ["phone"]),
    # The four spellings of one field all reduce to the same finding.
    ("naming: snake, camel, pascal and screaming all match", GO,
     "phone_number\nphoneNumber\nPhoneNumber\nPHONE_NUMBER\n",
     ["phone", "phone", "phone", "phone"]),
    ("naming: an acronym run does not swallow the next word", GO,
     "SMSCode\n", ["sms"]),
    ("naming: a pair matches only when adjacent", GO,
     "verificationCode\nverification, unrelated, code\n", ["verification code"]),

    # C — the R3 trap. The words appear, in a comment, describing the control.
    ("sql: a line comment is not a finding", SQL,
     "-- no phone, or email exists anywhere, by THREAT_MODEL.md 3.4\nCREATE TABLE t (a UUID);\n",
     []),
    ("go: a line comment is not a finding", GO,
     "// There is no phone number, no email, no username lookup.\nvar ok bool\n", []),
    ("swift: a doc comment is not a finding", SWIFT,
     "/// Phone-number identifier. Cipher never issues one.\ncase pni = 1\n", []),
    ("swift: a block comment is not a finding", SWIFT,
     "/* email\n   phone */\nlet a = 1\n", []),
    ("swift: block comments nest", SWIFT,
     "/* outer /* inner */ email */\nlet a = 1\n", []),
    ("go: block comments do NOT nest", GO,
     "/* outer /* inner */\nvar Email string\n", ["email"]),

    # The distinction the whole stripper exists for: a comment marker inside a string
    # literal is not a comment, and a field declared after one must still be seen.
    ("go: // inside a string does not blind the rest of the line", GO,
     'x := "// not a comment"; var Email string\n', ["email"]),
    ("swift: /* inside a string does not open a comment", SWIFT,
     'let a = "/* email */"\nlet phone = 1\n', ["email", "phone"]),
    ("sql: -- inside a string does not open a comment", SQL,
     "INSERT INTO t VALUES ('-- not a comment'), ('email');\n", ["email"]),
    ("sql: a doubled quote is an escape, not a terminator", SQL,
     "INSERT INTO t VALUES ('it''s email');\nSELECT phone FROM t;\n",
     ["email", "phone"]),
    ("go: a raw string is still code", GO,
     "s := `email`\n", ["email"]),
    # A bare `//` inside a Go raw string — no inner quotes to absorb it. Without raw-string
    # handling this opens a line comment, blanks the rest of the line, and hides every
    # field declared after it. Both cases below are chosen so they FAIL if the backtick
    # branch is removed; a case that passes either way would prove nothing.
    ("go: // inside a raw string does not blind the rest of the line", GO,
     "s := `see http://x`; var Email string\n", ["email"]),
    # And the worse one: an unterminated comment *opener* inside a raw string. Without
    # raw-string handling `/*` starts a block comment that never closes, blanking every
    # remaining line in the file rather than merely the rest of one.
    ("go: /* inside a raw string does not swallow the rest of the file", GO,
     "s := `a /* b`\nvar Email string\n", ["email"]),
    # The three below each carry a comment opener the surrounding literal must absorb.
    # A literal holding only ordinary words would pass with the handler removed — string
    # contents are code here by design — and would prove nothing about the handler.
    ("swift: a multiline string absorbs an unclosed /*", SWIFT,
     'let s = """\n/* not a comment\n"""\nlet phone = 1\n', ["phone"]),
    ("swift: a raw string is not ended by a bare quote inside it", SWIFT,
     'let s = #"x " // y"#; let phone = 1\n', ["phone"]),
    ("swift: a raw string is still code", SWIFT,
     'let s = #"email"#\nlet a = 1\n', ["email"]),
    ("sql: a dollar-quoted body absorbs an unclosed /*", SQL,
     "DO $$ BEGIN /* unclosed END $$;\nSELECT phone FROM t;\n", ["phone"]),
    ("swift: an escaped quote does not end the string early", SWIFT,
     'let s = "a \\" phone"\nlet a = 1\n', ["phone"]),

    # Out of scope by design, and it must stay that way: the local profile field and the
    # PNI namespace are both legitimate, and firing on them would make the gate a lie.
    ("scope: 'mailbox' is not 'email'", SWIFT,
     "let mailbox = RelayMailbox()\n", []),
    ("scope: 'iphoneos' is not a phone number", GO,
     "sdk := \"iphoneos\"\n", []),
    ("scope: the PNI namespace is not a finding", SWIFT,
     "case pni = 1\nlet id = Pni(fromUUID: uuid)\n", []),
    ("scope: signature verification is not a verification code", SWIFT,
     "let ok = verify(signature)\nlet c = inviteCode\n", []),
]


def self_test():
    failures = 0

    for name, lang, source, expected in SELF_TESTS:
        found = [token for _, _, _, token, _, _ in
                 scan_text(source, lang, "<self-test>", "<self-test>")]
        if found != expected:
            failures += 1
            print(f"  FAIL  {name}")
            print(f"        expected {expected}, got {found}")

    # C, second half: control A must FAIL when handed a scanner that cannot see. A
    # stripper that blanks everything is what an over-eager comment lexer degrades into,
    # and it would make every scan below it pass while reading nothing.
    blind = positive_control(strip=lambda text, lang: "")
    if len(blind) != len(SENTINELS):
        failures += 1
        print("  FAIL  the positive control does not detect a blind scanner")
        print(f"        expected {len(SENTINELS)} failures from a stripper that returns "
              f"nothing, got {len(blind)}")

    # And it must PASS against the real tree, or the check above proves nothing about
    # the real run: a control that always fails is not a control either.
    live = positive_control()
    if live:
        failures += 1
        print("  FAIL  the positive control does not pass against the real tree")
        for message in live:
            print(f"        {message}")

    # Every scanned surface still resolves to files.
    _, empty = collect_files()
    if empty:
        failures += 1
        print(f"  FAIL  a scanned surface produced no files: {', '.join(empty)}")

    if failures:
        sys.exit(f"  !     {failures} self-test failure(s): this gate cannot be trusted")
    print(f"  ok    self-test: {len(SELF_TESTS) + 3} cases — the scanner still fires on a "
          f"field, still ignores a comment, and still fails when blinded")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()
    else:
        main()
