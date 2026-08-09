#!/usr/bin/env python3
"""Gate: the deployed nginx configuration cannot log what the threat model forbids.

Copyright (C) 2026 Jan Richter
SPDX-License-Identifier: AGPL-3.0-only

Why this exists (AUDIT 5.29)
----------------------------
The relay's TLS virtual host set a deliberately minimal log format and a 24-hour
rotation. Its two siblings — the port-80 redirect and the catch-all default server —
set nothing, and *inherited* nginx.conf's http-level ``access_log
/var/log/nginx/access.log;``. No format is named there, so nginx uses its built-in
**combined**: client IP, the full request line, the referrer and the user agent. Stock
Ubuntu logrotate then keeps ``/var/log/nginx/*.log`` for fourteen daily generations.

So the two endpoints an unauthenticated scanner reaches first retained, for a fortnight,
exactly what ``httpx.pattern()`` strips from application logs. ``GET /v1/keys/<uuid>``
over http:// is a metadata record naming who was looked up; redirecting it to HTTPS does
not stop it having been written down first.

The configuration was correct in the place someone had thought about and wrong in the
two places nobody had, which is what a gate is for. It reads the committed files rather
than the live box on purpose: a check that needs SSH cannot run in CI, and a gate that
cannot run is a gate that gets removed (AUDIT R2). Whether the box matches these files is
a separate, operator-run comparison — see docs/RUNBOOK-VPS.md §H.6.
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "server" / "deploy" / "nginx"
SITE = DEPLOY / "cipher.conf"
HARDENING = DEPLOY / "00-cipher-hardening.conf"

# Variables that must never appear in a log format. Each identifies a request rather
# than describing one: the path names who was fetched, and the agent and referrer are
# fingerprinting surface with no triage value for a native-app API.
FORBIDDEN_LOG_VARIABLES = ("$request", "$request_uri", "$http_user_agent", "$http_referer")

# nginx's built-in format, which contains all of the above. Naming it is the same defect
# as writing them out, and inheriting it is how this happened without anyone naming it.
FORBIDDEN_FORMAT = "combined"

# The stock logrotate globs this directory at `rotate 14`, so anything written here has a
# fourteen-day life whatever the config claims.
FORBIDDEN_LOG_DIRECTORY = "/var/log/nginx/"


def strip_comments(text: str) -> str:
    """Replace `#` comment bytes with spaces, preserving every offset.

    Required, not tidiness (AUDIT **R3**). The configuration files carry paragraphs
    explaining why `combined`, `$request` and `$http_user_agent` must not be logged —
    naming each one. A scanner that read comments would fire on the documentation of the
    rule it enforces, which is a gate that cries wolf and therefore a gate that is
    deleted.
    """
    out = []
    for line in text.split("\n"):
        hash_at = line.find("#")
        if hash_at >= 0:
            line = line[:hash_at] + " " * (len(line) - hash_at)
        out.append(line)
    return "\n".join(out)


def server_blocks(text: str) -> list[str]:
    """Return the body of every `server { ... }` block, by brace matching.

    Brace matching rather than a regex: a regex either stops at the first `}` — which is
    the end of a `location` block, not the server — or runs to the last one and returns
    the whole file as a single block. Both read as "every server has an access_log".
    """
    blocks = []
    for match in re.finditer(r"\bserver\s*\{", text):
        depth = 0
        start = match.end()
        for index in range(match.end() - 1, len(text)):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    blocks.append(text[start:index])
                    break
    return blocks


def check(site_text: str, hardening_text: str) -> list[str]:
    """Return a list of problems; empty means the configuration is sound."""
    problems: list[str] = []
    site = strip_comments(site_text)
    hardening = strip_comments(hardening_text)

    blocks = server_blocks(site)
    if not blocks:
        problems.append("no server blocks were found at all — the parse did not work")

    for number, body in enumerate(blocks, start=1):
        # Nested blocks have their own directives; an access_log inside a `location`
        # does not cover the rest of the server, so only the block's own level counts.
        own_level = re.sub(r"\{[^{}]*\}", " ", body)
        while re.search(r"\{[^{}]*\}", own_level):
            own_level = re.sub(r"\{[^{}]*\}", " ", own_level)

        name = re.search(r"server_name\s+([^;]+);", body)
        label = f"server #{number} ({name.group(1).strip() if name else 'unnamed'})"

        if not re.search(r"\baccess_log\b", own_level):
            problems.append(
                f"{label} sets no access_log, so it inherits nginx.conf's — which is the "
                f"combined format in {FORBIDDEN_LOG_DIRECTORY}, kept for 14 days"
            )

    for label, text in (("cipher.conf", site), ("00-cipher-hardening.conf", hardening)):
        for directive in re.findall(r"\baccess_log\s+([^;]+);", text):
            if FORBIDDEN_FORMAT in directive.split():
                problems.append(f"{label}: an access_log names the '{FORBIDDEN_FORMAT}' format")
            if FORBIDDEN_LOG_DIRECTORY in directive:
                problems.append(
                    f"{label}: an access_log writes into {FORBIDDEN_LOG_DIRECTORY}, where the "
                    f"stock logrotate keeps it for 14 days"
                )

    formats = re.findall(r"\blog_format\s+(\S+)\s+([^;]+);", hardening)
    if not formats:
        problems.append("00-cipher-hardening.conf defines no log_format")
    for format_name, body in formats:
        for variable in FORBIDDEN_LOG_VARIABLES:
            # Word-boundary aware: $request must not match inside $request_time, which is
            # a duration and carries no identity.
            if re.search(re.escape(variable) + r"(?![A-Za-z0-9_])", body):
                problems.append(
                    f"log_format '{format_name}' includes {variable}, which identifies the request"
                )

    if not re.search(r"\bserver_tokens\s+off\s*;", hardening):
        problems.append(
            "00-cipher-hardening.conf does not set 'server_tokens off' at http level, so "
            "servers that do not set it themselves disclose the nginx version"
        )

    # --- The TLS floor (AUDIT 5.16) -------------------------------------------------------
    #
    # nginx negotiates the TLS version from the DEFAULT server's context for the listening
    # socket, before SNI selects a virtual server, so `ssl_protocols` in the relay block alone
    # is applied too late to refuse anything: Ubuntu's nginx.conf governs the socket and the
    # server accepts 1.2 while the file reads as 1.3-only. `nginx -t` passes either way, which
    # is precisely why this needs a check rather than a review.
    protocols = re.findall(r"\bssl_protocols\s+([^;]+);", site)
    if not protocols:
        problems.append(
            "cipher.conf sets no ssl_protocols at all, so the socket inherits the "
            "distribution default, which includes TLS 1.2 (AUDIT 5.16)"
        )
    for value in protocols:
        if value.split() != ["TLSv1.3"]:
            problems.append(
                f"cipher.conf: ssl_protocols is {value.strip()!r} rather than 'TLSv1.3' "
                f"(AUDIT 5.16)"
            )

    default_blocks = [
        body for body in blocks if re.search(r"\blisten\b[^;]*\bdefault_server\b", body)
    ]
    if not default_blocks:
        problems.append(
            "cipher.conf declares no default_server, so an unmatched Host is answered by "
            "whichever server happens to be first — and no block owns the socket's TLS floor"
        )
    for body in default_blocks:
        if not re.search(r"\bssl_protocols\s+TLSv1\.3\s*;", body):
            problems.append(
                "the default server does not set 'ssl_protocols TLSv1.3', so the TLS floor "
                "for the whole socket comes from nginx.conf (AUDIT 5.16)"
            )

    # --- The client address the relay is allowed to believe (AUDIT 5.15) -------------------
    #
    # `httpx.RealIP` trusts `X-Real-IP` only from `RELAY_TRUSTED_PROXY`, and that is sound only
    # while the proxy *sets* the header from the connection rather than passing along whatever
    # the client sent. Change `$remote_addr` to a `$http_` variable and one caller can mint a
    # fresh rate-limit bucket per request — the naive fix that is worse than the bug.
    for number, body in enumerate(blocks, start=1):
        if "proxy_pass" not in body:
            continue
        values = re.findall(r"\bproxy_set_header\s+X-Real-IP\s+([^;]+);", body)
        if not values:
            problems.append(
                f"server #{number} proxies to the relay without setting X-Real-IP, so every "
                f"request reaches it as the proxy's own address (AUDIT 5.15)"
            )
        for value in values:
            if value.strip() != "$remote_addr":
                problems.append(
                    f"server #{number}: X-Real-IP is set from {value.strip()!r} rather than "
                    f"$remote_addr; a client-supplied value would become the rate-limit "
                    f"subject (AUDIT 5.15)"
                )

    return problems


def self_test() -> int:
    """Reintroduce each defect and require the check to fire.

    Every assertion above is "a pattern is present" or "a pattern is absent", which is
    the shape that reports a clean result once it has stopped working (AUDIT **R2**).
    """
    good_site = """
        server {
            listen 443 ssl default_server;
            server_name _;
            ssl_protocols TLSv1.3;
            access_log off;
            return 444;
        }
        server {
            server_name relay.example;
            access_log off;
            location / { return 301 https://$host$request_uri; }
        }
        server {
            listen 443 ssl;
            server_name relay.example;
            ssl_protocols TLSv1.3;
            access_log /var/log/cipher/cipher-access.log minimal;
            proxy_set_header X-Real-IP $remote_addr;
            location / { proxy_pass http://127.0.0.1:8080; }
        }
    """
    good_hardening = """
        log_format minimal '$remote_addr $request_method $status $body_bytes_sent $request_time';
        server_tokens off;
    """

    cases: list[tuple[bool, str, str, str]] = [
        (True, "a correct configuration", good_site, good_hardening),
        # The finding itself, in the two places it actually occurred.
        (False, "the redirect server inheriting the http-level log",
         good_site.replace("            access_log off;\n            location / { return 301", "            location / { return 301"),
         good_hardening),
        (False, "the default server inheriting the http-level log",
         good_site.replace("            access_log off;\n            return 444;", "            return 444;"),
         good_hardening),
        # And the ways the same disclosure could be reintroduced deliberately.
        (False, "an access_log naming the combined format",
         good_site.replace("access_log off;\n            return 444;",
                           "access_log /var/log/cipher/x.log combined;\n            return 444;"),
         good_hardening),
        (False, "an access_log under /var/log/nginx",
         good_site.replace("/var/log/cipher/cipher-access.log", "/var/log/nginx/access.log"),
         good_hardening),
        (False, "a log format carrying the request path",
         good_site,
         good_hardening.replace("$remote_addr", "$remote_addr $request")),
        (False, "a log format carrying the user agent",
         good_site,
         good_hardening.replace("$remote_addr", "$remote_addr $http_user_agent")),
        (False, "a log format carrying the referrer",
         good_site,
         good_hardening.replace("$remote_addr", "$remote_addr $http_referer")),
        (False, "server_tokens left at its default",
         good_site,
         good_hardening.replace("server_tokens off;", "")),
        (False, "no log_format at all", good_site, "server_tokens off;"),
        (False, "a site file with no server blocks", "", good_hardening),
        # AUDIT 5.16, in the shape it actually occurred: the relay block keeps its floor and
        # the default server — the one that owns the socket — loses it. `nginx -t` is happy.
        (False, "the default server without a TLS floor",
         good_site.replace("            ssl_protocols TLSv1.3;\n            access_log off;\n"
                           "            return 444;",
                           "            access_log off;\n            return 444;"),
         good_hardening),
        (False, "a server re-admitting TLS 1.2",
         good_site.replace("ssl_protocols TLSv1.3;", "ssl_protocols TLSv1.2 TLSv1.3;"),
         good_hardening),
        (False, "no default_server at all",
         good_site.replace("listen 443 ssl default_server;", "listen 443 ssl;"),
         good_hardening),
        # AUDIT 5.15. The first is the relay seeing only the proxy; the second is the naive
        # fix that is worse than the bug, because the header becomes client-controlled.
        (False, "the proxied server not setting X-Real-IP",
         good_site.replace("            proxy_set_header X-Real-IP $remote_addr;\n", ""),
         good_hardening),
        (False, "X-Real-IP taken from a client-supplied header",
         good_site.replace("X-Real-IP $remote_addr;", "X-Real-IP $http_x_forwarded_for;"),
         good_hardening),
    ]

    failures = 0
    for want_ok, description, site, hardening in cases:
        problems = check(site, hardening)
        if want_ok and problems:
            print(f"  FAIL  self-test: {description} was refused: {problems}", file=sys.stderr)
            failures += 1
        if not want_ok and not problems:
            print(f"  FAIL  self-test: {description} was accepted", file=sys.stderr)
            failures += 1

    # R3: the real files explain the rule using the very tokens it forbids. A scanner
    # that read comments would refuse the configuration it is meant to approve.
    commented = good_hardening + "\n# Deliberately absent: $request, $http_user_agent, combined.\n"
    if check(good_site, commented):
        print("  FAIL  self-test: a comment naming the forbidden variables fired the check",
              file=sys.stderr)
        failures += 1

    # And the parser must see each server separately rather than the file as one block.
    if len(server_blocks(strip_comments(good_site))) != 3:
        print("  FAIL  self-test: server blocks are not being parsed individually", file=sys.stderr)
        failures += 1

    total = len(cases) + 2
    if failures:
        print(f"SELF-TEST FAILED ({failures} of {total})", file=sys.stderr)
        return 1
    print(f"  ok    self-test: {total} cases — every nginx logging, TLS-floor and "
          f"client-address rule still fails on its defect")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true",
                        help="reintroduce each defect and require the check to fire")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    for path in (SITE, HARDENING):
        if not path.is_file():
            print(f"FAILED: missing {path.relative_to(ROOT)}", file=sys.stderr)
            return 1

    problems = check(SITE.read_text(), HARDENING.read_text())
    if problems:
        for problem in problems:
            print(f"  FAIL  {problem}", file=sys.stderr)
        print("\nSee docs/AUDIT.md 5.29 and THREAT_MODEL.md §3.6.", file=sys.stderr)
        return 1

    blocks = len(server_blocks(strip_comments(SITE.read_text())))
    print(f"  ok    {blocks} nginx server blocks each set their own access_log; "
          f"no combined format, no /var/log/nginx, server_tokens off; the default server "
          f"holds the TLS 1.3 floor and X-Real-IP comes from the connection")
    return 0


if __name__ == "__main__":
    sys.exit(main())
