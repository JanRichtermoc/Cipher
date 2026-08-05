#!/usr/bin/env python3
#
# Keep first-party instructions and current documentation honest about key custody.
#
# Cipher's relay intentionally stores public identity and prekey material. Private E2E
# identity, prekey, session and ratchet keys remain on-device. Separately, the relay host
# necessarily holds operational material such as TLS private keys and service configuration.
# Collapsing those three categories into "keys" gives future agents a false security boundary.
#
# Copyright (C) 2026 Jan Richter
# SPDX-License-Identifier: AGPL-3.0-only

import subprocess
import sys
from pathlib import Path


RETIRED = [
    ("never plaintext or keys", "public messaging keys are intentionally stored by the relay"),
    ("never keys, never plaintext", "public messaging keys are intentionally stored by the relay"),
    ("keys never touch the server", "public messaging keys and operational server keys do"),
    ("keys never reach the server", "public messaging keys are published to the relay"),
    ("total tls break yields ciphertext only", "TLS also carries credentials, public keys and metadata"),
]

# The most authoritative boundaries must state the replacement, not merely avoid the old words.
REQUIRED = {
    "CLAUDE.md": (
        "public identity and prekey material",
        "private e2e",
        "tls private keys",
    ),
    "docs/CLAUDE_IMPLEMENTATION_PLAN.md": (
        "public identity and prekey material",
        "private e2e",
        "tls private keys",
    ),
    "docs/THREAT_MODEL.md": (
        "public identity and prekey material",
        "private e2e",
        "tls private keys",
    ),
    "docs/BACKEND.md": (
        "public identity/prekey material",
        "private e2e",
        "tls private keys",
    ),
}

EXCLUDED_PREFIXES = ("Pods/", "server/vendor/", "Vendor/bundle/", "docs/STEP_NOTES/")
EXCLUDED_FILES = {"docs/SECURITY_AUDIT.md"}


def analyse(documents):
    findings = []
    for path, text in sorted(documents.items()):
        folded = text.casefold()
        for phrase, why in RETIRED:
            if phrase in folded:
                findings.append(f"{path}: retired key-boundary claim {phrase!r} — {why}")

    for path, phrases in REQUIRED.items():
        text = documents.get(path)
        if text is None:
            findings.append(f"{path}: required canonical document was not scanned")
            continue
        folded = text.casefold()
        for phrase in phrases:
            if phrase not in folded:
                findings.append(f"{path}: missing required boundary phrase {phrase!r}")
    return findings


def tracked_documents():
    result = subprocess.run(
        [
            "git",
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            "*.md",
            "*.mdc",
        ],
        check=True,
        stdout=subprocess.PIPE,
    )
    paths = [path for path in result.stdout.decode().split("\0") if path]
    paths = [
        path
        for path in paths
        if path not in EXCLUDED_FILES
        and not any(path.startswith(prefix) for prefix in EXCLUDED_PREFIXES)
    ]
    if not paths:
        raise SystemExit("no first-party Markdown documents were scanned")
    return {path: Path(path).read_text(encoding="utf-8") for path in paths}


def clean_documents():
    return {
        path: (
            "Public identity and prekey material is published. Private E2E keys stay local. "
            "TLS private keys are operational."
        )
        if path != "docs/BACKEND.md"
        else (
            "Public identity/prekey material is stored. Private E2E keys stay local. "
            "TLS private keys are operational."
        )
        for path in REQUIRED
    }


def self_test():
    failures = 0
    for phrase, _ in RETIRED:
        documents = clean_documents()
        documents["README.md"] = f"The relay {phrase}."
        findings = analyse(documents)
        if not any(phrase in finding for finding in findings):
            failures += 1
            print(f"  FAIL  retired phrase {phrase!r} was not detected")

    documents = clean_documents()
    del documents["CLAUDE.md"]
    if not any("required canonical document was not scanned" in finding for finding in analyse(documents)):
        failures += 1
        print("  FAIL  missing canonical document was not detected")

    clean = analyse(clean_documents())
    if clean:
        failures += 1
        print(f"  FAIL  positive control produced findings: {clean}")

    if failures:
        raise SystemExit(1)
    print(f"  ok    self-test: {len(RETIRED) + 2} cases — retired and missing boundaries still fail")


def main():
    documents = tracked_documents()
    findings = analyse(documents)
    if findings:
        print(f"  !     {len(findings)} finding(s)")
        for finding in findings:
            print(f"        {finding}")
        raise SystemExit(1)
    print(
        f"  ok    {len(documents)} current first-party documents distinguish public, private E2E, "
        "and operational server keys"
    )


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        self_test()
    elif len(sys.argv) == 1:
        main()
    else:
        raise SystemExit("usage: verify-doc-key-boundary.py [--self-test]")
