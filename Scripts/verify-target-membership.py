#!/usr/bin/env python3
"""Every Swift file on disk is compiled by the target that owns its directory.

`Scripts/verify-app-target-manifest.sh` covers the *app* target, which uses a synchronized
folder and can therefore gain a file with no project edit. The three explicit-membership
targets have the opposite failure and no guard at all: `CipherCrypto`, `CipherCryptoTests`
and `CipherTests` list every file individually in `project.pbxproj`, so a file dropped into
one of those directories joins nothing until `Scripts/bootstrap-targets.rb` is run by hand
(`docs/DEVELOPMENT.md`, "Adding a Swift or test file").

For a source file that is usually loud — the first reference to it fails to compile. For a
**test** file it is silent by construction. A new `XCTestCase` that is not a member of its
target is not compiled, is not run, produces no test name, and changes no total; the full
verification stays green over a security test that never executed. That is the "a successful
zero-test run is a failure" rule (`AUDIT.md` §0, `.claude/rules/verification.md`) applied to
the one direction nothing was checking. AUDIT 6.19.

Read from the committed `project.pbxproj` rather than from a build: the property is whether
the *repository* would run the file, and a local Xcode session that has silently added a
reference is exactly the state this must not accept as evidence.
"""

import json
import os
import subprocess
import sys

PROJECT = "Cipher.xcodeproj/project.pbxproj"

# Directory on disk -> target that must compile everything in it. Written out rather than
# derived from the project file: deriving the expectation from the thing under test is how a
# check stops testing anything (AUDIT R5), and a target quietly renamed should fail here.
TARGETS = {
    "CipherCrypto": "CipherCrypto",
    "CipherCryptoTests": "CipherCryptoTests",
    "CipherTests": "CipherTests",
}


def load_objects(path):
    """The pbxproj as a plain dict. `plutil` is the parser Xcode itself ships."""
    raw = subprocess.run(
        ["plutil", "-convert", "json", "-o", "-", path],
        check=True, capture_output=True, text=True,
    ).stdout
    return json.loads(raw)["objects"]


def compiled_paths(objects, target_name):
    """Every `path` the named target's Sources phase compiles, or None if there is no target.

    `None` is distinct from an empty set on purpose: a target that has vanished is a different
    failure from one that compiles nothing, and reporting the second for the first would send
    a reader looking for deleted files.
    """
    target = next(
        (
            value
            for value in objects.values()
            if value.get("isa") == "PBXNativeTarget" and value.get("name") == target_name
        ),
        None,
    )
    if target is None:
        return None

    paths = set()
    for phase_id in target.get("buildPhases", []):
        phase = objects.get(phase_id, {})
        if phase.get("isa") != "PBXSourcesBuildPhase":
            continue
        for build_file_id in phase.get("files", []):
            file_ref_id = objects.get(build_file_id, {}).get("fileRef")
            if file_ref_id is None:
                continue
            path = objects.get(file_ref_id, {}).get("path")
            if path is not None:
                paths.add(path)
    return paths


def on_disk(directory):
    found = set()
    for root, _, files in os.walk(directory):
        for name in files:
            if name.endswith(".swift"):
                found.add(os.path.relpath(os.path.join(root, name)))
    return found


def analyse(memberships, disks):
    """Return every finding. Split out of main() so --self-test can drive it directly.

    `memberships` maps target name -> set of compiled paths (or None for a missing target);
    `disks` maps directory -> set of paths on disk.
    """
    findings = []
    for directory, target_name in sorted(TARGETS.items()):
        compiled = memberships.get(target_name)
        if compiled is None:
            findings.append(
                f"{PROJECT}: no target named {target_name!r}\n"
                f"          the directory {directory}/ is compiled by nothing."
            )
            continue

        present = disks.get(directory, set())
        missing = sorted(present - compiled)
        stale = sorted(p for p in compiled - present if p.startswith(f"{directory}/"))

        for path in missing:
            findings.append(
                f"{path}: on disk, not a member of {target_name}\n"
                f"          it is never compiled and never runs. Run "
                f"`bundle exec ruby Scripts/bootstrap-targets.rb` and commit the project file."
            )
        for path in stale:
            findings.append(
                f"{path}: a member of {target_name}, missing from disk\n"
                f"          the project references a file that no longer exists. Run "
                f"`bundle exec ruby Scripts/bootstrap-targets.rb` and commit the project file."
            )
    return findings


# --- self-test ---------------------------------------------------------------------------
#
# Both directions and the missing-target case, against synthetic inputs written as literals.
# Deriving them from the real project would mean the cases change whenever the tree does,
# which is the defect AUDIT 6.14 records and R5 restates.

def self_test():
    failures = 0
    cases = [
        (
            "a test file on disk that no target compiles",
            {"CipherCrypto": set(), "CipherCryptoTests": set(), "CipherTests": set()},
            {"CipherTests": {"CipherTests/GhostTests.swift"}},
            "CipherTests/GhostTests.swift: on disk, not a member of CipherTests",
        ),
        (
            "a project reference to a file that was deleted",
            {
                "CipherCrypto": {"CipherCrypto/Sources/Gone.swift"},
                "CipherCryptoTests": set(),
                "CipherTests": set(),
            },
            {},
            "CipherCrypto/Sources/Gone.swift: a member of CipherCrypto, missing from disk",
        ),
        (
            "a target that no longer exists",
            {"CipherCrypto": set(), "CipherCryptoTests": None, "CipherTests": set()},
            {},
            "no target named 'CipherCryptoTests'",
        ),
    ]

    for name, memberships, disks, expected in cases:
        findings = analyse(memberships, disks)
        if not any(expected in f for f in findings):
            failures += 1
            print(f"  FAIL  {name}")
            print(f"        expected a finding containing {expected!r}, got: {findings}")

    # Positive control: a tree where every file is a member must be silent, or "it fails on
    # everything" would read as "it detects everything".
    clean = analyse(
        {
            "CipherCrypto": {"CipherCrypto/Sources/A.swift"},
            "CipherCryptoTests": {"CipherCryptoTests/BTests.swift"},
            "CipherTests": {"CipherTests/CTests.swift"},
        },
        {
            "CipherCrypto": {"CipherCrypto/Sources/A.swift"},
            "CipherCryptoTests": {"CipherCryptoTests/BTests.swift"},
            "CipherTests": {"CipherTests/CTests.swift"},
        },
    )
    if clean:
        failures += 1
        print("  FAIL  positive control: a fully-compiled tree is silent")
        print(f"        expected no findings, got: {clean}")

    # And the parser has to survive the real project file, or every case above would be
    # exercising a comparison that never receives anything. This asserts only that each
    # target resolves to a non-empty set — the counts themselves are the real check's job.
    try:
        objects = load_objects(PROJECT)
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        failures += 1
        print(f"  FAIL  the project file could not be parsed: {error}")
    else:
        for directory, target_name in sorted(TARGETS.items()):
            compiled = compiled_paths(objects, target_name)
            if not compiled:
                failures += 1
                print(f"  FAIL  {target_name} resolved to no compiled files at all")

    if failures:
        sys.exit(f"  !     {failures} self-test failure(s): this gate cannot be trusted")
    print(f"  ok    self-test: {len(cases) + 1 + len(TARGETS)} cases — both drift directions "
          f"fire, a clean tree is silent, and the real project still parses")


def main():
    if not os.path.exists(PROJECT):
        sys.exit(f"  !     {PROJECT} not found; run from the repository root")

    objects = load_objects(PROJECT)
    memberships = {name: compiled_paths(objects, name) for name in TARGETS.values()}
    disks = {directory: on_disk(directory) for directory in TARGETS}

    findings = analyse(memberships, disks)
    if findings:
        print(f"  !     {len(findings)} finding(s)")
        for finding in findings:
            print(f"        {finding}")
        sys.exit(1)

    total = sum(len(paths) for paths in disks.values())
    print(f"  ok    {total} Swift files across {len(TARGETS)} explicit-membership targets, "
          f"each compiled by the target that owns its directory")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()
    else:
        main()
