#!/bin/bash
#
# Gate: no known vulnerability in the relay's dependency tree that our code
# actually reaches.
#
# Copyright (C) 2026 Jan Richter
# SPDX-License-Identifier: AGPL-3.0-only
#
# # Why this exists
#
# `golang.org/x/text` shipped an infinite-loop bug (CVE-2026-56852) reachable
# through pgx's connection path, and it sat in `server/go.mod` for the whole of
# P4 and most of P5. Nothing in this repository would ever have noticed: the
# supply-chain gate verifies that dependencies are the ones we *pinned*, which is
# a different question from whether what we pinned is safe. Dependabot watches
# GitHub Actions only, deliberately (AUDIT 1.8).
#
# # Why `govulncheck` and not a scanner
#
# It matches on *reachable symbols*, not on module versions, so it does not
# report a vulnerability in a package we vendor and never call. That is the
# difference between a gate someone acts on and a list someone learns to ignore.
#
# # Why the version is pinned
#
# `go run pkg@latest` inside a security gate is a supply-chain hole in the shape
# of a convenience: it executes whatever that path resolves to today, with the
# repository checked out. The version below is bumped deliberately, like every
# other pin in this tree.
#
# Needs the network: the vulnerability database is fetched at run time. That is
# why `verify-all.sh --offline` skips it, and why skipping is announced rather
# than silent.
#
# # Why the toolchain is pinned too, and not just govulncheck
#
# Most of what this gate finds is in the **standard library**, which means the
# answer depends on which Go compiled the code. It scanned whatever was on the
# developer's PATH, so the same tree reported "No vulnerabilities found" on a
# machine with Go 1.26.5 and 21 reachable vulnerabilities in CI, which installs
# the version `server/go.mod` declares. A green local run was not evidence of
# anything, and the gate could not have caught the finding it exists to catch.
#
# It now scans under exactly the version go.mod declares — the same one CI
# installs and the release binary is built with. The declared version is the
# subject of the check, so reading it from the file is the point rather than a
# convenience: bumping go.mod is what moves this gate. AUDIT 1.13.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER="$REPO_ROOT/server"

# Pinned. Bump in a reviewed commit, never automatically.
GOVULNCHECK_VERSION="v1.1.4"

export PATH="/opt/homebrew/bin:/usr/local/go/bin:$PATH"

if ! command -v go >/dev/null 2>&1; then
  echo "FAILED: the Go toolchain is not on PATH, so no vulnerability scan ran." >&2
  exit 1
fi

cd "$SERVER"

# The `go` directive, which is this module's toolchain pin. `awk` on a 20-line
# file rather than a `grep | head` pipeline: R1 (AUDIT §0) — a consumer that
# exits early closes the pipe, and under `set -o pipefail` a succeeding pipeline
# then fails on Linux but not on macOS.
DECLARED_GO="$(awk '$1 == "go" { print $2; exit }' go.mod)"

# A partial version (`1.25`) names no released toolchain, so GOTOOLCHAIN would
# fail to resolve it. Refused loudly instead of falling back to the PATH Go:
# falling back is precisely the behaviour that made this gate report a false
# pass, and a check that cannot do its job must say so rather than run a
# weaker one quietly (R2).
if [[ ! "$DECLARED_GO" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  cat >&2 <<EOF
FAILED: server/go.mod declares go '$DECLARED_GO', which is not a full
        version, so this gate cannot pin the toolchain it must scan under.

  Write a complete version (for example 'go 1.25.13'). A two-part version
  names no released toolchain, and scanning under whatever Go happens to be
  installed is how a standard-library vulnerability reaches CI unnoticed.
EOF
  exit 1
fi

# Scan under the version the module declares, not the one on PATH. Downloaded on
# first use, like the vulnerability database itself.
export GOTOOLCHAIN="go$DECLARED_GO"
echo "  scanning under the toolchain go.mod declares: $GOTOOLCHAIN"

# -mod=mod: govulncheck resolves the module graph, which a vendored tree cannot
# answer for. It does not modify anything — the check below proves that.
before="$(shasum -a 256 go.mod go.sum | shasum -a 256)"

echo "  using govulncheck $GOVULNCHECK_VERSION"
if ! GOFLAGS=-mod=mod go run "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" ./...; then
  cat >&2 <<EOF

FAILED: a reachable vulnerability is present in the relay's dependencies.

  Fix it, do not silence it. Which fix depends on where the finding is, and the
  report above says so on every entry — read the 'Found in:' line before acting:

  1. "Standard library" (Found in: crypto/tls@go1.xx, net/url@go1.xx, ...)
     No amount of 'go get' touches this: the stdlib comes from the toolchain,
     not from the module graph. Raise the 'go' directive in server/go.mod to
     the highest 'Fixed in:' version the report names, which is what this gate
     and CI both install:
       server/go.mod:  go $DECLARED_GO  ->  go <highest fixed version>

  2. A module (Found in: some.host/module@vX.Y.Z)
       cd server && go get <module>@<fixed version> && go mod tidy && go mod vendor

  Then re-run this gate. Re-run Scripts/verify-relay.sh too if the vendor tree
  changed (case 2 always changes it; case 1 usually does not).
EOF
  exit 1
fi

after="$(shasum -a 256 go.mod go.sum | shasum -a 256)"
if [ "$before" != "$after" ]; then
  echo "FAILED: the scan modified go.mod or go.sum; a gate must not rewrite the tree." >&2
  exit 1
fi

echo "  ok    no reachable vulnerability in the relay dependency tree"
