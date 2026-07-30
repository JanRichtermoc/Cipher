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

# -mod=mod: govulncheck resolves the module graph, which a vendored tree cannot
# answer for. It does not modify anything — the check below proves that.
before="$(shasum -a 256 go.mod go.sum | shasum -a 256)"

echo "  using govulncheck $GOVULNCHECK_VERSION"
if ! GOFLAGS=-mod=mod go run "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" ./...; then
  cat >&2 <<'EOF'

FAILED: a reachable vulnerability is present in the relay's dependencies.

  Fix it, do not silence it:
    cd server && go get <module>@<fixed version> && go mod tidy && go mod vendor
  Then re-run this gate and Scripts/verify-relay.sh (the vendor tree changed).
EOF
  exit 1
fi

after="$(shasum -a 256 go.mod go.sum | shasum -a 256)"
if [ "$before" != "$after" ]; then
  echo "FAILED: the scan modified go.mod or go.sum; a gate must not rewrite the tree." >&2
  exit 1
fi

echo "  ok    no reachable vulnerability in the relay dependency tree"
