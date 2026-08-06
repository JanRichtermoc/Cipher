#!/bin/bash
#
# Gate: no known vulnerability in the binary the relay image actually ships.
#
# Copyright (C) 2026 Jan Richter
# SPDX-License-Identifier: AGPL-3.0-only
#
# # Why this is not covered by Scripts/verify-vulns.sh
#
# That gate scans the *source*, under the toolchain `server/go.mod` declares.
# This one scans the *artifact*, under whatever toolchain built it — and on this
# tree those are not the same Go. The `go` directive is a minimum, not a
# selection: go.mod declares 1.25.12 while the Dockerfile's build stage is pinned
# to a golang:1.26.5-alpine digest, so the binary that ships to the staging box
# carries 1.26.5's standard library and nothing was asking that library any
# questions.
#
# Most of what a Go vulnerability scan finds is in the standard library
# (AUDIT 1.13 records exactly this: the same tree reported clean on one Go and 21
# reachable vulnerabilities on another). A gate that scans a stdlib the release
# does not contain is answering a question nobody asked.
#
# The images are pinned by digest, so neither of those versions moves on its own.
# What moves is a deliberate bump to one of them, and this gate is what makes the
# consequences of bumping one and not the other visible.
#
# # Why the image and not the compose stack
#
# `scratch` plus one static binary means the image *is* the binary: there is no
# libc, no package manager, and no distribution packages for a scanner to
# enumerate. Extracting `/relay` and scanning it covers the whole runtime image.
#
# Postgres and Redis are a different question and deliberately out of scope here:
# they are third-party images, pinned by digest, and scanning them needs a
# container-image scanner this repository does not depend on. Recorded as a
# residual in docs/AUDIT.md 5.28 rather than papered over.
#
# # Binary mode still sees reachable symbols, and that was checked rather than
# # assumed
#
# The relay is linked with `-ldflags='-s -w'`, which is the obvious reason to
# expect this scan to be blind — and it would make "No vulnerabilities found" the
# output of a scanner that could not see, which is the failure mode AUDIT R2 is
# about. It is not: `-s -w` drops the DWARF and the classic symbol table, while
# govulncheck reads the module metadata and the `pclntab` that a Go binary keeps
# regardless.
#
# Measured, 2026-08-06: a probe built with the same flags under go1.24.0 was
# reported as affected by 44 standard-library vulnerabilities, naming reachable
# symbols (`internal.chunkedReader.Read`, `http.ProxyFromEnvironment`), and
# govulncheck exited 3. So a clean report here is a fact about the artifact.
#
# Usage:
#   Scripts/verify-image-vulns.sh              # build, extract, scan
#   Scripts/verify-image-vulns.sh --self-test  # prove the scan cannot pass vacuously

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER="$REPO_ROOT/server"

# Pinned, and the same version Scripts/verify-vulns.sh uses. Bump both together
# in a reviewed commit; `@latest` inside a security gate executes whatever that
# path resolves to today.
GOVULNCHECK_VERSION="v1.1.4"

IMAGE_TAG="cipher-relay:vulnscan"

export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/local/go/bin:$PATH"

SELF_TEST=0
for arg in "$@"; do
  case "$arg" in
  --self-test) SELF_TEST=1 ;;
  *)
    echo "unknown option: $arg" >&2
    exit 2
    ;;
  esac
done

fail() {
  printf 'FAILED: %s\n' "$1" >&2
  exit 1
}

command -v go >/dev/null 2>&1 ||
  fail "the Go toolchain is not on PATH, so no image scan ran.

  Fatal rather than skipped: a gate that passes because it could not run is the
  failure docs/AUDIT.md 1.9, 5.12 and 6.14 all record."

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- Self-test ---------------------------------------------------------------
#
# Every assertion below is "the scanner found nothing", and "found nothing" is
# also what a scanner that was handed an empty file prints. These cases prove the
# two ways that could happen are refused (AUDIT R2).
#
# Detection itself is deliberately NOT self-tested here, and the reason is a
# trade rather than an omission: proving it needs a binary built by a
# known-vulnerable toolchain, and the only honest way to have one is to download
# an old Go on every run. A gate that pulls an obsolete toolchain from the
# network is slow, needs the network to say anything at all, and leaves a
# vulnerable compiler in the module cache of every machine that runs it.
#
# It was proved once, by hand, and the result is recorded at the top of this file
# and in docs/AUDIT.md 5.28: 44 standard-library vulnerabilities reported against
# a stripped go1.24.0 build, exit status 3.
self_test() {
  local cases=0 rc

  # A binary that is not there must fail, not scan nothing.
  rc=0
  scan_binary "$WORK/does-not-exist" >/dev/null 2>&1 || rc=$?
  [ "$rc" -ne 0 ] || fail "the scan reported success for a binary that does not exist"
  cases=$((cases + 1))

  # An empty file is the shape a broken `docker cp` leaves behind: present,
  # readable, zero bytes. govulncheck cannot parse it, and that must be an
  # error rather than a clean report.
  : >"$WORK/empty"
  rc=0
  scan_binary "$WORK/empty" >/dev/null 2>&1 || rc=$?
  [ "$rc" -ne 0 ] || fail "the scan reported success for an empty file"
  cases=$((cases + 1))

  # And a non-Go binary, which is what extracting the wrong path would produce.
  printf 'not a go binary at all\n' >"$WORK/text"
  rc=0
  scan_binary "$WORK/text" >/dev/null 2>&1 || rc=$?
  [ "$rc" -ne 0 ] || fail "the scan reported success for a file that is not a Go binary"
  cases=$((cases + 1))

  # The build-info reader is the other half: it is what proves the artifact is
  # the relay and names the toolchain that produced it. It must refuse the same
  # three inputs rather than printing an empty version.
  rc=0
  binary_go_version "$WORK/text" >/dev/null 2>&1 || rc=$?
  [ "$rc" -ne 0 ] || fail "the build-info reader accepted a file that is not a Go binary"
  cases=$((cases + 1))

  echo "  ok    self-test: $cases cases — the image scan cannot pass without an artifact"
}

# scan_binary runs govulncheck against one file.
#
# `-mode=binary` reads the module metadata Go embeds; it does not compile
# anything and does not need the source tree, which is what makes it usable
# against an extracted artifact.
scan_binary() {
  local binary="$1"
  [ -s "$binary" ] || {
    echo "the artifact is missing or empty: $binary" >&2
    return 1
  }
  go run "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" -mode=binary "$binary"
}

# binary_go_version prints the toolchain recorded in a Go binary.
#
# `go version -m` exits 0 and prints nothing useful for a file it does not
# recognise, so the output is checked rather than the status — the same trap
# AUDIT 6.8 records for `docker compose port`.
binary_go_version() {
  local binary="$1" line
  line="$(go version "$binary" 2>/dev/null || true)"
  case "$line" in
  *": go"[0-9]*) ;;
  *)
    echo "not a recognisable Go binary: $binary" >&2
    return 1
    ;;
  esac
  printf '%s\n' "${line##*: }"
}

if [ "$SELF_TEST" -eq 1 ]; then
  self_test
  exit 0
fi

# --- The real artifact -------------------------------------------------------
command -v docker >/dev/null 2>&1 ||
  fail "docker is not on PATH, so the shipping image was not scanned."
docker info >/dev/null 2>&1 ||
  fail "the docker daemon is not running, so the shipping image was not scanned."

self_test

echo "  building the relay image"
docker build --quiet -t "$IMAGE_TAG" "$SERVER" >/dev/null ||
  fail "the relay image did not build, so there was nothing to scan"

# `scratch` has no shell, so the binary is lifted out of a created (never
# started) container rather than read with `docker run cat`.
container="$(docker create "$IMAGE_TAG")" ||
  fail "could not create a container from the relay image"
# shellcheck disable=SC2064  # $container is expanded now, on purpose.
trap "docker rm -f '$container' >/dev/null 2>&1 || true; rm -rf '$WORK'" EXIT

docker cp "$container:/relay" "$WORK/relay" >/dev/null ||
  fail "could not extract /relay from the image"

image_go="$(binary_go_version "$WORK/relay")" ||
  fail "the extracted artifact is not a Go binary, so the scan would have proved nothing"
declared_go="$(awk '$1 == "go" { print $2; exit }' "$SERVER/go.mod")"

echo "  the shipping binary was built with $image_go"
echo "  (source-mode scanning uses go$declared_go, the go.mod directive)"

echo "  using govulncheck $GOVULNCHECK_VERSION in binary mode"
if ! scan_binary "$WORK/relay"; then
  cat >&2 <<EOF

FAILED: the binary inside the relay image has a known vulnerability.

  This is the artifact that reaches the staging box, so it cannot be resolved by
  changing what the source-mode scan looks at. Read the 'Found in:' line of each
  entry above:

  1. "Standard library" — the fix is the BUILD STAGE, not server/go.mod. Repin
     the builder image in server/Dockerfile to a golang tag whose Go version is
     at or above the highest 'Fixed in:' the report names, and record the tag in
     the comment beside the digest:
       docker pull golang:<version>-alpine
       docker inspect --format='{{index .RepoDigests 0}}' golang:<version>-alpine

  2. A module — fix it in the module graph, then re-vendor:
       cd server && go get <module>@<fixed version> && go mod tidy && go mod vendor

  Then re-run this gate and Scripts/verify-relay.sh.
EOF
  exit 1
fi

echo "  ok    no known vulnerability in the binary the relay image ships"
