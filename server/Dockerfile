# Cipher relay container.
#
# Copyright (C) 2026 Jan Richter
# SPDX-License-Identifier: AGPL-3.0-only
#
# Base images are pinned by DIGEST, not by tag. A tag is a pointer its publisher
# can move, which is exactly what docs/AUDIT.md 1.8 records for GitHub Actions and
# 1.3 for libsignal — and a base image has the largest blast radius of the three,
# because everything in it runs as the service. Resolved from the registry on
# 2026-07-29; the tag is kept in a comment so the intended version is legible.
#
# ---------------------------------------------------------------------------
# Build stage
# ---------------------------------------------------------------------------
FROM golang@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
# golang:1.26.5-alpine

WORKDIR /src

# vendor/ is committed, so the build needs no network at all. That is the point:
# a build that cannot reach the internet cannot pull a substituted dependency,
# and the bytes that go into the binary are the bytes in the diff.
COPY go.mod go.sum ./
COPY vendor/ vendor/
COPY cmd/ cmd/
COPY internal/ internal/

# CGO_ENABLED=0 produces a static binary, which is what makes a `scratch` runtime
# image possible. There is no libc to keep patched because there is no libc.
#
# -trimpath removes build-machine filesystem paths from the binary; they would
# otherwise appear in panic traces and leak the layout of whoever built it.
#
# -buildvcs=false keeps the git revision out of the binary. Version information
# is reconnaissance (docs/BACKEND.md §1 forbids reporting it), and a binary that
# does not carry it cannot leak it through a stack trace either.
ENV CGO_ENABLED=0 GOFLAGS=-mod=vendor
RUN go build -trimpath -buildvcs=false -ldflags='-s -w' -o /relay ./cmd/relay

# The blob directory is created here, in a stage that has a shell, because the
# runtime stage is `scratch` and cannot run mkdir. It is copied below with an
# explicit owner.
RUN mkdir -p /var/lib/cipher/blobs

# ---------------------------------------------------------------------------
# Runtime stage
# ---------------------------------------------------------------------------
#
# scratch: no shell, no package manager, no coreutils, no libc. An attacker with
# remote code execution in the relay lands in an image containing exactly one
# executable. It also means there is nothing to patch, so the runtime image never
# accrues CVEs of its own.
#
# The cost is that debugging requires attaching a sidecar rather than exec-ing a
# shell, and that the health check has to be the binary itself — `relay
# --health-check`, which exists for this reason.
FROM scratch

# Numeric, because scratch has no /etc/passwd for a name to resolve against.
# 65532 is the conventional "nonroot" id. Running as root in a container is one
# kernel or runtime bug away from being root on the host.
USER 65532:65532

COPY --from=build /relay /relay

# Ships an empty, correctly-owned directory at the blob path.
#
# This is not cosmetic. Docker creates a named volume owned by root:root, and
# mounting one over a path the image does not contain leaves it root-owned — so
# the relay, running as 65532, cannot create its temp directory and crash-loops
# with "mkdir /var/lib/cipher/blobs/tmp: permission denied". When the path DOES
# exist in the image, Docker seeds the empty volume from it and carries the
# ownership across, which is what makes this work.
#
# The integration suite cannot catch this: it runs the package under a golang
# image, not this one. It was found by running the real stack, which is why
# Scripts/verify-relay-integration.sh is not the only thing worth running.
COPY --from=build --chown=65532:65532 /var/lib/cipher/blobs /var/lib/cipher/blobs

EXPOSE 8080

# --health-check probes /health/ready over loopback and exits non-zero when the
# relay cannot reach Postgres or Redis, so `depends_on: service_healthy` means
# what it appears to mean.
HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
    CMD ["/relay", "--health-check"]

ENTRYPOINT ["/relay"]
