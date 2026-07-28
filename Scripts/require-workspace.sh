#!/bin/bash
#
# Build guard: refuse to build from the bare Cipher.xcodeproj.
#
# Opening Cipher.xcodeproj instead of Cipher.xcworkspace leaves the Pods project
# out of the build graph. The pod xcconfigs are still applied (they are attached
# at project level), so every search path looks correct and nothing reports a
# missing dependency — the build simply fails deep inside the crypto module with
#
#     CipherCrypto/Sources/Engine/IsolationContract.swift:10:8:
#     error: no such module 'LibSignalClient'
#
# which points at a file that is not the problem. This phase turns that into a
# one-line instruction.
#
# Copyright (C) 2026 Jan Richter
# SPDX-License-Identifier: AGPL-3.0-only

set -euo pipefail

# WORKSPACE_DIR names the container Xcode is building from. With an explicit
# workspace it is the directory that holds the .xcworkspace; with a bare project
# it is the .xcodeproj bundle itself, because Xcode wraps a lone project in an
# implicit workspace of the same name.
#
# The check is deliberately fail-open: if a future Xcode stops exporting this
# variable, or exports it in a shape we do not recognise, the guard says nothing
# and the build proceeds exactly as it does today. A guard for a developer
# ergonomics problem must never be able to break a correct build.
case "${WORKSPACE_DIR:-}" in
*.xcodeproj)
    cat >&2 <<EOF
error: Cipher must be built from Cipher.xcworkspace, not Cipher.xcodeproj.

  Building the bare project leaves CocoaPods' Pods project out of the build
  graph, so LibSignalClient.framework is never produced and CipherCrypto fails
  with "no such module 'LibSignalClient'".

  In Xcode:  close this window and open Cipher.xcworkspace
  From CLI:  xcodebuild -workspace Cipher.xcworkspace -scheme CipherCrypto ...

  If the workspace itself is missing or stale, regenerate it:
      bundle exec pod install
EOF
    exit 1
    ;;
esac

exit 0
