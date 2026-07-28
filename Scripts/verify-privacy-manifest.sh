#!/bin/bash
#
# Required-reason API gate (AUDIT 6.1).
#
# Apple requires a declared reason for five API categories, and the requirement attaches to
# what is *in the shipped bundle* — not to what the app calls. That distinction is the whole
# problem here: libsignal is a **dynamic** framework, so its entire 18 MB symbol surface
# ships whether or not a single line of Cipher reaches it. Nothing gets dead-stripped, and
# `Cipher.app/Cipher` is clean while the framework beside it is not.
#
# libsignal ships no PrivacyInfo.xcprivacy of its own (Vendor/libsignal/DECISIONS.md, Q2), so
# its usage has to be enumerated and merged into ours. The Swift wrapper can be read; the
# Rust core arrives as a prebuilt .a and cannot. This scans the built Mach-O instead, which
# covers both and is the artifact Apple actually inspects.
#
# What this is sound for, and what it is not:
#
#   SOUND      a C call compiles to an undefined external. `fstat()` cannot be reached
#              without `_fstat` appearing in `nm -u`. For the C half of Apple's lists this
#              is proof, not evidence.
#   NOT SOUND  Swift and Objective-C usage. `url.resourceValues(forKeys: [.creationDateKey])`
#              leaves no reliable literal — the selector may be a symbol reference, and bare
#              names like `creationDate` collide with unrelated strings. So the Foundation
#              half of each list is checked here only for its distinctive spellings, and is
#              covered properly by grepping sources: ours in Cipher/ and CipherCrypto/,
#              libsignal's in Pods/LibSignalClient/swift/. See docs/PRIVACY_MANIFEST.md.
#
# Usage: Scripts/verify-privacy-manifest.sh [path/to/Cipher.app]
#
# Copyright (C) 2026 Jan Richter
# SPDX-License-Identifier: AGPL-3.0-only

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MANIFEST="Cipher/PrivacyInfo.xcprivacy"
APP="${1:-}"
if [ -z "$APP" ]; then
  APP="$(ls -d "$HOME/Library/Developer/Xcode/DerivedData/Cipher-"*/Build/Products/Release-iphoneos/Cipher.app 2>/dev/null | head -1)"
fi
[ -n "$APP" ] && [ -d "$APP" ] || {
  echo "  !     no Release bundle to scan (build one, or pass its path)" >&2
  exit 1
}
[ -f "$MANIFEST" ] || {
  echo "  !     missing $MANIFEST" >&2
  exit 1
}

# Apple's five categories. `c:` entries are link-time symbols (proof); `s:` entries are
# literal spellings distinctive enough not to collide (evidence).
#
# `getattrlist` family deliberately appears under both FileTimestamp and DiskSpace: one call
# can serve either, and the manifest must cover whichever reason applies.
CATEGORIES=(
  "NSPrivacyAccessedAPICategoryFileTimestamp|c:stat,stat64,fstat,fstat64,lstat,lstat64,fstatat,getattrlist,fgetattrlist,getattrlistat,getattrlistbulk|s:NSFileCreationDate,NSFileModificationDate,NSURLContentModificationDateKey,NSURLCreationDateKey,contentModificationDateKey,creationDateKey,fileModificationDate"
  "NSPrivacyAccessedAPICategorySystemBootTime|c:mach_absolute_time,mach_continuous_time|s:systemUptime"
  "NSPrivacyAccessedAPICategoryDiskSpace|c:statfs,statfs64,fstatfs,fstatfs64,statvfs,fstatvfs,getattrlist,fgetattrlist,getattrlistat|s:volumeAvailableCapacityKey,volumeAvailableCapacityForImportantUsageKey,volumeAvailableCapacityForOpportunisticUsageKey,volumeTotalCapacityKey,NSURLVolumeAvailableCapacityKey,NSFileSystemFreeSize,NSFileSystemSize,systemFreeSize"
  "NSPrivacyAccessedAPICategoryActiveKeyboards|c:|s:activeInputModes"
  "NSPrivacyAccessedAPICategoryUserDefaults|c:|s:NSUserDefaults,standardUserDefaults"
)

# --- what the bundle actually contains --------------------------------------
MACHO=()
while IFS= read -r f; do
  file "$f" 2>/dev/null | grep -q "Mach-O" && MACHO+=("$f")
done < <(find "$APP" -type f -perm +111 2>/dev/null | sort)

[ "${#MACHO[@]}" -gt 0 ] || {
  echo "  !     no Mach-O binaries found in $APP" >&2
  exit 1
}

found=()
evidence=""
for spec in "${CATEGORIES[@]}"; do
  category="${spec%%|*}"
  rest="${spec#*|}"
  csyms="${rest%%|*}"
  csyms="${csyms#c:}"
  ssyms="${rest#*|}"
  ssyms="${ssyms#s:}"

  hits=""
  for bin in "${MACHO[@]}"; do
    short="${bin#"$APP"/}"

    if [ -n "$csyms" ]; then
      # `nm -u` lists undefined externals: a C call cannot be made without one.
      pattern="^_(${csyms//,/|})(\\\$INODE64)?$"
      while IFS= read -r sym; do
        [ -n "$sym" ] && hits+="            ${short}: ${sym} (link-time symbol)"$'\n'
      done < <(nm -u "$bin" 2>/dev/null | sed 's/^ *//' | sort -u | grep -E "$pattern" || true)
    fi

    if [ -n "$ssyms" ]; then
      pattern="^(${ssyms//,/|})$"
      while IFS= read -r sym; do
        [ -n "$sym" ] && hits+="            ${short}: ${sym} (literal)"$'\n'
      done < <(strings -a "$bin" 2>/dev/null | grep -xE "$pattern" | sort -u || true)
    fi
  done

  if [ -n "$hits" ]; then
    found+=("$category")
    evidence+="  ${category}"$'\n'"$hits"
  fi
done

# --- what the manifest declares ---------------------------------------------
declared=()
i=0
while decl="$(plutil -extract "NSPrivacyAccessedAPITypes.$i.NSPrivacyAccessedAPIType" raw -o - "$MANIFEST" 2>/dev/null)"; do
  declared+=("$decl")
  i=$((i + 1))
done

contains() {
  local needle="$1"
  shift
  for x in "$@"; do [ "$x" = "$needle" ] && return 0; done
  return 1
}

# --- verdict ----------------------------------------------------------------
printf '        scanned %d Mach-O binaries in %s\n' "${#MACHO[@]}" "${APP##*/}"
[ -n "$evidence" ] && printf '%s' "$evidence"

undeclared=()
for c in "${found[@]}"; do
  contains "$c" ${declared[@]+"${declared[@]}"} || undeclared+=("$c")
done

# Over-declaring is permitted by Apple and is the safe direction, but a category that no
# longer appears is usually a dependency that changed under us — worth saying out loud.
for c in ${declared[@]+"${declared[@]}"}; do
  contains "$c" ${found[@]+"${found[@]}"} || printf '  note  %s is declared but no longer detected in the bundle\n' "$c"
done

if [ "${#undeclared[@]}" -gt 0 ]; then
  for c in "${undeclared[@]}"; do
    printf '  !     %s is present in the shipped bundle and NOT declared in %s\n' "$c" "$MANIFEST"
  done
  echo "  !     App Store submission would be rejected; see docs/PRIVACY_MANIFEST.md" >&2
  exit 1
fi

printf '  ok    every required-reason category in the bundle is declared (%d found, %d declared)\n' \
  "${#found[@]}" "${#declared[@]}"
