#!/usr/bin/env bash
#
# Gate: the SPKI the host actually serves still matches the pin recorded in
# docs/BACKEND.md §9.1, and certbot is still configured not to rotate the key.
#
# Copyright (C) 2026 Jan Richter
# SPDX-License-Identifier: AGPL-3.0-only
#
# Why this exists as a script rather than a note in the runbook.
#
# P5.S08 ships a client that pins the leaf SPKI and FAILS CLOSED. From then on,
# the leaf key changing is not a weakened control — it is every installed app
# unable to connect, discovered by users, with no server-side fix because the
# clients are already shipped. certbot generates a fresh key on every renewal
# unless `reuse_key` is set, so the disaster is one forgotten flag away and
# arrives ~60 days later, long after whoever ran the command has moved on.
#
# This turns the pin table from a record into a checked claim. Run it after any
# certbot invocation that rewrites the renewal config, and on a schedule.
#
# NOT part of Scripts/verify-all.sh: it needs the network and a live host, and
# verify-all must pass offline and in CI without reaching the staging box. A
# gate that cannot run is a gate that gets removed (AUDIT R2).
#
#   Usage: Scripts/verify-pins.sh [host]
#          Scripts/verify-pins.sh relay.mgchatman.app
#
set -euo pipefail

HOST="${1:-relay.mgchatman.app}"
PORT="${PIN_PORT:-443}"
DOC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docs/BACKEND.md"

fail() { echo "FAILED: $*" >&2; exit 1; }

# macOS ships LibreSSL as `openssl`, which cannot drive some TLS probes and has
# reported a false pass on exactly this host before (AUDIT 5.16). Prefer a real
# OpenSSL when one is installed. The SPKI extraction below works under either,
# but the version is printed so a surprising result can be attributed.
OPENSSL="openssl"
for candidate in /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl; do
  [ -x "$candidate" ] && { OPENSSL="$candidate"; break; }
done

echo "  using $("$OPENSSL" version)"
echo "  host  $HOST:$PORT"

[ -f "$DOC" ] || fail "cannot find $DOC"

# --- the SPKI actually served -------------------------------------------------
#
# Buffered into a variable rather than piped into an early-exiting consumer:
# AUDIT R1. `</dev/null` closes stdin so s_client cannot block waiting for input.
chain="$("$OPENSSL" s_client -connect "$HOST:$PORT" -servername "$HOST" \
           -showcerts </dev/null 2>/dev/null)" \
  || fail "could not reach $HOST:$PORT"

[ -n "$chain" ] || fail "empty response from $HOST:$PORT"

leaf_spki="$(printf '%s' "$chain" \
  | "$OPENSSL" x509 -pubkey -noout 2>/dev/null \
  | "$OPENSSL" pkey -pubin -outform der 2>/dev/null \
  | "$OPENSSL" dgst -sha256 -binary \
  | "$OPENSSL" base64)" || fail "could not extract the leaf public key"

[ -n "$leaf_spki" ] || fail "extracted an empty SPKI — the probe did not work"

echo "  served leaf SPKI: $leaf_spki"

# --- is it one of the pins we shipped? ----------------------------------------
#
# Matched against the rows of the §9.1 table marked pinned, not against the whole
# document: the intermediate and root SPKIs are recorded there too, deliberately
# NOT pinned, and matching them would defeat the point of recording them
# separately. This is AUDIT 6.7's lesson — scan the control, not the prose.
pinned="$(awk -F'|' '/^\| `[A-Za-z0-9+\/=]+` \|/ {
             gsub(/^[ \t]+|[ \t]+$/, "", $4)
             if ($4 == "**YES**") { gsub(/[ \t`]/, "", $2); print $2 }
           }' "$DOC")"

[ -n "$pinned" ] || fail "no pinned SPKIs found in $DOC §9.1 — has the table changed shape?"

echo "  pins recorded as shipped:"
printf '    %s\n' $pinned

if printf '%s\n' $pinned | grep -qxF "$leaf_spki"; then
  echo "  ok    served leaf matches a shipped pin"
else
  echo "" >&2
  echo "  The key this host serves is NOT one of the pinned keys." >&2
  echo "  Every client shipped with the pin set above will fail closed against it." >&2
  echo "  Most likely: certbot renewed without reuse_key. See BACKEND.md 9.1." >&2
  fail "served SPKI $leaf_spki is not in the shipped pin set"
fi

# --- and will it still match after the next renewal? --------------------------
if command -v ssh >/dev/null 2>&1 && ssh -o BatchMode=yes -o ConnectTimeout=5 \
     cipher-staging true >/dev/null 2>&1; then
  reuse="$(ssh -o BatchMode=yes cipher-staging \
            "sudo grep -h '^reuse_key' /etc/letsencrypt/renewal/*.conf 2>/dev/null || true")"
  case "$reuse" in
    *True*) echo "  ok    certbot reuse_key = True (the next renewal keeps this key)" ;;
    "")     fail "no reuse_key in any renewal config — the next renewal WILL rotate the key" ;;
    *)      fail "reuse_key is not True: $reuse" ;;
  esac
else
  echo "  !     skipped the reuse_key check (no ssh access to cipher-staging)"
  echo "        run this where the host is reachable before trusting a green result"
fi

echo "  ok    pin set verified"
