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
#          Scripts/verify-pins.sh --self-test    # offline; proves the checks below
#          Scripts/verify-pins.sh --partial      # allow a run that could not do everything
#
# # Why a partial run is a failure by default (AUDIT 6.14)
#
# Three checks here can find their material missing rather than wrong: the certbot
# `reuse_key` check needs SSH to the host, the source check needs a checkout, and the
# backup-key check needs a key file. Each used to print a `!` line and let the script end
# "ok pin set verified" with exit 0 — so a run that proved one property and a run that
# proved four reported the same thing, and the only difference was a line in the middle of
# the output. A skipped check is now an incomplete run, and an incomplete run exits
# non-zero unless the operator says `--partial` and therefore knows what did not happen.
set -euo pipefail

SELF_TEST=0
PARTIAL=0
ARGS=()
for arg in "$@"; do
  case "$arg" in
  --self-test) SELF_TEST=1 ;;
  --partial)   PARTIAL=1 ;;
  -*)          echo "unknown option: $arg" >&2; exit 2 ;;
  *)           ARGS+=("$arg") ;;
  esac
done
set -- ${ARGS+"${ARGS[@]}"}

HOST="${1:-relay.mgchatman.app}"
PORT="${PIN_PORT:-443}"
DOC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docs/BACKEND.md"

fail() { echo "FAILED: $*" >&2; exit 1; }

INCOMPLETE=0
skipped_checks=()
skip() {
  INCOMPLETE=1
  skipped_checks+=("$1")
  echo "  !     did not run: $1"
}

# chain_is_verified reads s_client's own verdict out of a captured session.
#
# The pin comparison below is NOT a substitute for this, which is the defect AUDIT 6.14
# names. `CertificatePinner` states the rule the other way round and enforces it —
# platform validation first, the pin as an extra hurdle — because a pin match on an
# unvalidated chain accepts an expired, revoked, wrong-host or self-signed certificate
# that happens to carry the pinned key. This script hashed whatever was presented and
# compared it, so it asserted a weaker property than the client it exists to protect.
#
# Parsing the verdict rather than trusting an exit code: `openssl s_client` exits 0 on a
# failed verification unless it is asked not to, and the LibreSSL that macOS ships as
# `openssl` has already reported a false pass on this very host (AUDIT 5.16). The flags
# below are still passed; the parse is what the result is read from.
chain_is_verified() {
  local session="$1" line
  line="$(printf '%s\n' "$session" | grep -E '^[[:space:]]*Verify return code:' | tail -1)"
  [ -n "$line" ] || return 2
  case "$line" in
  *"Verify return code: 0 (ok)"*) return 0 ;;
  *) return 1 ;;
  esac
}

# macOS ships LibreSSL as `openssl`, which cannot drive some TLS probes and has
# reported a false pass on exactly this host before (AUDIT 5.16). Prefer a real
# OpenSSL when one is installed. The SPKI extraction below works under either,
# but the version is printed so a surprising result can be attributed.
OPENSSL="openssl"
for candidate in /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl; do
  [ -x "$candidate" ] && { OPENSSL="$candidate"; break; }
done

# --- self-test ----------------------------------------------------------------
#
# Offline, and it runs before anything touches the network. Every check this script makes
# is "compare two strings" or "read a verdict out of some text", which is precisely the
# shape that reports a clean result when it has stopped working (AUDIT R2).
#
# What it deliberately does not do: negotiate a real TLS session. Standing up a local
# server would test the flags as well as the parsing, and would also make this gate depend
# on which openssl the machine has, on a free port, and on a background process — a gate
# that is flaky is a gate that gets ignored. The parsing is tested exhaustively here; that
# the flags are passed is visible in one place, a few lines below.
if [ "$SELF_TEST" -eq 1 ]; then
  cases=0
  check() {
    local want="$1" desc="$2" session="$3"
    local got=0
    cases=$((cases + 1))
    # `|| got=$?` rather than a bare call: under `set -e` a function returning non-zero as
    # a statement aborts the script. The first version of this self-test did exactly that
    # and exited 1 with no output at all — and the same mistake was in the live call site,
    # where it would have turned "this certificate failed validation" into a silent exit.
    chain_is_verified "$session" || got=$?
    [ "$got" = "$want" ] ||
      fail "self-test: $desc — chain_is_verified returned $got, want $want"
  }

  check 0 "an ok verdict is accepted" \
    "depth=0 CN = relay.example
    Verify return code: 0 (ok)"
  # The defect this gate had: any of these used to be hashed and pin-compared anyway.
  check 1 "a self-signed chain is refused" \
    "    Verify return code: 18 (self signed certificate)"
  check 1 "an expired certificate is refused" \
    "    Verify return code: 10 (certificate has expired)"
  check 1 "an unknown issuer is refused" \
    "    Verify return code: 20 (unable to get local issuer certificate)"
  check 1 "a hostname mismatch is refused" \
    "    Verify return code: 62 (Hostname mismatch)"
  # No verdict at all is not an all-clear either: it means the probe did not work.
  check 2 "output with no verdict is refused" \
    "CONNECTED(00000003)
    no peer certificate available"
  # The last verdict wins: a renegotiated session prints more than one.
  check 1 "the final verdict is the one that counts" \
    "    Verify return code: 0 (ok)
    Verify return code: 10 (certificate has expired)"

  # A skipped check must make the run incomplete. This is the other half of 6.14 —
  # the previous script printed a warning and exited 0.
  INCOMPLETE=0
  skipped_checks=()
  skip "a fabricated check" >/dev/null
  [ "$INCOMPLETE" -eq 1 ] || fail "self-test: a skipped check did not mark the run incomplete"
  cases=$((cases + 1))
  INCOMPLETE=0
  skipped_checks=()

  # And the backup-key comparison, against keys generated for this test and thrown away.
  # A real key is never involved: the point is that the derivation and the comparison work.
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  "$OPENSSL" ecparam -name prime256v1 -genkey -noout -out "$tmp/a.pem" 2>/dev/null ||
    fail "self-test: could not generate a throwaway key"
  "$OPENSSL" ecparam -name prime256v1 -genkey -noout -out "$tmp/b.pem" 2>/dev/null ||
    fail "self-test: could not generate a second throwaway key"
  spki_of() {
    "$OPENSSL" pkey -in "$1" -pubout -outform der 2>/dev/null \
      | "$OPENSSL" dgst -sha256 -binary | "$OPENSSL" base64
  }
  a="$(spki_of "$tmp/a.pem")"
  b="$(spki_of "$tmp/b.pem")"
  [ -n "$a" ] || fail "self-test: derived an empty SPKI from a generated key"
  [ "$a" = "$(spki_of "$tmp/a.pem")" ] || fail "self-test: SPKI derivation is not deterministic"
  [ "$a" != "$b" ] || fail "self-test: two different keys derived the same SPKI"
  cases=$((cases + 3))
  rm -rf "$tmp"
  trap - EXIT

  echo "  ok    self-test: $cases cases — validation is read from the verdict, a skip is incomplete, and key derivation works"
  exit 0
fi

echo "  using $("$OPENSSL" version)"
echo "  host  $HOST:$PORT"

[ -f "$DOC" ] || fail "cannot find $DOC"

# --- the SPKI actually served -------------------------------------------------
#
# Buffered into a variable rather than piped into an early-exiting consumer:
# AUDIT R1. `</dev/null` closes stdin so s_client cannot block waiting for input.
#
# `-verify_return_error` makes a failed verification an error rather than a note, and
# `-verify_hostname` is what ties the certificate to the name we asked for — without it a
# valid certificate for any other host passes the chain check. Both are passed when the
# available OpenSSL advertises them; when it does not, that is recorded as a check that
# did not run rather than quietly dropped.
verify_flags=(-verify_return_error -verify 5)
if "$OPENSSL" s_client -help 2>&1 | grep -q -- '-verify_hostname'; then
  verify_flags+=(-verify_hostname "$HOST")
else
  skip "hostname validation ($OPENSSL has no -verify_hostname; install openssl@3)"
fi
[ -n "${PIN_CA_FILE:-}" ] && verify_flags+=(-CAfile "$PIN_CA_FILE")

chain="$("$OPENSSL" s_client -connect "$HOST:$PORT" -servername "$HOST" \
           "${verify_flags[@]}" -showcerts </dev/null 2>/dev/null)" \
  || fail "could not reach $HOST:$PORT, or its certificate failed validation"

[ -n "$chain" ] || fail "empty response from $HOST:$PORT"

# Validation BEFORE the hash. Hashing first and comparing to the pin set would report a
# match for a self-signed certificate carrying the pinned key.
verdict=0
chain_is_verified "$chain" || verdict=$?
case "$verdict" in
0) echo "  ok    chain and hostname validated by $("$OPENSSL" version | cut -d' ' -f1-2)" ;;
2) fail "$OPENSSL reported no verification result — the probe cannot be trusted" ;;
*) fail "certificate validation FAILED for $HOST: $(printf '%s\n' "$chain" | grep -E '^[[:space:]]*Verify return code:' | tail -1)" ;;
esac

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
  skip "the certbot reuse_key check (no ssh access to cipher-staging)"
fi

# --- and does the SHIPPED APP pin the same values? ----------------------------
#
# The doc and the server agreeing is not enough: what fails closed on a user's
# phone is the constant compiled into the binary. Checking source against the doc
# closes the loop source -> doc -> live host, so a pin edited in one place and not
# the other is caught here rather than by users who cannot connect.
SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/Cipher/Networking/RelayEndpoint.swift"

if [ -f "$SOURCE" ]; then
  # Only the two pin constants, not every base64-looking string in the file.
  shipped="$(grep -oE 'static let (currentLeaf|backupKey) = "[A-Za-z0-9+/=]+"' "$SOURCE" \
             | sed -E 's/.*"([A-Za-z0-9+\/=]+)"/\1/' | sort)"
  recorded="$(printf '%s\n' $pinned | sort)"

  if [ "$shipped" = "$recorded" ]; then
    echo "  ok    RelayEndpoint.swift pins exactly the values recorded in BACKEND.md 9.1"
  else
    echo "" >&2
    echo "  shipped in RelayEndpoint.swift:" >&2; printf '    %s\n' $shipped >&2
    echo "  recorded in BACKEND.md 9.1:" >&2;    printf '    %s\n' $recorded >&2
    fail "the app's pin set and the documented pin set disagree"
  fi
else
  skip "the source check ($SOURCE not found)"
fi

# --- is the spare actually a spare? -------------------------------------------
#
# `RelayEndpoint` ships two pins and justifies the second one plainly: one pin plus one
# lost key is a permanently bricked client, because every installed app fails closed
# against a host that cannot present the pinned key and there is no server-side remedy.
# That argument holds only if a private key matching `backupKey` still exists somewhere an
# operator can reach. Nothing checked it, so the emergency plan was a base64 string.
#
# The key is never read by anyone but openssl here, and only its SPKI digest — a public
# value derivable from any certificate carrying it — is ever printed.
if [ -n "${PIN_BACKUP_KEY_FILE:-}" ]; then
  [ -f "$PIN_BACKUP_KEY_FILE" ] || fail "PIN_BACKUP_KEY_FILE is set but $PIN_BACKUP_KEY_FILE does not exist"
  derived="$("$OPENSSL" pkey -in "$PIN_BACKUP_KEY_FILE" -pubout -outform der 2>/dev/null \
             | "$OPENSSL" dgst -sha256 -binary | "$OPENSSL" base64)" \
    || fail "could not derive a public key from PIN_BACKUP_KEY_FILE"
  [ -n "$derived" ] || fail "derived an empty SPKI from PIN_BACKUP_KEY_FILE"

  if [ -f "$SOURCE" ]; then
    backup_pin="$(grep -oE 'static let backupKey = "[A-Za-z0-9+/=]+"' "$SOURCE" \
                  | sed -E 's/.*"([A-Za-z0-9+\/=]+)"/\1/')"
  else
    backup_pin=""
  fi

  if [ -z "$backup_pin" ]; then
    fail "cannot read backupKey from $SOURCE to compare against PIN_BACKUP_KEY_FILE"
  elif [ "$derived" = "$backup_pin" ]; then
    echo "  ok    the backup private key still derives the pinned backup SPKI"
  else
    echo "  derived from PIN_BACKUP_KEY_FILE: $derived" >&2
    echo "  pinned as backupKey:              $backup_pin" >&2
    fail "the backup key does not match the shipped backup pin — the emergency reissue would brick every client"
  fi
else
  skip "the backup-key check (set PIN_BACKUP_KEY_FILE to the emergency key)"
fi

# --- verdict ------------------------------------------------------------------
if [ "$INCOMPLETE" -eq 1 ]; then
  echo ""
  echo "  This run did not check everything:" >&2
  printf '    - %s\n' "${skipped_checks[@]}" >&2
  if [ "$PARTIAL" -eq 0 ]; then
    fail "incomplete pin verification — re-run where the material is available, or pass --partial to accept this"
  fi
  echo "  !     --partial: reporting success on an incomplete run, at the operator's request" >&2
fi

echo "  ok    pin set verified"
