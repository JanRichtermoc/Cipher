#!/usr/bin/env bash
#
# Encrypted relay backup (P9.S05).
#
# Copyright (C) 2026 Jan Richter
# SPDX-License-Identifier: AGPL-3.0-only
#
# # What this backs up, and why it is not "the database"
#
# `docs/BACKEND.md` §4 is a retention policy, and a backup is the one operation
# that can quietly repeal it: a nightly dump kept for a month reintroduces every
# message the relay deleted, with a delay. So this does not dump the database. It
# dumps the two tables whose loss cannot be repaired by a client, and refuses to
# carry anything else:
#
#   accounts        an account's identity key and registration id. Losing it
#                   loses the account itself: the aci is the address peers hold
#                   and the identity key is what their safety numbers are of.
#   session_tokens  the ONLY credential path. `POST /v1/auth/rotate` needs the
#                   old token and redemption mints a *new* account, so an
#                   account whose token hash is gone cannot authenticate again
#                   by any route — its owner would have to redeem a fresh
#                   invite, receive a different aci, and re-verify with every
#                   peer. Excluding this table would make a restore worse than
#                   no restore.
#
# Everything else is excluded on purpose, and each for its own reason:
#
#   messages        §4: acknowledged means gone. Losing undelivered messages in
#                   a restore is the correct outcome, not a gap to fix.
#   attachments     same, plus the blobs live outside Postgres entirely.
#   invites         a live account-creation credential. Restoring one resurrects
#                   a credential that was consumed or expired.
#   one_time_prekeys
#   kyber_prekeys   dispensed-then-deleted. Restoring a one-time prekey lets the
#                   same key be dispensed twice, which is precisely the forward
#                   secrecy AUDIT 2.6 exists to protect.
#   signed_prekeys  public and short-lived; the client republishes.
#   push_tokens     metadata that outlives the message (P7.S03). It is rotated
#                   at 30 days and re-registered by the device; restoring stale
#                   ciphertext buys nothing and extends a retention window.
#
# The cost of excluding the prekey tables is bounded rather than argued: the
# client rotates on a 48h interval regardless of any count
# (`MessageRepository.preKeyRotationInterval`), so a restored relay is missing
# published prekeys for at most one rotation. Existing sessions are unaffected —
# the ratchet is on the device — so the visible symptom is that a *new* session
# with a restored account cannot start until its owner's next rotation.
#
# # Encryption, and why it is public-key
#
# `openssl cms` with AES-256-GCM to a recipient certificate. The box holds only
# the certificate (a public key), so **the relay cannot decrypt its own
# backups** — a seized host yields the archive and no way into it. The private
# half is the operator's and belongs off the box; see docs/RUNBOOK-VPS.md.
# Symmetric encryption with a passphrase on the host would have put the key
# beside the ciphertext, which is what §1.1 assumes the adversary already has.
#
# Usage:
#   backup.sh --recipient /path/to/cipher-backup-cert.pem [--out DIR]
#   backup.sh --self-test          # offline; proves the guards below
set -euo pipefail

# The whole allow-list. Scripts/verify-backup-scope.sh reads these two arrays and
# fails if their union is not exactly the schema's table set, so a table added in
# a later migration cannot default into either answer.
BACKUP_TABLES=(accounts session_tokens)
EXCLUDED_TABLES=(invites one_time_prekeys signed_prekeys kyber_prekeys messages attachments push_tokens)

RECIPIENT=""
OUT_DIR="/var/backups/cipher"
SELF_TEST=0
COMPOSE_DIR="${COMPOSE_DIR:-$HOME/cipher/server}"

while [ $# -gt 0 ]; do
  case "$1" in
  --recipient) RECIPIENT="${2:?--recipient needs a path}"; shift 2 ;;
  --out)       OUT_DIR="${2:?--out needs a path}"; shift 2 ;;
  --self-test) SELF_TEST=1; shift ;;
  *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

fail() { printf 'FAILED: %s\n' "$1" >&2; exit 1; }

# Refuses a dump that carries a forbidden table, whatever produced it.
#
# The last line of defence rather than the first: the dump is already built with
# an explicit --table list, so this fires only if that list and the policy above
# ever disagree. It reads the dump's own COPY/INSERT headers, so it is checking
# the artifact and not the arguments that were meant to produce it — a check that
# re-read the arguments would agree with itself by construction.
assert_dump_scope() {
  local dump="$1" table found
  for table in "${EXCLUDED_TABLES[@]}"; do
    found="$(grep -cE "^(COPY|INSERT INTO) public\.${table}[ (]" "$dump" || true)"
    [ "$found" = "0" ] ||
      fail "the dump carries the excluded table '${table}' — retention policy (BACKEND.md 4) would be repealed by this backup"
  done
  for table in "${BACKUP_TABLES[@]}"; do
    grep -qE "^(COPY|INSERT INTO) public\.${table}[ (]" "$dump" ||
      fail "the dump is missing the required table '${table}' — a restore from it could not return an account"
  done
}

if [ "$SELF_TEST" = "1" ]; then
  # Proves assert_dump_scope fires, and fires only when it should. Without the
  # first case a broken check reports every backup as correctly scoped, which is
  # the failure that looks identical to success (AUDIT R2).
  probe="$(mktemp -d)"
  trap 'rm -rf "$probe"' EXIT
  cases=0

  good="$probe/good.sql"
  { echo "COPY public.accounts (aci) FROM stdin;"
    echo "COPY public.session_tokens (token_hash) FROM stdin;"; } >"$good"
  assert_dump_scope "$good" || fail "self-test: a correctly scoped dump was rejected"
  cases=$((cases + 1))

  for forbidden in messages attachments invites one_time_prekeys push_tokens; do
    bad="$probe/bad-$forbidden.sql"
    cp "$good" "$bad"
    echo "COPY public.${forbidden} (id) FROM stdin;" >>"$bad"
    if ( assert_dump_scope "$bad" ) 2>/dev/null; then
      fail "self-test: a dump carrying '${forbidden}' was accepted"
    fi
    cases=$((cases + 1))
  done

  missing="$probe/missing.sql"
  echo "COPY public.accounts (aci) FROM stdin;" >"$missing"
  if ( assert_dump_scope "$missing" ) 2>/dev/null; then
    fail "self-test: a dump missing session_tokens was accepted"
  fi
  cases=$((cases + 1))

  # INSERT form as well as COPY: pg_dump --inserts produces the other one, and a
  # check that knew only one shape would pass a backup it never read.
  insert_bad="$probe/insert-bad.sql"
  cp "$good" "$insert_bad"
  echo "INSERT INTO public.messages (id) VALUES ('x');" >>"$insert_bad"
  if ( assert_dump_scope "$insert_bad" ) 2>/dev/null; then
    fail "self-test: an INSERT-form dump carrying 'messages' was accepted"
  fi
  cases=$((cases + 1))

  echo "  ok    self-test: ${cases} cases — the scope guard fires, and only when it should"
  exit 0
fi

[ -n "$RECIPIENT" ] || fail "no --recipient certificate; refusing to write an unencrypted backup"
[ -r "$RECIPIENT" ] || fail "recipient certificate not readable: $RECIPIENT"
cd "$COMPOSE_DIR" || fail "no compose directory at $COMPOSE_DIR"

pg="$(docker compose ps -q postgres)"
[ -n "$pg" ] || fail "the postgres container is not running"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT_DIR"
plain="$(mktemp)"
# The plaintext dump exists only inside this script's lifetime, and only at 0600.
trap 'shred -u "$plain" 2>/dev/null || rm -f "$plain"' EXIT
chmod 600 "$plain"

# --table for each included table, never --exclude-table: an allow-list fails
# closed when a migration adds a table, a deny-list ships it.
args=()
for t in "${BACKUP_TABLES[@]}"; do args+=(--table="public.$t"); done

# The credentials are the container's own environment and are never read here.
docker exec -e PGDUMP_ARGS="${args[*]}" "$pg" sh -c \
  'PGPASSWORD="$POSTGRES_PASSWORD" pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
     --no-owner --no-privileges --no-comments $PGDUMP_ARGS' \
  </dev/null >"$plain" || fail "pg_dump failed"

assert_dump_scope "$plain"

out="$OUT_DIR/cipher-$stamp.sql.cms"
openssl cms -encrypt -aes-256-gcm -binary -outform DER -in "$plain" -out "$out" "$RECIPIENT" ||
  fail "encryption failed — no plaintext backup is left behind"
chmod 600 "$out"

printf 'wrote %s (%s bytes, encrypted to %s)\n' \
  "$out" "$(wc -c <"$out" | tr -d ' ')" "$(basename "$RECIPIENT")"
printf 'tables: %s\n' "${BACKUP_TABLES[*]}"
