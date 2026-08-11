#!/usr/bin/env bash
#
# Gate: every table in the relay schema is deliberately classified as backed up
# or excluded, and the retention-critical ones are excluded.
#
# Copyright (C) 2026 Jan Richter
# SPDX-License-Identifier: AGPL-3.0-only
#
# # Why this is a gate and not a comment in the backup script
#
# `docs/BACKEND.md` §4 is the strongest server-side control Cipher has, and a
# backup is the one operation that can repeal it silently — nothing fails, no
# test goes red, and the deleted messages simply come back at restore time. The
# backup script's own allow-list is the control; this gate is what stops that
# list from drifting away from the schema it is supposed to cover.
#
# The property checked is deliberately stronger than "messages is excluded":
#
#   union(BACKUP_TABLES, EXCLUDED_TABLES) == every CREATE TABLE in the migrations
#
# so a table added by a future migration belongs to neither list and **fails**,
# rather than defaulting into whichever answer the script's flags happen to
# produce. A deny-list would have shipped that table; this refuses to guess.
#
# Offline by construction: it reads the migrations and the script, never a
# database and never the box, so it runs in CI and in verify-all.
#
#   Usage: Scripts/verify-backup-scope.sh [--self-test]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_SCRIPT="$REPO_ROOT/server/deploy/backup.sh"
MIGRATIONS="$REPO_ROOT/server/internal/store/migrations"

# Retention-critical: these must never appear in the backup list, whatever else
# changes. Named individually rather than derived, because the reason each one is
# excluded is a separate argument and a derived rule would lose all of them at
# once if the derivation broke.
declare -a MUST_EXCLUDE=(messages attachments invites one_time_prekeys kyber_prekeys push_tokens)

fail() { printf '\nFAILED: %s\n' "$1" >&2; exit 1; }

# Table names the schema actually declares.
schema_tables() {
  local dir="$1"
  grep -hoE '^CREATE TABLE [a-z_]+' "$dir"/*.sql |
    awk '{print $3}' | sort -u
}

# A bash array literal out of the backup script, without sourcing it — sourcing
# would run the argument parser and the exit trap.
declared_list() {
  local script="$1" name="$2"
  sed -n "s/^${name}=(\\(.*\\))\$/\\1/p" "$script" | tr ' ' '\n' | sed '/^$/d' | sort -u
}

check() {
  local script="$1" migrations="$2"
  local included excluded classified schema unclassified stray forbidden

  included="$(declared_list "$script" BACKUP_TABLES)"
  excluded="$(declared_list "$script" EXCLUDED_TABLES)"
  [ -n "$included" ] || fail "BACKUP_TABLES is empty or unreadable in $script"

  classified="$(printf '%s\n%s\n' "$included" "$excluded" | sed '/^$/d' | sort -u)"
  schema="$(schema_tables "$migrations")"
  [ -n "$schema" ] || fail "no CREATE TABLE found under $migrations — the gate read nothing"

  # A schema table nobody classified.
  unclassified="$(comm -23 <(printf '%s\n' "$schema") <(printf '%s\n' "$classified") | tr '\n' ' ' | sed 's/ *$//')"
  [ -z "$unclassified" ] ||
    fail "table(s) in the schema that the backup policy does not mention: ${unclassified}. Add each to BACKUP_TABLES or EXCLUDED_TABLES in server/deploy/backup.sh, with the reason."

  # A classified table the schema does not have — a stale entry is a policy that
  # has stopped describing the product.
  stray="$(comm -13 <(printf '%s\n' "$schema") <(printf '%s\n' "$classified") | tr '\n' ' ' | sed 's/ *$//')"
  [ -z "$stray" ] ||
    fail "the backup policy names table(s) the schema does not have: ${stray}"

  # The retention-critical ones are on the right side.
  for forbidden in "${MUST_EXCLUDE[@]}"; do
    if printf '%s\n' "$included" | grep -qx "$forbidden"; then
      fail "'${forbidden}' is in BACKUP_TABLES — a restore would reintroduce data BACKEND.md 4 deletes"
    fi
  done

  printf '%s' "$(printf '%s\n' "$schema" | wc -l | tr -d ' ')"
}

if [ "${1:-}" = "--self-test" ]; then
  probe="$(mktemp -d)"
  trap 'rm -rf "$probe"' EXIT
  cases=0

  mkdir -p "$probe/migrations"
  cat >"$probe/migrations/0001.sql" <<'SQL'
CREATE TABLE accounts (aci UUID);
CREATE TABLE messages (id UUID);
CREATE TABLE session_tokens (token_hash BYTEA);
SQL
  mk_script() {
    printf 'BACKUP_TABLES=(%s)\nEXCLUDED_TABLES=(%s)\n' "$1" "$2" >"$probe/s.sh"
  }

  # Positive control: a correct policy passes. Without it, a check that rejects
  # everything would look like a working gate.
  mk_script "accounts session_tokens" "messages"
  check "$probe/s.sh" "$probe/migrations" >/dev/null || fail "self-test: a correct policy was rejected"
  cases=$((cases + 1))

  # A schema table classified nowhere.
  mk_script "accounts" "messages"
  if ( check "$probe/s.sh" "$probe/migrations" ) >/dev/null 2>&1; then
    fail "self-test: an unclassified table (session_tokens) was accepted"
  fi
  cases=$((cases + 1))

  # A retention-critical table on the wrong side.
  mk_script "accounts session_tokens messages" ""
  if ( check "$probe/s.sh" "$probe/migrations" ) >/dev/null 2>&1; then
    fail "self-test: 'messages' in BACKUP_TABLES was accepted"
  fi
  cases=$((cases + 1))

  # A stale entry naming a table the schema dropped.
  mk_script "accounts session_tokens" "messages ghosts"
  if ( check "$probe/s.sh" "$probe/migrations" ) >/dev/null 2>&1; then
    fail "self-test: a policy naming a nonexistent table was accepted"
  fi
  cases=$((cases + 1))

  # An empty backup list.
  mk_script "" "messages accounts session_tokens"
  if ( check "$probe/s.sh" "$probe/migrations" ) >/dev/null 2>&1; then
    fail "self-test: an empty BACKUP_TABLES was accepted"
  fi
  cases=$((cases + 1))

  # A migrations directory the gate cannot read must fail, not pass silently.
  mkdir -p "$probe/empty"
  mk_script "accounts session_tokens" "messages"
  if ( check "$probe/s.sh" "$probe/empty" ) >/dev/null 2>&1; then
    fail "self-test: a schema the gate could not read was reported as clean"
  fi
  cases=$((cases + 1))

  echo "  ok    self-test: ${cases} cases — an unclassified or misclassified table still fails"
  exit 0
fi

[ -r "$BACKUP_SCRIPT" ] || fail "no backup script at $BACKUP_SCRIPT"
total="$(check "$BACKUP_SCRIPT" "$MIGRATIONS")"
echo "  ok    all ${total} schema tables are classified; every retention-critical one is excluded"

"$BACKUP_SCRIPT" --self-test
