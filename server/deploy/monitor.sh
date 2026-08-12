#!/usr/bin/env bash
#
# Relay monitoring (P9.S04) — metrics and alerts that carry no message content
# and no per-message metadata.
#
# Copyright (C) 2026 Jan Richter
# SPDX-License-Identifier: AGPL-3.0-only
#
# # Why this is a shell script on the host and not a /metrics endpoint
#
# The obvious implementation is a Prometheus endpoint on the relay. It is the
# wrong one here, for three reasons that are all the same reason:
#
#   1. `docs/BACKEND.md` §7 ends with "log volume is itself metadata: an error
#      log that fires once per delivery is a delivery record", and
#      `TestNoLogLineIsEmittedPerDeliveredMessage` enforces it. A counter that
#      increments once per delivery is the same record with a different name —
#      and unlike a log line it is *retained and scrapeable*, so it is worse.
#   2. A scrape endpoint is new authenticated surface on a service whose whole
#      design is to have as little as possible, and `messages.go` already
#      records that the relay deliberately has nowhere to put a per-message
#      counter.
#   3. Any hosted alerting target is a third party that learns when the relay is
#      up, which is exactly the class of leak `THREAT_MODEL.md` §3.4 removes by
#      collecting no identifiers and §4.1 removes by refusing SDKs.
#
# So: everything here is derived from what the host already knows — container
# state, disk, the certificate, and *aggregate counts* over the access log the
# relay already writes and already rotates at 24h. Nothing is retained that the
# log did not already hold, and nothing is sent anywhere.
#
# # The output contract, which is the security-critical part
#
# This script emits **counts and status words only**. It must never print a log
# line, an IP address, a UUID, a route's populated path, or any token — because
# an alert is a record that outlives the 24h log, and a "helpful" excerpt in an
# alert is how a retention policy gets repealed by an operational convenience.
# `--self-test` proves that over a fabricated log stuffed with exactly those
# values, so the guard fails loudly rather than being a comment.
#
# Usage:
#   monitor.sh                 # run every check; exit 0 ok, 1 warn, 2 critical
#   monitor.sh --self-test     # offline; proves the thresholds and the redaction
#
# Thresholds may be overridden for a drill:
#   CERT_WARN_DAYS CERT_CRIT_DAYS DISK_WARN_PCT DISK_CRIT_PCT ERROR_WARN ERROR_CRIT
set -uo pipefail

CERT_WARN_DAYS="${CERT_WARN_DAYS:-21}"
CERT_CRIT_DAYS="${CERT_CRIT_DAYS:-7}"
DISK_WARN_PCT="${DISK_WARN_PCT:-80}"
DISK_CRIT_PCT="${DISK_CRIT_PCT:-90}"
ERROR_WARN="${ERROR_WARN:-1}"
ERROR_CRIT="${ERROR_CRIT:-20}"
HOST="${MONITOR_HOST:-relay.mgchatman.app}"
ACCESS_LOG="${MONITOR_ACCESS_LOG:-/var/log/cipher/cipher-access.log}"
COMPOSE_DIR="${COMPOSE_DIR:-$HOME/cipher/server}"

# Counts matching lines. `grep -c` prints 0 *and* exits non-zero when nothing
# matches, so the obvious `grep -c ... || echo 0` emits TWO zeros and every later
# integer comparison then fails with "integer expression expected". Found by
# running this against the live box rather than by reading it.
count_matching() { # pattern; reads stdin
  local n
  n="$(grep -c "$1" || true)"
  printf '%s' "${n:-0}" | tr -d '\n'
}

WORST=0
note() { # severity, check, detail  — detail must already be aggregate-only
  local sev="$1" check="$2" detail="$3" label
  case "$sev" in
  0) label="ok  " ;;
  1) label="WARN" ;;
  2) label="CRIT" ;;
  esac
  [ "$sev" -gt "$WORST" ] && WORST="$sev"
  printf '  %s  %-22s %s\n' "$label" "$check" "$detail"
}

# --- pure threshold logic, so the self-test can drive it with no host ---------

sev_for_days() { # days_remaining -> severity
  local d="${1:-}"
  [ -n "$d" ] || { echo 2; return; }
  if [ "$d" -le "$CERT_CRIT_DAYS" ]; then echo 2
  elif [ "$d" -le "$CERT_WARN_DAYS" ]; then echo 1
  else echo 0; fi
}

sev_for_pct() { # used_percent -> severity
  local p="${1:-}"
  [ -n "$p" ] || { echo 2; return; }
  if [ "$p" -ge "$DISK_CRIT_PCT" ]; then echo 2
  elif [ "$p" -ge "$DISK_WARN_PCT" ]; then echo 1
  else echo 0; fi
}

sev_for_errors() { # error_count -> severity
  local n="${1:-}"
  [ -n "$n" ] || { echo 2; return; }
  if [ "$n" -ge "$ERROR_CRIT" ]; then echo 2
  elif [ "$n" -ge "$ERROR_WARN" ]; then echo 1
  else echo 0; fi
}

# Counts only. Takes a log on stdin and emits five integers, never a line from
# it. This is the function the output contract lives or dies on.
#
# The format is nginx's `minimal` (server/deploy/nginx/00-cipher-hardening.conf):
#
#   $remote_addr $request_method $status $body_bytes_sent $request_time
#
# so the status is field 3. The first version of this matched a JSON `"status":`
# shape and therefore matched NOTHING against the real log — it reported
# "401=0" from a file it could not parse, which is AUDIT **R2** exactly: a
# "found nothing" check with no evidence it ever scanned anything. `parsed` is
# the fix. It is returned so the caller can tell "no failures" from "no idea",
# and the caller treats the second as an alert.
summarise_access_log() { # stdin: log -> "total parsed 4xx 401 429"
  awk '
    { total++ }
    $3 ~ /^[0-9][0-9][0-9]$/ {
      parsed++
      if ($3 ~ /^4/) fourxx++
      if ($3 == "401") unauth++
      if ($3 == "429") limited++
    }
    END { printf "%d %d %d %d %d", total+0, parsed+0, fourxx+0, unauth+0, limited+0 }
  '
}

if [ "${1:-}" = "--self-test" ]; then
  cases=0
  fail() { printf '\nFAILED: %s\n' "$1" >&2; exit 1; }

  # Thresholds, both directions. A check that only ever returned ok would pass a
  # test that only asserted the ok case.
  [ "$(CERT_CRIT_DAYS=7 CERT_WARN_DAYS=21 sev_for_days 40)" = 0 ] || fail "self-test: a healthy cert did not read ok"
  [ "$(sev_for_days 14)" = 1 ] || fail "self-test: a cert inside the warn window did not warn"
  [ "$(sev_for_days 3)" = 2 ]  || fail "self-test: a cert inside the crit window was not critical"
  [ "$(sev_for_days '')" = 2 ] || fail "self-test: an unreadable cert expiry was not critical"
  cases=$((cases + 4))

  [ "$(sev_for_pct 10)" = 0 ] || fail "self-test: a healthy disk did not read ok"
  [ "$(sev_for_pct 85)" = 1 ] || fail "self-test: a filling disk did not warn"
  [ "$(sev_for_pct 95)" = 2 ] || fail "self-test: a full disk was not critical"
  [ "$(sev_for_pct '')" = 2 ] || fail "self-test: an unreadable disk was not critical"
  cases=$((cases + 4))

  [ "$(sev_for_errors 0)" = 0 ]  || fail "self-test: a quiet relay did not read ok"
  [ "$(sev_for_errors 5)" = 1 ]  || fail "self-test: errors did not warn"
  [ "$(sev_for_errors 50)" = 2 ] || fail "self-test: an error storm was not critical"
  cases=$((cases + 3))

  # THE OUTPUT CONTRACT. A log stuffed with exactly the values that must never
  # leave it; the summary must be four integers and nothing else.
  probe_log='203.0.113.9 GET 401 0 0.003
198.51.100.7 POST 202 12 0.005
192.0.2.44 POST 429 31 0.001
203.0.113.9 GET 404 5 0.002'
  summary="$(printf '%s\n' "$probe_log" | summarise_access_log)"
  [ "$summary" = "4 4 3 1 1" ] || fail "self-test: the access-log summary miscounted (got '$summary', want '4 4 3 1 1')"
  cases=$((cases + 1))

  # R2, made executable: a log this cannot parse must report parsed=0 rather
  # than a confident zero. This is the exact defect the first version shipped —
  # a JSON-shaped log scanned by a field-3 parser, or vice versa.
  wrong_format='{"route":"GET /v1/keys/{aci}","status":401,"ip":"203.0.113.9"}
{"route":"POST /v1/messages","status":202,"ip":"198.51.100.7"}'
  wrong_summary="$(printf '%s\n' "$wrong_format" | summarise_access_log)"
  case "$wrong_summary" in
  "2 0 "*) : ;;
  *) fail "self-test: an unparseable log did not report parsed=0 (got '$wrong_summary')" ;;
  esac
  cases=$((cases + 1))

  for forbidden in 203.0.113.9 198.51.100.7 192.0.2.44 3f2b8c14 AAAABBBBCCCC /v1/keys/3f2b8c14; do
    case "$summary" in
    *"$forbidden"*) fail "self-test: the summary leaked '$forbidden' — an alert must carry counts, not log content" ;;
    esac
    cases=$((cases + 1))
  done

  # And the emitter itself must not pass content through. Positive control: it
  # does emit the count, so a redactor that printed nothing at all would fail.
  rendered="$(note 1 "auth failures" "401=1 429=1 over 4 requests" 2>&1)"
  case "$rendered" in
  *"401=1"*) : ;;
  *) fail "self-test: the emitter dropped the count it is supposed to report" ;;
  esac
  case "$rendered" in
  *203.0.113.9*|*3f2b8c14*) fail "self-test: the emitter passed log content through" ;;
  esac
  cases=$((cases + 2))

  # The double-zero defect, pinned. `grep -c` prints 0 and exits 1 on no match,
  # so the obvious idiom yields "0\n0" and every integer test downstream dies
  # with "integer expression expected". It reached the live box before it was
  # caught, so it gets an assertion rather than a comment.
  empty_count="$(printf '' | count_matching 'nothing')"
  [ "$empty_count" = "0" ] ||
    fail "self-test: counting an empty stream produced '${empty_count}', not a single 0"
  [ "$(printf 'a\nb\na\n' | count_matching 'a')" = "2" ] ||
    fail "self-test: counting a matching stream miscounted"
  # It must be usable as an integer, which is the property that actually broke.
  [ "$empty_count" -eq 0 ] 2>/dev/null ||
    fail "self-test: the count is not usable in an integer comparison"
  cases=$((cases + 3))

  echo "  ok    self-test: ${cases} cases — thresholds fire both ways, counts stay integers, and alerts carry counts, never log content"
  exit 0
fi

echo "cipher relay monitor — $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- 1. certificate expiry ----------------------------------------------------
# The pinned-SPKI disaster is a separate check (Scripts/verify-pins.sh); this is
# only "does the certificate expire soon", which is the boring failure that takes
# the service down anyway.
expiry_raw="$(echo | openssl s_client -connect "$HOST:443" -servername "$HOST" 2>/dev/null |
  openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)"
if [ -n "$expiry_raw" ]; then
  expiry_epoch="$(date -d "$expiry_raw" +%s 2>/dev/null || echo '')"
  now_epoch="$(date +%s)"
  if [ -n "$expiry_epoch" ]; then
    days=$(( (expiry_epoch - now_epoch) / 86400 ))
    note "$(sev_for_days "$days")" "cert expiry" "${days}d remaining"
  else
    note 2 "cert expiry" "expiry date unparseable"
  fi
else
  note 2 "cert expiry" "could not read the served certificate"
fi

# --- 2. disk ------------------------------------------------------------------
# The relay stores blobs and Postgres data on this volume; a full disk is a
# silent write failure, not an outage that announces itself.
used_pct="$(df -P / | awk 'NR==2 {gsub("%","",$5); print $5}')"
note "$(sev_for_pct "$used_pct")" "disk" "${used_pct}% used"

# --- 3. containers ------------------------------------------------------------
# Health only says something is serving — the 2026-08-11 deploy trap. So the
# check is "all three healthy", and the deploy row in RUNBOOK-VPS.md owns the
# separate question of whether it is the *right* binary.
if cd "$COMPOSE_DIR" 2>/dev/null; then
  total_c="$(docker compose ps --format '{{.Service}}' 2>/dev/null | count_matching .)"
  healthy_c="$(docker compose ps --format '{{.Status}}' 2>/dev/null | count_matching 'healthy')"
  if [ "$total_c" -gt 0 ] && [ "$healthy_c" = "$total_c" ]; then
    note 0 "containers" "${healthy_c}/${total_c} healthy"
  else
    note 2 "containers" "${healthy_c}/${total_c} healthy"
  fi
else
  note 2 "containers" "compose directory unreadable"
fi

# --- 4. relay errors ----------------------------------------------------------
# A COUNT over the last hour, never the lines. An error line can carry a `reason`
# (BACKEND.md §7), so echoing one into an alert would move operational detail
# into a record that outlives the log's 24h.
if [ -n "${total_c:-}" ] && [ "${total_c:-0}" -gt 0 ]; then
  err_n="$(docker compose logs --since 1h --no-color api 2>/dev/null | count_matching '"level":"ERROR"')"
  note "$(sev_for_errors "$err_n")" "relay errors" "${err_n} in the last hour"
fi

# --- 5. auth anomalies and throttling ----------------------------------------
# Aggregates over the access log the relay already writes. A spike in 401s is the
# signal an operator acts on; *which* account or address produced them is exactly
# the correlation §7 refuses to make, so it is not computed here either.
if [ -r "$ACCESS_LOG" ]; then
  read -r a_total a_parsed a_4xx a_401 a_429 <<<"$(summarise_access_log <"$ACCESS_LOG")"
  if [ "$a_total" -gt 0 ] && [ "$a_parsed" -eq 0 ]; then
    # Never report "401=0" from a file we could not read. See summarise_access_log.
    note 1 "auth failures" "log format not recognised — scanned ${a_total} lines, parsed 0"
  else
    auth_sev=0
    [ "$a_401" -ge 50 ] && auth_sev=1
    [ "$a_401" -ge 500 ] && auth_sev=2
    note "$auth_sev" "auth failures" "401=${a_401} of ${a_parsed} parsed requests"
    note 0 "throttling" "429=${a_429}, 4xx=${a_4xx}"
  fi
else
  note 1 "access log" "not readable at the configured path"
fi

echo
case "$WORST" in
0) echo "status: OK" ;;
1) echo "status: WARN" ;;
2) echo "status: CRITICAL" ;;
esac
exit "$WORST"
