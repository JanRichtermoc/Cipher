// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
//
// AUDIT 5.28: LookupSession used to swallow a failed `last_seen` write entirely.
// That was harmless while nothing read the column and became an active-account-
// deletion path the moment the abandonment sweep existed, so the failure now
// reaches a caller that has a logger.
//
// What is tested here is the *reporting*, which is the part with a cost. A
// warning on every authenticated request would be a request record, and
// docs/BACKEND.md §7 is explicit that log volume is itself metadata — so the
// throttle is a privacy control and not a tidiness one.

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"cipher.relay/internal/logging"
)

// capturingHandler builds a handler over a buffer, with the relay's redaction.
func capturingHandler(t *testing.T) (*AuthHandler, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	return &AuthHandler{log: logging.New(&buf, slog.LevelDebug)}, &buf
}

func countLines(buf *bytes.Buffer) int {
	trimmed := strings.TrimSpace(buf.String())
	if trimmed == "" {
		return 0
	}
	return len(strings.Split(trimmed, "\n"))
}

// TestTheFirstActivityFailureIsReported is the positive control.
//
// Every assertion below is about a line NOT appearing, and "no line" is also what
// a broken logger produces. This proves the warning is emitted at all, so the
// suppression tests are about the throttle rather than about silence (AUDIT R2).
func TestTheFirstActivityFailureIsReported(t *testing.T) {
	h, buf := capturingHandler(t)

	h.reportLastSeenFailure(context.Background())

	if countLines(buf) != 1 {
		t.Fatalf("the first activity-refresh failure produced %d log lines, want 1: %s",
			countLines(buf), buf.String())
	}
	if !strings.Contains(buf.String(), "abandonment sweep") {
		t.Fatalf("the warning does not say what the consequence is: %s", buf.String())
	}
}

// TestRepeatedActivityFailuresAreSuppressed is the reason the throttle exists.
//
// A failing refresh leaves `last_seen` stale, so every subsequent authenticated
// request retries the same write and fails the same way. Unthrottled, the warning
// would arrive once per request — a count of who was talking to the relay,
// written by the code that exists to avoid keeping that.
func TestRepeatedActivityFailuresAreSuppressed(t *testing.T) {
	h, buf := capturingHandler(t)

	for range 50 {
		h.reportLastSeenFailure(context.Background())
	}

	if got := countLines(buf); got != 1 {
		t.Fatalf("50 failures produced %d log lines; the warning scales with request "+
			"volume and is therefore a request record (docs/BACKEND.md §7)", got)
	}
}

// TestTheActivityWarningReturnsAfterTheInterval keeps suppression from becoming
// silence.
//
// A throttle that only ever logs once would hide a fault that started an hour
// after the process did, which is the realistic case: the relay comes up
// healthy and the database privilege is changed later.
func TestTheActivityWarningReturnsAfterTheInterval(t *testing.T) {
	h, buf := capturingHandler(t)

	h.reportLastSeenFailure(context.Background())
	// Move the recorded time back past the interval rather than sleeping for it:
	// a test that waits out a real minute is a test that gets deleted.
	h.lastSeenWarnedAt.Store(time.Now().Add(-2 * lastSeenWarnInterval).UnixNano())
	h.reportLastSeenFailure(context.Background())

	if got := countLines(buf); got != 2 {
		t.Fatalf("the warning did not return after the interval: %d lines, want 2", got)
	}
}

// TestTheActivityWarningNamesNoAccount is the privacy assertion.
//
// `aci` is not logged at info level (docs/BACKEND.md §7) and the redaction
// denylist does not cover it — "aci" contains none of the denied substrings — so
// a field naming the affected account would pass straight through the handler and
// onto disk. Asserted by decoding the record rather than by reading the source,
// because the question is what was written.
func TestTheActivityWarningNamesNoAccount(t *testing.T) {
	h, buf := capturingHandler(t)

	h.reportLastSeenFailure(context.Background())

	var record map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &record); err != nil {
		t.Fatalf("the warning is not valid JSON: %v (%s)", err, buf.String())
	}
	for key := range record {
		switch strings.ToLower(key) {
		case "aci", "account", "recipient", "subject", "uuid":
			t.Fatalf("the warning carries %q, which makes it a per-account activity "+
				"record: %s", key, buf.String())
		}
	}
}
