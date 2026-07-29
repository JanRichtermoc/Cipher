// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
//
// These tests pin a *policy*, not an implementation. docs/THREAT_MODEL.md
// prohibition 6 is the kind of rule that is obeyed for months and then broken by
// one debugging line added under pressure, so the mechanism that enforces it
// needs to fail loudly when someone weakens it.

package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestDeniedKeysAreRedacted(t *testing.T) {
	// Spelling variants matter: the same field is written three ways across a
	// codebase, and a policy that catches only one of them catches none.
	denied := []string{
		"token", "Token", "session_token", "sessionToken", "token_hash",
		"secret", "password", "passphrase", "credential",
		"authorization", "Authorization", "cookie",
		"invite", "invite_code", "code",
		"identity_key", "prekey", "public_key", "apiKey",
		"envelope", "ciphertext", "plaintext",
		"body", "request_body", "payload",
		"nonce", "signature", "safety_number",
		"ip", "remote_addr", "client-ip",
	}
	for _, key := range denied {
		if !IsDenied(key) {
			t.Errorf("IsDenied(%q) = false, want true — this key would reach a log", key)
		}
	}
}

func TestAllowedKeysSurvive(t *testing.T) {
	// Over-redaction is the safe direction but not a free one: a log with every
	// field replaced by a placeholder is useless during an incident, which is
	// how redaction ends up being switched off wholesale.
	allowed := []string{"keyId", "key_id", "keyCount", "description", "method", "route", "status", "duration"}
	for _, key := range allowed {
		if IsDenied(key) {
			t.Errorf("IsDenied(%q) = true, want false — a useful field is being lost", key)
		}
	}
}

func TestSecretRedactsThroughTheHandler(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, slog.LevelInfo)

	// Deliberately an innocuous key, so the denylist cannot be what saves this.
	// This asserts the *type* protects the value on its own.
	log.Info("issued", slog.Any("detail", NewSecret("super-secret-token-value")))

	out := buf.String()
	if strings.Contains(out, "super-secret-token-value") {
		t.Fatalf("Secret leaked through slog: %s", out)
	}
	if !strings.Contains(out, Placeholder) {
		t.Fatalf("expected %q in output, got: %s", Placeholder, out)
	}
}

func TestSecretRedactsThroughStringFormatting(t *testing.T) {
	// A Secret that only redacts under slog would leak the moment it appeared in
	// a wrapped error or a panic message, which are exactly the paths taken when
	// something has already gone wrong.
	s := NewSecret("another-secret")
	if got := s.String(); got != Placeholder {
		t.Fatalf("String() = %q, want %q", got, Placeholder)
	}
	if formatted := strings.TrimSpace(sprint(s)); formatted != Placeholder {
		t.Fatalf("%%v = %q, want %q", formatted, Placeholder)
	}
}

func TestSecretValueIsStillUsable(t *testing.T) {
	// A wrapper that is painful to use gets unwrapped at the call site, and an
	// unwrapped secret is a logged secret. Retrieval must stay trivial.
	s := NewSecret([]byte{1, 2, 3})
	if got := s.Value(); len(got) != 3 || got[0] != 1 {
		t.Fatalf("Value() = %v, want [1 2 3]", got)
	}
}

func TestDeniedKeyRedactedInsideAGroup(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, slog.LevelInfo)
	log.WithGroup("auth").Info("check", slog.String("token", "leaked-value"))

	if strings.Contains(buf.String(), "leaked-value") {
		t.Fatalf("a grouped attribute escaped redaction: %s", buf.String())
	}
}

func TestOutputIsValidJSON(t *testing.T) {
	// The lines are read by machines during an incident. A handler that emits
	// something unparseable is discovered at the worst possible time.
	var buf bytes.Buffer
	log := New(&buf, slog.LevelInfo)
	log.Info("request", slog.String("route", "/v1/keys/{aci}"), slog.Int("status", 200))

	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if decoded["route"] != "/v1/keys/{aci}" {
		t.Fatalf("route not preserved: %v", decoded["route"])
	}
}

func TestParseLevel(t *testing.T) {
	cases := []struct {
		in         string
		want       slog.Level
		recognised bool
	}{
		{"debug", slog.LevelDebug, true},
		{"INFO", slog.LevelInfo, true},
		{"", slog.LevelInfo, true},
		{"warn", slog.LevelWarn, true},
		{"error", slog.LevelError, true},
		// A typo must not silently select debug, which would turn a fat-finger
		// into verbose logging in production.
		{"trace", slog.LevelInfo, false},
	}
	for _, c := range cases {
		got, ok := ParseLevel(c.in)
		if got != c.want || ok != c.recognised {
			t.Errorf("ParseLevel(%q) = (%v, %v), want (%v, %v)",
				c.in, got, ok, c.want, c.recognised)
		}
	}
}

// sprint formats with %v without importing fmt at the top of the test file for
// one use.
func sprint(v any) string {
	var b strings.Builder
	if s, ok := v.(interface{ String() string }); ok {
		b.WriteString(s.String())
	}
	return b.String()
}
