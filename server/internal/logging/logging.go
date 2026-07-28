// Package logging provides the relay's structured logger.
//
// docs/THREAT_MODEL.md prohibition 6 forbids logging private keys, session or
// ratchet state, plaintext, tokens, invite codes, safety numbers, or raw addresses.
// docs/BACKEND.md §7 adds request bodies, envelope bytes, push tokens, and IP
// addresses beyond a short TTL.
//
// A prohibition enforced by remembering is a prohibition that will be violated
// during the one incident where someone adds a log line to debug something at
// 2am. So this package enforces it two ways, neither of which relies on care:
//
//  1. [Secret] wraps a sensitive value and renders as "[redacted]" whatever the
//     call site does with it. Fields typed this way cannot leak.
//  2. A key denylist in the handler redacts by attribute name, catching values
//     that were logged raw because someone did not know about (1).
//
// Neither is sufficient alone. (1) misses values that were never wrapped; (2)
// misses sensitive values under an innocuous key. Together they cover the
// realistic mistakes.
//
// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
package logging

import (
	"io"
	"log/slog"
	"strings"
)

// Placeholder substituted for every redacted value. Fixed length and content:
// varying it by input would turn the log into an oracle for the value it hides.
const Placeholder = "[redacted]"

// Secret wraps a value that must never reach a log.
//
// It implements [slog.LogValuer], so slog renders the placeholder no matter how
// the value is passed. Use it for tokens, invite codes, push tokens, key
// material, and envelope bytes.
//
// The type parameter keeps the wrapped value usable without a cast at the point
// of use, which matters: a wrapper that is annoying gets unwrapped, and an
// unwrapped secret is a logged secret.
type Secret[T any] struct {
	value T
}

// NewSecret wraps v.
func NewSecret[T any](v T) Secret[T] { return Secret[T]{value: v} }

// Value returns the wrapped value. Call it where the value is *used*, never
// where it is logged.
func (s Secret[T]) Value() T { return s.value }

// LogValue implements [slog.LogValuer].
func (s Secret[T]) LogValue() slog.Value { return slog.StringValue(Placeholder) }

// String implements [fmt.Stringer], so %s and %v in a non-slog path — a panic
// message, a wrapped error — redact too. Without this the type would protect
// only the path it was designed for and quietly fail on every other.
func (s Secret[T]) String() string { return Placeholder }

// deniedKeys are attribute names whose values are redacted regardless of type.
//
// Matching is on a normalised key (lowercased, separators stripped) and is a
// substring test, so "session_token", "sessionToken", and "tokenHash" all match
// "token". Over-redaction is the acceptable failure direction here: a log line
// missing a field is an inconvenience, and a log line containing a session token
// is a credential on disk.
var deniedKeys = []string{
	"token",
	"secret",
	"password",
	"passphrase",
	"credential",
	"authorization",
	"cookie",
	"invite",
	"code",
	"key", // covers identity_key, prekey, apikey; see allowedKeys for exceptions
	"envelope",
	"ciphertext",
	"plaintext",
	"body",
	"payload",
	"nonce",
	"signature",
	"safetynumber",
	"ip",
	"remoteaddr",
}

// allowedKeys are exact normalised names that survive the substring test above.
//
// Without this, "key" would redact "keyid" — a per-account counter that is not
// sensitive and is genuinely useful in a log — and "ip" would redact
// "description". Each entry is an explicit decision that the named field is safe.
var allowedKeys = map[string]struct{}{
	"keyid":       {}, // a counter local to one account
	"keycount":    {}, // remaining prekey pool size
	"description": {},
	"skipped":     {},
}

func normalise(key string) string {
	var b strings.Builder
	b.Grow(len(key))
	for _, r := range key {
		switch {
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		case r == '_' || r == '-' || r == '.' || r == ' ':
			// separators dropped so snake_case and camelCase normalise alike
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// IsDenied reports whether an attribute with this key would be redacted.
// Exported so the policy is directly testable rather than only observable
// through rendered output.
func IsDenied(key string) bool {
	n := normalise(key)
	if _, ok := allowedKeys[n]; ok {
		return false
	}
	for _, denied := range deniedKeys {
		if strings.Contains(n, denied) {
			return true
		}
	}
	return false
}

func redact(groups []string, a slog.Attr) slog.Attr {
	// Groups are not consulted: a key is sensitive by its own name, and a value
	// under a group is no less sensitive for it.
	_ = groups
	if IsDenied(a.Key) {
		return slog.String(a.Key, Placeholder)
	}
	return a
}

// New returns the relay's logger: JSON to w, at level, with redaction applied.
//
// JSON rather than text because these lines are read by machines during an
// incident, and because a text encoder that has to escape a value is one more
// place a raw value can appear.
func New(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level:       level,
		ReplaceAttr: redact,
	}))
}

// ParseLevel maps a configuration string to a level, defaulting to info.
//
// An unrecognised value returns info and false rather than an error: a
// mistyped log level must not prevent the relay from starting, but it must not
// silently select debug either. The caller logs the fallback.
func ParseLevel(s string) (slog.Level, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, true
	case "", "info":
		return slog.LevelInfo, true
	case "warn", "warning":
		return slog.LevelWarn, true
	case "error":
		return slog.LevelError, true
	default:
		return slog.LevelInfo, false
	}
}
