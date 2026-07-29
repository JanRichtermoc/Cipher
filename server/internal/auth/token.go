// Package auth issues and verifies session tokens.
//
// # Opaque and random, never a JWT
//
// docs/BACKEND.md §2.3 and the P4.S04 anti-goal both say this outright, and the
// reason is revocation. A JWT carries its claims inside itself, so the server can
// verify one without consulting any storage — which is exactly why it cannot
// *un*-verify one. Revoking a JWT means keeping a denylist that has to be checked
// on every request and that grows until every issued token has expired, so the
// design that was chosen to avoid a lookup ends up performing a lookup with worse
// properties.
//
// An opaque token is a lookup by construction. Revocation is `DELETE`, it is
// immediate, and there is no second structure to keep consistent. For a relay
// whose entire posture is "hold as little as possible for as short as possible",
// a credential that cannot be withdrawn is the wrong shape regardless of how
// convenient it is to validate.
//
// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

// TokenBytes is the raw entropy in a session token.
//
// 256 bits. As with invite codes, this number is what makes storing a plain
// SHA-256 correct rather than negligent: preimage search over 2^256 is not a
// thing, so a memory-hard KDF would add cost and buy nothing. Unlike an invite
// code, nobody ever types this, so there is no transcription pressure pushing it
// shorter.
const TokenBytes = 32

// ErrMalformedToken is returned for anything that is not a well-formed token.
//
// One error for every kind of malformation, and — more importantly — the caller
// must return the same response for this as for a token that is well-formed and
// simply unknown. See [Parse].
var ErrMalformedToken = errors.New("auth: malformed token")

// Token is a bearer credential.
//
// The raw value exists in memory on exactly two paths: at issuance, on its way to
// the client, and at verification, on its way to a hash. It is never stored, never
// logged, and never returned by an accessor that a logging call could reach — the
// only way out is [Token.String], which callers use deliberately.
type Token struct {
	raw string
}

// Generate returns a fresh token.
func Generate() (Token, error) {
	b := make([]byte, TokenBytes)
	if _, err := rand.Read(b); err != nil {
		return Token{}, err
	}
	// URL-safe and unpadded: this travels in an Authorization header, and `+`,
	// `/` and `=` are all characters that something between here and the client
	// will eventually try to escape.
	return Token{raw: base64.RawURLEncoding.EncodeToString(b)}, nil
}

// Parse validates a presented token.
//
// Structural validation only — it says nothing about whether the token exists.
// That distinction has to be invisible to the caller's *response*: a handler that
// returned 400 for a malformed token and 401 for an unknown one would let an
// attacker learn which of their guesses were at least the right shape. Both must
// be 401.
//
// The length check is not security-relevant on its own; it exists so a garbage
// header does not reach the database as a lookup.
func Parse(s string) (Token, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Token{}, ErrMalformedToken
	}

	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) != TokenBytes {
		return Token{}, ErrMalformedToken
	}
	return Token{raw: s}, nil
}

// ParseBearer extracts a token from an Authorization header value.
//
// The scheme is matched case-insensitively because RFC 9110 says it is
// case-insensitive, and a client that sends "bearer" is not an attacker, it is a
// client that read a different RFC.
func ParseBearer(header string) (Token, error) {
	const prefix = "bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return Token{}, ErrMalformedToken
	}
	return Parse(header[len(prefix):])
}

// Hash returns the SHA-256 of the token — what the database stores.
//
// The token itself is never persisted. A database dump therefore yields no
// credential that authenticates as anyone, which is the single property that
// makes `session_tokens` safe to hold at all under docs/THREAT_MODEL.md §1.1.
func (t Token) Hash() []byte {
	sum := sha256.Sum256([]byte(t.raw))
	return sum[:]
}

// String returns the raw token.
//
// Named `String` reluctantly. It satisfies fmt.Stringer, which means `%v` on a
// Token prints the credential — the opposite of what logging.Secret does. That is
// accepted because the alternative is worse: a type whose value can only be
// obtained through an awkward accessor gets copied into a plain string at the
// call site, and then nothing protects it at all.
//
// The protection is elsewhere and is structural: no Token is ever passed to a
// logging call, `logging.IsDenied` redacts every attribute whose name contains
// "token", and this value reaches exactly one place — the JSON body of the
// response that issues it.
func (t Token) String() string { return t.raw }

// IsZero reports whether this is the zero Token.
func (t Token) IsZero() bool { return t.raw == "" }
