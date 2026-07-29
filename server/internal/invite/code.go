// Package invite issues and redeems invite codes.
//
// Invite codes are the *only* way an account comes into existence, and the only
// identifier the system has (docs/THREAT_MODEL.md §3.4). There is no phone
// number, no email, no username lookup, and therefore no contact discovery and
// nothing to correlate against another service. An identifier that was never
// collected cannot be seized.
//
// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
package invite

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strings"
)

// Entropy in bits. docs/BACKEND.md §2.2 depends on this number: it is what makes
// a plain SHA-256 of the code correct rather than negligent, because preimage
// search over 2^128 is infeasible and a memory-hard KDF would buy nothing.
//
// Lowering it silently converts that reasoning into a vulnerability. Changing
// this constant should mean changing §2.2 in the same commit.
const EntropyBits = 128

// alphabet is Crockford base32: the digits and uppercase letters with I, L, O
// and U removed.
//
// I/1, L/1 and O/0 are the pairs people transcribe wrongly when reading a code
// aloud or copying it off a screen; U is excluded because its absence keeps
// accidental obscenities out of generated codes. 32 symbols carry exactly 5
// bits each, so no value is wasted and no rejection sampling is needed.
const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// codeLen is how many symbols carry EntropyBits.
//
// 128/5 is 25.6, so 26 symbols carry 130 bits and the code has at least the
// entropy claimed. Rounding down would quietly ship 125 bits while the docs said
// 128.
const codeLen = (EntropyBits + 4) / 5

// groupSize is how many symbols per hyphen-separated group when formatted.
// Groups exist only for transcription; they are stripped before parsing.
const groupSize = 5

var (
	// ErrMalformed is returned for anything that is not a well-formed code.
	//
	// One error for every kind of malformation — wrong length, bad symbol,
	// empty — on purpose. A caller that distinguished them would leak, through
	// its response, which part of a guess was wrong.
	ErrMalformed = errors.New("invite: malformed code")
)

// Code is a validated invite code in canonical (ungrouped, uppercase) form.
type Code struct {
	canonical string
}

// Generate returns a fresh code from the system CSPRNG.
//
// crypto/rand only. math/rand seeded from the clock has been the root cause of
// enough token-guessing vulnerabilities that the distinction is worth stating:
// this value is the sole gate on account creation.
func Generate() (Code, error) {
	// One byte of randomness per symbol, masked to 5 bits. Masking a uniform
	// byte to its low 5 bits is uniform over 0..31 because 32 divides 256
	// exactly — no modulo bias, and no rejection sampling needed. That property
	// is why the alphabet is 32 symbols rather than, say, 34.
	raw := make([]byte, codeLen)
	if _, err := rand.Read(raw); err != nil {
		return Code{}, err
	}

	var b strings.Builder
	b.Grow(codeLen)
	for _, v := range raw {
		b.WriteByte(alphabet[v&0x1f])
	}
	return Code{canonical: b.String()}, nil
}

// Parse accepts a user-entered code in any reasonable shape.
//
// Lowercase, hyphens, and surrounding whitespace are all normalised away. This
// is not politeness: a code is transcribed by hand from another device, and a
// parser that rejects "abcde-fghij" for a code it would accept as
// "ABCDEFGHIJ" produces a support problem whose usual resolution is someone
// shortening the code.
func Parse(s string) (Code, error) {
	var b strings.Builder
	b.Grow(len(s))

	for _, r := range strings.TrimSpace(s) {
		switch {
		case r == '-' || r == ' ':
			continue
		case r >= 'a' && r <= 'z':
			r -= 'a' - 'A'
		}

		// Crockford's transcription rules, applied on input only: the symbols
		// excluded from the alphabet are mapped to what the writer meant. This
		// is one-directional — Generate never emits these — so it widens what
		// is accepted without widening the key space.
		switch r {
		case 'I', 'L':
			r = '1'
		case 'O':
			r = '0'
		}

		if !strings.ContainsRune(alphabet, r) {
			return Code{}, ErrMalformed
		}
		b.WriteRune(r)
	}

	if b.Len() != codeLen {
		return Code{}, ErrMalformed
	}
	return Code{canonical: b.String()}, nil
}

// String returns the grouped, human-readable form.
//
// Deliberately NOT the canonical form: this is the one that gets shown, copied
// and read aloud, and groups of five are what make a 26-symbol string
// transcribable.
func (c Code) String() string {
	if c.canonical == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(c.canonical) + len(c.canonical)/groupSize)
	for i, r := range c.canonical {
		if i > 0 && i%groupSize == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Hash returns the SHA-256 of the canonical form — what the database stores.
//
// The code itself is never persisted anywhere. A database dump therefore does
// not yield working invites, which matters because an unredeemed invite is a
// live credential for creating an account.
//
// Plain SHA-256 rather than a password KDF: see EntropyBits. The code is
// machine-generated with 128 bits, so preimage search is infeasible and the
// memory-hard construction that protects low-entropy secrets would only add
// cost. That reasoning is *entirely* dependent on the entropy, which is why the
// constant and this comment reference each other.
func (c Code) Hash() []byte {
	sum := sha256.Sum256([]byte(c.canonical))
	return sum[:]
}

// IsZero reports whether this is the zero Code.
func (c Code) IsZero() bool { return c.canonical == "" }
