// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestGenerateCarriesTheDeclaredEntropy(t *testing.T) {
	tok, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(tok.String())
	if err != nil {
		t.Fatalf("generated token is not raw base64url: %v", err)
	}
	if len(raw) != TokenBytes {
		t.Fatalf("token carries %d bytes, TokenBytes claims %d", len(raw), TokenBytes)
	}
}

func TestGeneratedTokensAreDistinct(t *testing.T) {
	seen := make(map[string]bool, 500)
	for range 500 {
		tok, err := Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if seen[tok.String()] {
			t.Fatal("Generate returned a duplicate token")
		}
		seen[tok.String()] = true
	}
}

func TestGeneratedTokensAreHeaderSafe(t *testing.T) {
	// The token travels in an Authorization header. `+`, `/` and `=` are all
	// characters something between here and the client eventually tries to
	// escape, which is why this is RawURLEncoding rather than StdEncoding.
	for range 200 {
		tok, err := Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if strings.ContainsAny(tok.String(), "+/= \t\r\n") {
			t.Fatalf("token contains a character that needs escaping: %q", tok.String())
		}
	}
}

func TestParseRoundTrips(t *testing.T) {
	tok, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	parsed, err := Parse(tok.String())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.String() != tok.String() {
		t.Fatal("round trip changed the token")
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	valid, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	s := valid.String()

	cases := map[string]string{
		"empty":            "",
		"whitespace":       "   ",
		"too short":        s[:len(s)-2],
		"too long":         s + "AA",
		"not base64":       strings.Repeat("!", len(s)),
		"padded std":       base64.StdEncoding.EncodeToString(make([]byte, TokenBytes)),
		"wrong byte count": base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
	}
	for name, in := range cases {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%s) accepted %q", name, in)
		}
	}
}

func TestParseBearer(t *testing.T) {
	tok, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	accepted := map[string]string{
		"canonical":  "Bearer " + tok.String(),
		"lowercase":  "bearer " + tok.String(),
		"mixed case": "BeArEr " + tok.String(),
	}
	for name, header := range accepted {
		got, err := ParseBearer(header)
		if err != nil {
			t.Errorf("ParseBearer(%s): %v", name, err)
			continue
		}
		if got.String() != tok.String() {
			t.Errorf("ParseBearer(%s) returned the wrong token", name)
		}
	}

	rejected := map[string]string{
		"empty":           "",
		"scheme only":     "Bearer ",
		"no scheme":       tok.String(),
		"wrong scheme":    "Basic " + tok.String(),
		"basic-ish":       "Bearer" + tok.String(), // no space
		"malformed token": "Bearer !!!!",
	}
	for name, header := range rejected {
		if _, err := ParseBearer(header); err == nil {
			t.Errorf("ParseBearer(%s) accepted %q", name, header)
		}
	}
}

func TestEveryMalformationReturnsTheSameError(t *testing.T) {
	// The caller must render all of these as one 401. Distinguishing them would
	// tell an attacker which guesses had the right shape.
	for _, in := range []string{"", "x", strings.Repeat("!", 43)} {
		if _, err := Parse(in); err != ErrMalformedToken {
			t.Errorf("Parse(%q) = %v, want ErrMalformedToken exactly", in, err)
		}
	}
	for _, in := range []string{"", "Basic abc", "Bearer "} {
		if _, err := ParseBearer(in); err != ErrMalformedToken {
			t.Errorf("ParseBearer(%q) = %v, want ErrMalformedToken exactly", in, err)
		}
	}
}

func TestHashIsSHA256OfTheToken(t *testing.T) {
	tok, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	want := sha256.Sum256([]byte(tok.String()))
	if string(tok.Hash()) != string(want[:]) {
		t.Fatal("Hash is not SHA-256 of the token")
	}
	if len(tok.Hash()) != sha256.Size {
		t.Fatalf("hash is %d bytes, want %d", len(tok.Hash()), sha256.Size)
	}
}

func TestHashRoundTripsThroughParse(t *testing.T) {
	// Verification hashes what the client sent, so a token that survives Parse
	// must hash to the same value it had at issuance — otherwise every request
	// would look like an unknown token.
	tok, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	parsed, err := ParseBearer("Bearer " + tok.String())
	if err != nil {
		t.Fatalf("ParseBearer: %v", err)
	}
	if string(parsed.Hash()) != string(tok.Hash()) {
		t.Fatal("a parsed token hashes differently from the issued one")
	}
}

func TestHashDoesNotContainTheToken(t *testing.T) {
	tok, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if strings.Contains(string(tok.Hash()), tok.String()) {
		t.Fatal("the hash contains the token")
	}
}

func TestZeroToken(t *testing.T) {
	var tok Token
	if !tok.IsZero() {
		t.Error("the zero Token should report IsZero")
	}
	if tok.String() != "" {
		t.Errorf("zero Token String() = %q, want empty", tok.String())
	}
}
