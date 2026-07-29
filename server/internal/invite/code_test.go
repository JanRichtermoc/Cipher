// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only

package invite

import (
	"crypto/sha256"
	"strings"
	"testing"
)

func TestGenerateProducesTheDeclaredEntropy(t *testing.T) {
	// docs/BACKEND.md §2.2 argues that plain SHA-256 is sufficient *because* the
	// code carries 128 bits. If the code is shorter than claimed, that argument
	// silently becomes wrong and the stored hash becomes brute-forceable.
	c, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if got := len(c.canonical); got != codeLen {
		t.Fatalf("canonical length = %d, want %d", got, codeLen)
	}
	// 32 symbols carry 5 bits each.
	if bits := codeLen * 5; bits < EntropyBits {
		t.Fatalf("code carries %d bits, EntropyBits claims %d", bits, EntropyBits)
	}
}

func TestGenerateUsesOnlyTheAlphabet(t *testing.T) {
	for range 200 {
		c, err := Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		for _, r := range c.canonical {
			if !strings.ContainsRune(alphabet, r) {
				t.Fatalf("generated code contains %q, which is outside the alphabet", r)
			}
		}
	}
}

func TestAlphabetExcludesAmbiguousSymbols(t *testing.T) {
	// The whole point of Crockford base32. If these creep back in, codes read
	// aloud stop round-tripping and the transcription mapping in Parse becomes
	// ambiguous rather than helpful.
	for _, r := range "ILOU" {
		if strings.ContainsRune(alphabet, r) {
			t.Errorf("alphabet contains %q, which is visually ambiguous", r)
		}
	}
	if len(alphabet) != 32 {
		t.Fatalf("alphabet has %d symbols; 32 is what makes the 5-bit mask unbiased",
			len(alphabet))
	}
}

func TestGeneratedCodesAreDistinct(t *testing.T) {
	// A weak generator — a misplaced seed, a reused buffer — usually shows up as
	// repetition long before it shows up as anything subtler.
	seen := make(map[string]bool, 500)
	for range 500 {
		c, err := Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if seen[c.canonical] {
			t.Fatalf("Generate returned a duplicate: %s", c)
		}
		seen[c.canonical] = true
	}
}

func TestParseRoundTripsGeneratedCodes(t *testing.T) {
	for range 100 {
		c, err := Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		// String() is the grouped form the user actually sees and retypes.
		parsed, err := Parse(c.String())
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.String(), err)
		}
		if parsed.canonical != c.canonical {
			t.Fatalf("round trip changed the code: %q -> %q", c.canonical, parsed.canonical)
		}
	}
}

func TestParseNormalisesTranscription(t *testing.T) {
	c, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	canonical := c.canonical

	variants := map[string]string{
		"grouped":       c.String(),
		"lowercase":     strings.ToLower(canonical),
		"spaces":        strings.Join(strings.Split(canonical, ""), " "),
		"surrounded":    "  " + canonical + "\n",
		"mixed hyphens": strings.ToLower(c.String()),
	}
	for name, in := range variants {
		got, err := Parse(in)
		if err != nil {
			t.Errorf("Parse(%s): %v", name, err)
			continue
		}
		if got.canonical != canonical {
			t.Errorf("Parse(%s) = %q, want %q", name, got.canonical, canonical)
		}
	}
}

func TestParseAppliesCrockfordSubstitutions(t *testing.T) {
	// I and L read as 1, O reads as 0. Applied on input only — Generate never
	// emits them — so this widens what is accepted without widening the key
	// space, which is the property that makes it safe.
	base := strings.Repeat("2", codeLen)

	for _, sub := range []struct{ typed, means byte }{
		{'I', '1'}, {'L', '1'}, {'O', '0'},
		{'i', '1'}, {'l', '1'}, {'o', '0'},
	} {
		typed := string(sub.typed) + base[1:]
		want := string(sub.means) + base[1:]

		got, err := Parse(typed)
		if err != nil {
			t.Errorf("Parse(%q): %v", typed, err)
			continue
		}
		if got.canonical != want {
			t.Errorf("Parse(%q) = %q, want %q", typed, got.canonical, want)
		}
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	valid := strings.Repeat("2", codeLen)

	cases := map[string]string{
		"empty":               "",
		"too short":           valid[:codeLen-1],
		"too long":            valid + "2",
		"non-alphabet symbol": valid[:codeLen-1] + "!",
		"unicode":             valid[:codeLen-1] + "é",
		"only separators":     strings.Repeat("-", codeLen),
	}
	for name, in := range cases {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%s) accepted %q", name, in)
		}
	}
}

func TestParseReturnsOneErrorForEveryMalformation(t *testing.T) {
	// A caller that could tell "wrong length" from "bad symbol" would leak,
	// through its response, which part of a guess was wrong.
	for _, in := range []string{"", "2", strings.Repeat("!", codeLen)} {
		_, err := Parse(in)
		if err != ErrMalformed {
			t.Errorf("Parse(%q) = %v, want ErrMalformed exactly", in, err)
		}
	}
}

func TestHashIsOfTheCanonicalForm(t *testing.T) {
	// Two users typing the same code differently must hit the same row. If Hash
	// were computed over the entered string, "abc-de" and "ABCDE" would be
	// different invites and redemption would fail for reasons nobody could see.
	c, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	grouped, err := Parse(c.String())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	lower, err := Parse(strings.ToLower(c.canonical))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	want := sha256.Sum256([]byte(c.canonical))
	for name, got := range map[string][]byte{
		"generated": c.Hash(),
		"grouped":   grouped.Hash(),
		"lowercase": lower.Hash(),
	} {
		if string(got) != string(want[:]) {
			t.Errorf("%s hash differs from the canonical hash", name)
		}
	}
}

func TestHashDoesNotContainTheCode(t *testing.T) {
	// Belt and braces against a future "optimisation" that stores a prefix
	// alongside the hash to speed up lookups.
	c, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if strings.Contains(string(c.Hash()), c.canonical) {
		t.Fatal("the hash contains the code")
	}
	if len(c.Hash()) != sha256.Size {
		t.Fatalf("hash is %d bytes, want %d", len(c.Hash()), sha256.Size)
	}
}

func TestStringGroupsForTranscription(t *testing.T) {
	c, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	s := c.String()

	if !strings.Contains(s, "-") {
		t.Fatalf("String() = %q, expected hyphen-separated groups", s)
	}
	for _, group := range strings.Split(s, "-") {
		if len(group) > groupSize {
			t.Fatalf("group %q is longer than %d symbols", group, groupSize)
		}
	}
	if strings.ReplaceAll(s, "-", "") != c.canonical {
		t.Fatal("String() is not the canonical form plus separators")
	}
}

func TestZeroCode(t *testing.T) {
	var c Code
	if !c.IsZero() {
		t.Error("the zero Code should report IsZero")
	}
	if c.String() != "" {
		t.Errorf("zero Code String() = %q, want empty", c.String())
	}
}
