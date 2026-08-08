// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
//
// These tests need no database. What they defend is the cipher's own contract:
// that a token round-trips, that it does not appear in the bytes that get
// stored, and that every way the stored bytes could be tampered with is refused
// rather than opened. The store-level properties — no plaintext in the column,
// deletion with the account, the rotation sweep — are in the integration suite,
// against a real PostgreSQL.

package pushtoken

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// A realistic APNs device token: 32 bytes as 64 hex characters.
const sampleToken = "740f4707bebcf74f9b7c25d48e3358945f6aa01da5ddb387462c7eaf61bb78ad"

func testKey(t *testing.T) *Cipher {
	t.Helper()
	c, err := New([]byte(strings.Repeat("k", KeyBytes)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestARoundTripReturnsTheSameToken(t *testing.T) {
	c := testKey(t)
	aci := [16]byte{1, 2, 3}

	ciphertext, nonce, err := c.Seal(aci, sampleToken)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(nonce) != NonceBytes {
		t.Fatalf("nonce is %d bytes, want %d — migration 0002 constrains the column to this",
			len(nonce), NonceBytes)
	}

	got, err := c.Open(aci, ciphertext, nonce)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got != sampleToken {
		t.Fatalf("round trip returned %q", got)
	}
}

// The property the step exists for, at the lowest level: what would be written
// to the column does not contain the token.
func TestTheStoredBytesDoNotContainTheToken(t *testing.T) {
	c := testKey(t)
	ciphertext, nonce, err := c.Seal([16]byte{9}, sampleToken)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	stored := append(append([]byte{}, ciphertext...), nonce...)
	if bytes.Contains(stored, []byte(sampleToken)) {
		t.Fatal("the token appears verbatim in what would be stored")
	}

	// Positive control: the search finds the token when it is there, so the
	// assertion above is not passing because `bytes.Contains` cannot match.
	if !bytes.Contains(append(stored, sampleToken...), []byte(sampleToken)) {
		t.Fatal("the containment check cannot find a token that is present; the check above is void")
	}
}

// Two seals of the same token must differ, or the column becomes a fingerprint:
// equal ciphertexts would tell whoever holds a dump which accounts share a
// device, and would make a token recognisable across rotations.
func TestSealingTwiceProducesDifferentBytes(t *testing.T) {
	c := testKey(t)
	aci := [16]byte{4}

	first, firstNonce, err := c.Seal(aci, sampleToken)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	second, secondNonce, err := c.Seal(aci, sampleToken)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if bytes.Equal(firstNonce, secondNonce) {
		t.Fatal("the same nonce was used twice, which is the one thing GCM must never do")
	}
	if bytes.Equal(first, second) {
		t.Fatal("the same token sealed twice produced identical ciphertext")
	}
}

// The ACI is bound in as additional data, so a row lifted into another account
// does not open. Without this, write access to the table would be enough to
// point one account's notifications at another account's device.
func TestACiphertextMovedToAnotherAccountDoesNotOpen(t *testing.T) {
	c := testKey(t)
	owner := [16]byte{1}
	other := [16]byte{2}

	ciphertext, nonce, err := c.Seal(owner, sampleToken)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if _, err := c.Open(other, ciphertext, nonce); !errors.Is(err, ErrMalformed) {
		t.Fatalf("a moved row opened, or failed wrongly: %v", err)
	}

	// Positive control: it opens for the account it was sealed for.
	if _, err := c.Open(owner, ciphertext, nonce); err != nil {
		t.Fatalf("the row does not open for its own account either: %v", err)
	}
}

func TestTamperedBytesAreRefused(t *testing.T) {
	c := testKey(t)
	aci := [16]byte{7}
	ciphertext, nonce, err := c.Seal(aci, sampleToken)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	cases := map[string]func() ([]byte, []byte){
		"flipped ciphertext bit": func() ([]byte, []byte) {
			edited := append([]byte{}, ciphertext...)
			edited[0] ^= 0x01
			return edited, nonce
		},
		"flipped nonce bit": func() ([]byte, []byte) {
			edited := append([]byte{}, nonce...)
			edited[0] ^= 0x01
			return ciphertext, edited
		},
		"truncated ciphertext": func() ([]byte, []byte) {
			return ciphertext[:len(ciphertext)-1], nonce
		},
		"short nonce": func() ([]byte, []byte) {
			return ciphertext, nonce[:NonceBytes-1]
		},
		"empty": func() ([]byte, []byte) { return nil, nonce },
	}

	for name, mutate := range cases {
		editedCiphertext, editedNonce := mutate()
		if _, err := c.Open(aci, editedCiphertext, editedNonce); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: opened or failed wrongly: %v", name, err)
		}
	}
}

// A different key must not open the row. This is the whole claim of "encrypted
// under a key held only in the service environment": a database dump taken
// without that environment is not enough.
func TestADifferentKeyDoesNotOpen(t *testing.T) {
	aci := [16]byte{3}
	ciphertext, nonce, err := testKey(t).Seal(aci, sampleToken)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	other, err := New([]byte(strings.Repeat("j", KeyBytes)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := other.Open(aci, ciphertext, nonce); !errors.Is(err, ErrMalformed) {
		t.Fatalf("another key opened the token: %v", err)
	}
}

func TestAShortOrAbsentKeyIsRefused(t *testing.T) {
	for name, secret := range map[string][]byte{
		"absent": nil,
		"empty":  {},
		"short":  []byte(strings.Repeat("k", KeyBytes-1)),
	} {
		if _, err := New(secret); !errors.Is(err, ErrNoKey) {
			t.Errorf("%s key was accepted, or failed wrongly: %v", name, err)
		}
	}
}

// A nil cipher is what a relay with no key configured holds, and it must refuse
// rather than panic: this is the current deployment, since push does not exist
// until P8.
func TestANilCipherRefusesRatherThanPanicking(t *testing.T) {
	var c *Cipher
	if _, _, err := c.Seal([16]byte{}, sampleToken); !errors.Is(err, ErrNoKey) {
		t.Errorf("Seal on an unconfigured cipher: %v", err)
	}
	if _, err := c.Open([16]byte{}, []byte{1}, make([]byte, NonceBytes)); !errors.Is(err, ErrNoKey) {
		t.Errorf("Open on an unconfigured cipher: %v", err)
	}
}

func TestAnEmptyOrOversizedTokenIsRefused(t *testing.T) {
	c := testKey(t)
	for name, token := range map[string]string{
		"empty":     "",
		"oversized": strings.Repeat("a", MaxTokenBytes+1),
	} {
		if _, _, err := c.Seal([16]byte{}, token); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s token was accepted, or failed wrongly: %v", name, err)
		}
	}

	// Positive control: exactly at the ceiling is accepted, so the refusal is
	// the bound and not the fixture.
	if _, _, err := c.Seal([16]byte{}, strings.Repeat("a", MaxTokenBytes)); err != nil {
		t.Errorf("a token at the ceiling was refused: %v", err)
	}
}
