// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only

// Package pushtoken encrypts APNs device tokens at rest under a key that lives
// only in the service environment and never in the database.
//
// # Why encryption and not hashing
//
// The token is replayed verbatim to APNs, so a one-way function cannot be used.
// docs/THREAT_MODEL.md §3.3 originally asked for hashing and was amended when
// that turned out to be unbuildable (AUDIT 6.10); this package is the amended
// position, not a weakening of the original one.
//
// # What it defends against, and what it does not
//
// A Postgres dump, a filesystem backup, or a stolen read replica is not enough
// on its own: the key is not in any of them. It does **not** defeat §1.1 host
// seizure, where the process environment is taken with the disk. The controls
// that work there are the two §3.3 also names — rotate the token, and delete it
// with the account — and both are implemented beside this, in the store.
//
// # AES-256-GCM, not the XChaCha20-Poly1305 the schema first specified
//
// docs/BACKEND.md §2.9 and the original migration specified XChaCha20-Poly1305,
// which is why `token_nonce` was 24 bytes wide. That algorithm is not reachable
// from the Go standard library: `chacha20poly1305` exists in the toolchain only
// as the standard library's own vendored copy under `vendor/golang.org/x/crypto`
// and cannot be imported by this module. Building it as documented would mean
// adding `golang.org/x/crypto` as the relay's first cryptographic dependency,
// which is a supply-chain decision rather than an implementation detail.
//
// AES-256-GCM is in `crypto/cipher`, is what the rest of this deployment's TLS
// already relies on, and costs nothing new to review. The nonce is 96 bits, the
// size the construction is specified and analysed for, so migration 0002 narrows
// the column's CHECK to match. The table has never held a row, so nothing is
// re-encrypted and nothing is lost.
//
// Nonces are random per write. With a fresh 96-bit nonce per row and one row per
// account, the birthday bound is far beyond anything this deployment approaches
// — a private circle rotating tokens has a handful of writes per account per
// year, against a bound measured in billions.
package pushtoken

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

// keyInfo domain-separates this key from anything else derived from the same
// secret. Changing it makes every stored token unopenable, which is why it is a
// constant with a version in it rather than a string literal at the call site.
const keyInfo = "cipher-relay push-token key v1"

// KeyBytes is the AES-256 key size. The configuration layer enforces a minimum
// input length; this is what the key is derived to.
const KeyBytes = 32

// NonceBytes is GCM's standard 96-bit nonce, and the width migration 0002
// constrains `push_tokens.token_nonce` to.
const NonceBytes = 12

// MaxTokenBytes bounds what will be sealed.
//
// An APNs device token is 32 bytes rendered as 64 hex characters, and newer
// formats are longer but nothing near this. The bound exists so a caller cannot
// turn this into a general-purpose blob store by handing it something large, and
// so a malformed value is refused before it reaches the database.
const MaxTokenBytes = 512

// ErrNoKey is returned when the service was started without a push-token key.
//
// Deliberately an error rather than a silent pass-through: a relay with no key
// must refuse to store a token, never store it in the clear. Push is not enabled
// until P8, so absent is the expected state today and it is not a startup
// failure — it is a failure at the point where a token would have been written.
var ErrNoKey = errors.New("push token key is not configured")

// ErrMalformed is returned when stored bytes do not decrypt, or when a caller
// offers a token that cannot be stored.
var ErrMalformed = errors.New("push token is malformed")

// Cipher seals and opens device tokens. Safe for concurrent use.
type Cipher struct {
	aead cipher.AEAD
}

// New derives a cipher from the configured secret.
//
// The key material is hashed to exactly 32 bytes rather than requiring the
// operator to supply raw AES key bytes, matching how RELAY_RATELIMIT_PEPPER is
// handled: an operator may reasonably produce either `openssl rand -hex 32` or a
// passphrase, and a configuration that only accepts one of those is a
// configuration that gets worked around.
func New(secret []byte) (*Cipher, error) {
	if len(secret) < KeyBytes {
		return nil, fmt.Errorf("%w: need at least %d bytes of key material",
			ErrNoKey, KeyBytes)
	}

	// HKDF rather than a bare hash, for domain separation: an operator who reuses
	// one value for this and for RELAY_RATELIMIT_PEPPER should not end up with a
	// rate-limit subject key that is also the key opening every push token.
	key, err := hkdf.Key(sha256.New, secret, nil, keyInfo, KeyBytes)
	if err != nil {
		return nil, fmt.Errorf("push token key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("push token cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("push token cipher: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// Seal encrypts a token, returning the ciphertext and the nonce it was sealed
// under. Both are stored; only the nonce is not secret.
//
// `aci` is bound in as additional data, so a ciphertext lifted out of one row
// and written into another does not open. Without it, anyone with write access
// to the table could point an account's push registration at somebody else's
// device — a redirection that no amount of encryption on the value itself would
// notice, because the value would still be perfectly valid.
func (c *Cipher) Seal(aci [16]byte, token string) (ciphertext, nonce []byte, err error) {
	if c == nil {
		return nil, nil, ErrNoKey
	}
	if token == "" || len(token) > MaxTokenBytes {
		return nil, nil, fmt.Errorf("%w: %d bytes", ErrMalformed, len(token))
	}

	nonce = make([]byte, NonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("push token nonce: %w", err)
	}

	ciphertext = c.aead.Seal(nil, nonce, []byte(token), aci[:])
	return ciphertext, nonce, nil
}

// Open reverses Seal, refusing anything that does not authenticate.
func (c *Cipher) Open(aci [16]byte, ciphertext, nonce []byte) (string, error) {
	if c == nil {
		return "", ErrNoKey
	}
	if len(nonce) != NonceBytes {
		return "", fmt.Errorf("%w: nonce is %d bytes", ErrMalformed, len(nonce))
	}

	plaintext, err := c.aead.Open(nil, nonce, ciphertext, aci[:])
	if err != nil {
		// The underlying error is deliberately not wrapped: it distinguishes
		// nothing a caller may act on, and an authentication failure is an
		// authentication failure whether the key is wrong, the row was moved
		// between accounts, or the bytes were edited.
		return "", ErrMalformed
	}
	if len(plaintext) > MaxTokenBytes {
		return "", ErrMalformed
	}
	return string(plaintext), nil
}
