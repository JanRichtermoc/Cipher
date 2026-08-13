// Package reauth issues and consumes the single-use challenges that let a
// device prove possession of its account key (AUDIT 5.41).
//
// # What a challenge is for
//
// Re-authentication is a signature over a value the *server* chose. Without
// that, a signature captured once could be replayed forever, and the account key
// would be a bearer token with no expiry — strictly worse than the session token
// it exists to replace.
//
// # Why Redis and not Postgres
//
// A challenge is ephemeral by construction: it is valid for two minutes and is
// consumed on first use. Putting it in Postgres would make routing-adjacent
// state durable for no benefit, which is what docs/BACKEND.md §3 keeps out of
// the database. Losing every outstanding challenge costs one retry.
//
// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
package reauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// TTL is how long a challenge remains redeemable.
//
// Short, because its only job is to span one round trip on a device that is
// already holding the key. Long enough to survive a slow network and a
// biometric prompt.
const TTL = 2 * time.Minute

// Bytes is the challenge length. 32 bytes of CSPRNG output: the same size as a
// session token, and far beyond any birthday concern over a two-minute window.
const Bytes = 32

// ErrNotRedeemable is returned when a challenge is unknown, already used, or
// expired.
//
// One error for all three, the same way store.ErrInviteNotRedeemable is: a
// caller that could distinguish them learns whether a challenge it guessed was
// ever real.
var ErrNotRedeemable = errors.New("reauth: challenge is not redeemable")

// Redis is the narrow slice of the client this package needs. Declared here
// rather than taking a concrete client so a test can drive it, and so the
// dependency is visible in one place.
type Redis interface {
	Eval(ctx context.Context, script string, keys []string, args ...any) *redis.Cmd
	Set(ctx context.Context, key string, value any, exp time.Duration) *redis.StatusCmd
}

// Store issues and consumes challenges.
type Store struct {
	rdb Redis
}

// NewStore builds a Store.
func NewStore(rdb Redis) *Store { return &Store{rdb: rdb} }

// key namespaces a challenge by the account it was issued to.
//
// **Binding the challenge to the aci is load-bearing.** Without it, a challenge
// issued for account A could be signed by account B's key and presented as A —
// which does not authenticate B as A, since the signature would then fail
// against A's stored key, but it does let a caller consume challenges issued to
// someone else. Keying by aci makes a challenge meaningless anywhere but the
// account that asked for it.
func key(aci uuid.UUID, challenge string) string {
	return "reauth:" + aci.String() + ":" + challenge
}

// consumeScript atomically deletes the challenge and reports whether it existed.
//
// A scripted DEL, not GET-then-DEL from Go: DEL returns how many keys it
// removed, so exactly one of two concurrent presentations of the same challenge
// can see 1. Same reasoning as invite redemption's
// `DELETE ... RETURNING` — single use is a property of the operation, not of the
// ordering of two of them.
const consumeScript = `
local existed = redis.call('DEL', KEYS[1])
return existed
`

// Issue mints a challenge for an account and stores it.
//
// It is called for accounts that do not exist too, and deliberately: the handler
// must answer identically either way, or requesting a challenge becomes a
// membership oracle for a five-person circle. For an unknown account the value
// is generated and stored exactly the same; nothing can ever redeem it, because
// there is no key to verify against.
func (s *Store) Issue(ctx context.Context, aci uuid.UUID) (string, error) {
	raw := make([]byte, Bytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("reauth: challenge: %w", err)
	}
	challenge := base64.RawURLEncoding.EncodeToString(raw)

	if err := s.rdb.Set(ctx, key(aci, challenge), 1, TTL).Err(); err != nil {
		return "", fmt.Errorf("reauth: store challenge: %w", err)
	}
	return challenge, nil
}

// Consume redeems a challenge exactly once.
//
// Fails closed: if Redis is unreachable the error propagates and the handler
// refuses, rather than accepting a signature over a value it cannot prove it
// issued. An attacker who can degrade Redis must not thereby remove the replay
// protection — the same rule ratelimit.Allow follows.
func (s *Store) Consume(ctx context.Context, aci uuid.UUID, challenge string) error {
	if challenge == "" {
		return ErrNotRedeemable
	}
	// Reject anything that is not the shape we issue, before it reaches Redis:
	// a caller must not be able to choose arbitrary key material.
	raw, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil || len(raw) != Bytes {
		return ErrNotRedeemable
	}

	res, err := s.rdb.Eval(ctx, consumeScript, []string{key(aci, challenge)}).Result()
	if err != nil {
		return fmt.Errorf("reauth: consume: %w", err)
	}
	deleted, ok := res.(int64)
	if !ok || deleted != 1 {
		return ErrNotRedeemable
	}
	return nil
}
