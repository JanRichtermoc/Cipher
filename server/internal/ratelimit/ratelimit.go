// Package ratelimit is the relay's token bucket, backed by Redis.
//
// docs/BACKEND.md §5 lists the limits. One of them — prekey fetch — is a
// security control rather than a capacity control, because every fetch consumes
// one of the target's one-time prekeys and an unthrottled endpoint lets anyone
// drain any peer's pool on demand (AUDIT 3.1). The rest are ordinary abuse
// control. This package does not distinguish between them; the callers do.
//
// # Why a token bucket and not a fixed window
//
// A fixed window is four lines of Lua and is wrong at the boundary: an attacker
// who spends the whole allowance at the end of one window and again at the start
// of the next gets double the rate, in a burst, exactly when a brute-force loop
// would want it. A token bucket refills continuously, so the sustained rate is
// the configured rate no matter how the attempts are aligned.
//
// # Why Lua
//
// Read-modify-write across two round trips is a race: two concurrent requests
// both read the same token count and both decide they are allowed. A Lua script
// runs atomically inside Redis, so the decision and the deduction cannot be
// interleaved. This is the whole reason the limiter is not three Go statements.
//
// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
package ratelimit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Limit is one configured bucket.
type Limit struct {
	// Capacity is the burst size: how many requests are allowed back to back
	// from a full bucket.
	Capacity int
	// Window is how long a full bucket takes to refill from empty. Capacity 10
	// with a one-hour window is "10 per hour, burstable".
	Window time.Duration
}

// Validate reports whether the limit is usable.
//
// Called at construction rather than at request time. A zero Capacity would
// refuse every request forever, and a zero Window would divide by zero inside
// the script — both are configuration mistakes that should stop the process at
// startup, not produce a confusing outage later.
func (l Limit) Validate() error {
	if l.Capacity <= 0 {
		return errors.New("ratelimit: Capacity must be positive")
	}
	if l.Window <= 0 {
		return errors.New("ratelimit: Window must be positive")
	}
	return nil
}

// Decision is the outcome of one Allow call.
type Decision struct {
	OK        bool
	Remaining int
	// RetryAfter is how long until one token is available. Zero when OK.
	RetryAfter time.Duration
}

// tokenBucket is evaluated atomically inside Redis.
//
// The clock is Redis's own (`TIME`), not the caller's. With more than one relay
// process, caller clocks disagree by however much NTP is drifting, and a bucket
// updated by a process whose clock runs fast grants tokens that have not been
// earned. One clock, in one place, is the only version of this that is correct.
//
// Redis 7+ permits non-deterministic commands in scripts because replication is
// effect-based rather than command-based, so `TIME` is safe here.
const tokenBucket = `
local capacity   = tonumber(ARGV[1])
local window_ms  = tonumber(ARGV[2])
local cost       = tonumber(ARGV[3])

local time  = redis.call('TIME')
local now   = (tonumber(time[1]) * 1000) + math.floor(tonumber(time[2]) / 1000)

local state  = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(state[1])
local ts     = tonumber(state[2])

if tokens == nil or ts == nil then
  tokens = capacity
  ts     = now
end

-- Refill is proportional to elapsed time. Guarded against a negative delta: a
-- Redis failover to a replica whose clock is behind would otherwise remove
-- tokens rather than add them.
local elapsed = now - ts
if elapsed > 0 then
  tokens = math.min(capacity, tokens + (elapsed * capacity / window_ms))
  ts     = now
end

local allowed = 0
if tokens >= cost then
  tokens  = tokens - cost
  allowed = 1
end

redis.call('HSET', KEYS[1], 'tokens', tokens, 'ts', ts)

-- The key expires one full window after the last touch. By then a bucket has
-- refilled completely, so its state is indistinguishable from absent and
-- keeping it would only retain the fact that this subject made a request.
redis.call('PEXPIRE', KEYS[1], window_ms)

local retry_ms = 0
if allowed == 0 then
  retry_ms = math.ceil(((cost - tokens) * window_ms) / capacity)
end

return {allowed, math.floor(tokens), retry_ms}
`

// Limiter evaluates limits against Redis.
type Limiter struct {
	rdb    redis.Scripter
	script *redis.Script

	// pepper keys the subject hash. See Subject.
	pepper []byte
}

// New builds a limiter.
//
// pepper should be a process-lifetime random value or a configured secret. It is
// not a security boundary on its own — see Subject — but it stops a Redis dump
// from being trivially reversed into the set of IP addresses that made requests.
func New(rdb redis.Scripter, pepper []byte) *Limiter {
	return &Limiter{rdb: rdb, script: redis.NewScript(tokenBucket), pepper: pepper}
}

// Subject derives the bucket key for a rate-limit subject.
//
// The raw value — an IP address, a token hash, an account id — is never used as
// a Redis key. docs/BACKEND.md §7 keeps IP addresses out of logs, and a Redis
// key is a log with a TTL: `KEYS *` on a dump would otherwise enumerate every
// address that had recently spoken to the relay.
//
// HMAC rather than a plain hash because the input space is small enough to
// enumerate. Every IPv4 address is 2^32 candidates, which is minutes of work on
// a laptop, so an unkeyed SHA-256 of an IP address is a reversible encoding
// wearing the costume of a hash.
func (l *Limiter) Subject(kind, value string) string {
	mac := hmac.New(sha256.New, l.pepper)
	mac.Write([]byte(kind))
	mac.Write([]byte{0})
	mac.Write([]byte(value))
	sum := mac.Sum(nil)
	// Truncated: 128 bits is far beyond collision risk at this scale and keeps
	// keys short.
	return "rl:" + kind + ":" + base64.RawURLEncoding.EncodeToString(sum[:16])
}

// Allow consumes one token for subject under limit.
//
// # Failure policy
//
// An error from Redis is returned to the caller with `OK` false — the limiter
// fails **closed**. That is deliberate and it is the uncomfortable choice: it
// means a Redis outage stops accepting requests on rate-limited routes rather
// than serving them unthrottled.
//
// Failing open would mean an attacker who can degrade Redis — which is a much
// lower bar than compromising it — also removes the brute-force limit on invite
// redemption and the drain limit on prekey fetch in the same move. A limiter
// that switches itself off under load is not a limit; it is a limit with a
// documented bypass.
func (l *Limiter) Allow(ctx context.Context, subject string, limit Limit) (Decision, error) {
	if err := limit.Validate(); err != nil {
		return Decision{}, err
	}

	raw, err := l.script.Run(ctx, l.rdb,
		[]string{subject},
		limit.Capacity,
		limit.Window.Milliseconds(),
		1, // cost
	).Slice()
	if err != nil {
		return Decision{}, fmt.Errorf("ratelimit: %w", err)
	}
	if len(raw) != 3 {
		return Decision{}, fmt.Errorf("ratelimit: script returned %d values, want 3", len(raw))
	}

	allowed, ok1 := raw[0].(int64)
	remaining, ok2 := raw[1].(int64)
	retryMS, ok3 := raw[2].(int64)
	if !ok1 || !ok2 || !ok3 {
		return Decision{}, errors.New("ratelimit: script returned unexpected types")
	}

	d := Decision{OK: allowed == 1, Remaining: int(remaining)}
	if !d.OK {
		d.RetryAfter = time.Duration(retryMS) * time.Millisecond
	}
	return d, nil
}
