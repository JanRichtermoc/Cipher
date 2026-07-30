//go:build integration

// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
//
// The token bucket, against a real Redis. It cannot be unit-tested: the decision
// and the deduction happen inside a Lua script, evaluated against Redis's own
// clock, and a fake that returned plausible numbers would be testing the fake.
//
// `Charge` exists because `Allow` has the wrong failure shape for a cost that has
// already been incurred — see AUDIT 5.22. These tests pin that difference, since
// it is the whole reason for the second method.

package integration

import (
	"context"
	"testing"
	"time"

	"cipher.relay/internal/ratelimit"
)

func TestChargeDeductsTheWholeCostWhenItFits(t *testing.T) {
	ctx := context.Background()
	limiter := testLimiter(t)
	limit := ratelimit.Limit{Capacity: 500, Window: 24 * time.Hour}
	subject := limiter.Subject("test-charge", "fits")

	d, err := limiter.Charge(ctx, subject, limit, 300)
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	if !d.OK {
		t.Fatal("a cost inside the capacity must be allowed")
	}
	if d.Remaining != 200 {
		t.Fatalf("remaining %d, want 200 — the cost was not deducted in full", d.Remaining)
	}
}

func TestChargeSaturatesOnOverrunSoTheNextCheckRefuses(t *testing.T) {
	// The property AUDIT 5.22 was about. `Allow` deducts nothing when it refuses,
	// which is right for work that is then not done. For a quota charged *after*
	// the work — the blob byte quota, where the size is unknown until the upload
	// finishes — a non-deducting refusal means the bucket ends every overrun
	// exactly as full as it started, so the quota never binds.
	ctx := context.Background()
	limiter := testLimiter(t)
	limit := ratelimit.Limit{Capacity: 500, Window: 24 * time.Hour}
	subject := limiter.Subject("test-charge", "saturates")

	if _, err := limiter.Charge(ctx, subject, limit, 400); err != nil {
		t.Fatalf("charge: %v", err)
	}

	over, err := limiter.Charge(ctx, subject, limit, 200)
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	if over.OK {
		t.Fatal("200 must not fit in the 100 that were left")
	}
	if over.Remaining != 0 {
		t.Fatalf("remaining %d, want 0 — the overrun did not drain the bucket, so the "+
			"next charge would be allowed and the quota would never bind", over.Remaining)
	}
	if over.RetryAfter <= 0 {
		t.Fatal("a refusal must report when the cost would next fit")
	}

	// And the consequence, stated as its own assertion: the *next* request is
	// refused, which is what makes this a quota rather than a counter.
	after, err := limiter.Charge(ctx, subject, limit, 1)
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	if after.OK {
		t.Fatal("the bucket was drained by the overrun, so one more token must be refused")
	}
}

func TestAllowDoesNotDeductWhenItRefuses(t *testing.T) {
	// The other half of the contract, so the two methods cannot quietly converge:
	// a refused *request* costs the caller nothing, because it was not served.
	ctx := context.Background()
	limiter := testLimiter(t)
	limit := ratelimit.Limit{Capacity: 2, Window: time.Hour}
	subject := limiter.Subject("test-allow", "no-deduct")

	for i := range 2 {
		if d, err := limiter.Allow(ctx, subject, limit); err != nil || !d.OK {
			t.Fatalf("attempt %d: allowed=%v err=%v", i, d.OK, err)
		}
	}

	first, err := limiter.Allow(ctx, subject, limit)
	if err != nil {
		t.Fatalf("allow: %v", err)
	}
	second, err := limiter.Allow(ctx, subject, limit)
	if err != nil {
		t.Fatalf("allow: %v", err)
	}
	if first.OK || second.OK {
		t.Fatal("the bucket is empty; both must be refused")
	}
	if second.Remaining != first.Remaining {
		t.Fatalf("a refusal deducted tokens: %d then %d", first.Remaining, second.Remaining)
	}
}

func TestChargeZeroIsAPeek(t *testing.T) {
	ctx := context.Background()
	limiter := testLimiter(t)
	limit := ratelimit.Limit{Capacity: 10, Window: time.Hour}
	subject := limiter.Subject("test-charge", "peek")

	if _, err := limiter.Charge(ctx, subject, limit, 4); err != nil {
		t.Fatalf("charge: %v", err)
	}
	peek, err := limiter.Charge(ctx, subject, limit, 0)
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if !peek.OK || peek.Remaining != 6 {
		t.Fatalf("peek reported ok=%v remaining=%d, want true/6", peek.OK, peek.Remaining)
	}
	// And it really did not consume: a second peek reports the same balance.
	again, err := limiter.Charge(ctx, subject, limit, 0)
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if again.Remaining != peek.Remaining {
		t.Fatalf("a peek consumed a token: %d then %d", peek.Remaining, again.Remaining)
	}
}

func TestChargeRejectsANegativeCost(t *testing.T) {
	// A negative cost would *add* tokens — a caller-supplied refund. Refused in Go
	// rather than clamped in Lua, so the mistake is a compile-time-shaped error at
	// the call site instead of a silently generous bucket.
	ctx := context.Background()
	limiter := testLimiter(t)
	limit := ratelimit.Limit{Capacity: 10, Window: time.Hour}

	if _, err := limiter.Charge(
		ctx, limiter.Subject("test-charge", "negative"), limit, -5,
	); err == nil {
		t.Fatal("a negative cost must be refused")
	}
}
