// Package sweep enforces the retention policy on a timer.
//
// docs/BACKEND.md §4 and docs/THREAT_MODEL.md §3.1. Delete-on-delivery empties
// the message table for anyone who comes back to collect; this empties it for
// everyone else — a device that is lost, wiped, or simply never opened again
// would otherwise leave its mail on the relay indefinitely, which is precisely
// the archive the policy says does not exist.
//
// It matters that this is a *sweep* and not merely an expiry predicate. Every
// read path here already filters on `expires_at > now()`, so nothing lapsed is
// ever served; that makes stale rows invisible, not absent. Under
// THREAT_MODEL.md §1.1 the adversary reads the disk, not the API, and an
// invisible row is a retained row.
//
// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
package sweep

import (
	"context"
	"log/slog"
	"time"
)

// Store is the subset of the database this needs.
//
// Narrow on purpose: a sweeper holding the full *store.DB could grow a query, and
// the one thing this goroutine must never do is read the data it is deleting.
type Store interface {
	DeleteExpiredMessages(ctx context.Context) (int64, error)
	DeleteExpiredInvites(ctx context.Context) (int64, error)
	DeleteExpiredSessions(ctx context.Context) (int64, error)
}

// Sweeper deletes expired rows on an interval.
type Sweeper struct {
	store    Store
	log      *slog.Logger
	interval time.Duration
}

// New builds a sweeper.
func New(store Store, log *slog.Logger, interval time.Duration) *Sweeper {
	return &Sweeper{store: store, log: log, interval: interval}
}

// Run sweeps until ctx is cancelled.
//
// Runs once immediately rather than waiting out the first interval. A relay that
// has been down for a week comes back holding a week of lapsed rows, and the
// worst moment to keep them is the one right after an unplanned outage.
func (s *Sweeper) Run(ctx context.Context) {
	s.once(ctx)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.once(ctx)
		}
	}
}

// once performs one pass.
//
// # A failure is logged, never fatal
//
// The sweeper must not be able to take the relay down. It holds no request path
// and its work is always still there next tick, so escalating a transient
// database error into a process exit would trade a delayed deletion for an
// outage.
//
// # Each table is swept independently
//
// A failure on one must not skip the others. Messages are the most sensitive and
// go first, so a database that fails part-way through has still shed the rows
// that matter most.
func (s *Sweeper) once(ctx context.Context) {
	// A bounded deadline: a sweep that hangs would otherwise hold its slot until
	// the process ended, and the next tick would find the previous one still
	// running with nothing to say about it.
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	type task struct {
		name string
		run  func(context.Context) (int64, error)
	}
	// Ordered by sensitivity, most first.
	for _, t := range []task{
		{"messages", s.store.DeleteExpiredMessages},
		{"sessions", s.store.DeleteExpiredSessions},
		{"invites", s.store.DeleteExpiredInvites},
	} {
		n, err := t.run(ctx)
		if err != nil {
			s.log.ErrorContext(ctx, "retention sweep failed",
				slog.String("table", t.name),
				slog.String("reason", err.Error()))
			continue
		}
		if n > 0 {
			// Counts only, never identifiers. How many rows lapsed is
			// operational; whose they were is the record this is deleting.
			s.log.InfoContext(ctx, "retention sweep",
				slog.String("table", t.name),
				slog.Int64("deleted", n))
		}
	}
}
