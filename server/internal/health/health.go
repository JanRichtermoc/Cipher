// Package health serves liveness and readiness.
//
// Split deliberately, because they answer different questions and conflating
// them makes both worse:
//
//   - **Liveness** ("is this process wedged?") touches nothing. An unauthenticated
//     endpoint that queries the database is a free amplifier: one cheap request
//     becomes one database round trip, and an orchestrator polling it during an
//     outage adds load to the thing that is already failing.
//   - **Readiness** ("should traffic be sent here?") checks dependencies, and is
//     therefore rate-limited by a short result cache.
//
// docs/BACKEND.md §1: health never reports version, build, or user counts. Those
// are free reconnaissance — a version string tells an attacker which
// vulnerabilities to try — and none of them help an orchestrator decide anything.
//
// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
package health

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"cipher.relay/internal/httpx"
)

// Checker is one dependency that readiness consults.
type Checker interface {
	Ping(ctx context.Context) error
}

// namedChecker pairs a checker with a name used only in logs.
type namedChecker struct {
	name    string
	checker Checker
}

// Handler serves /health and /health/ready.
type Handler struct {
	log      *slog.Logger
	checkers []namedChecker

	// cacheFor bounds how often dependencies are actually probed.
	cacheFor time.Duration

	mu          sync.Mutex
	lastChecked time.Time
	lastErr     error
}

// New builds a handler over the named dependencies.
func New(log *slog.Logger, cacheFor time.Duration) *Handler {
	return &Handler{log: log, cacheFor: cacheFor}
}

// Add registers a dependency for readiness.
func (h *Handler) Add(name string, c Checker) { h.checkers = append(h.checkers, namedChecker{name, c}) }

// Routes registers this handler's endpoints on mux.
func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", h.live)
	mux.HandleFunc("GET /health/ready", h.ready)
}

type statusBody struct {
	Status string `json:"status"`
}

// live answers only "this process is scheduling goroutines and serving HTTP".
func (h *Handler) live(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, statusBody{Status: "ok"})
}

// ready probes dependencies, at most once per cacheFor.
//
// The response body says "ready" or "unavailable" and nothing else. Naming the
// failing dependency would tell an unauthenticated caller which component of the
// relay is down, which is reconnaissance during exactly the window when the
// service is least able to absorb attention. The detail goes to the log.
func (h *Handler) ready(w http.ResponseWriter, r *http.Request) {
	if err := h.check(r.Context()); err != nil {
		httpx.WriteJSON(w, http.StatusServiceUnavailable, statusBody{Status: "unavailable"})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, statusBody{Status: "ready"})
}

// check runs every probe, returning the first failure, and caches the verdict.
func (h *Handler) check(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if time.Since(h.lastChecked) < h.cacheFor {
		return h.lastErr
	}

	// A probe must not inherit an arbitrarily long request deadline: readiness
	// that hangs is reported by the orchestrator as a timeout rather than as the
	// "not ready" it actually is.
	probeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()

	var firstErr error
	for _, c := range h.checkers {
		if err := c.checker.Ping(probeCtx); err != nil {
			h.log.WarnContext(ctx, "readiness probe failed",
				slog.String("dependency", c.name),
				slog.String("reason", err.Error()))
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	h.lastChecked = time.Now()
	h.lastErr = firstErr
	return firstErr
}
