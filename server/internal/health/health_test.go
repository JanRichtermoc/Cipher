// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only

package health

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"cipher.relay/internal/logging"
)

type stubChecker struct {
	err   atomic.Pointer[error]
	calls atomic.Int64
}

func (s *stubChecker) Ping(context.Context) error {
	s.calls.Add(1)
	if e := s.err.Load(); e != nil {
		return *e
	}
	return nil
}

func (s *stubChecker) fail(err error) { s.err.Store(&err) }
func (s *stubChecker) recover()       { s.err.Store(nil) }

func newHandler(t *testing.T, cacheFor time.Duration) (*Handler, *stubChecker, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	h := New(logging.New(&buf, slog.LevelDebug), cacheFor)
	stub := &stubChecker{}
	h.Add("postgres", stub)
	return h, stub, &buf
}

func serve(h *Handler, path string) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	h.Routes(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestLivenessTouchesNoDependency(t *testing.T) {
	// An unauthenticated endpoint that queries the database is a free amplifier:
	// one cheap request becomes one database round trip, and an orchestrator
	// polling during an outage adds load to the thing already failing.
	h, stub, _ := newHandler(t, time.Second)

	rec := serve(h, "/health")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := stub.calls.Load(); got != 0 {
		t.Fatalf("liveness probed dependencies %d times, want 0", got)
	}
}

func TestLivenessStaysUpWhenDependenciesAreDown(t *testing.T) {
	// Otherwise a database outage makes the orchestrator kill and restart every
	// replica, which turns a recoverable dependency failure into a crash loop.
	h, stub, _ := newHandler(t, 0)
	stub.fail(errors.New("connection refused"))

	if rec := serve(h, "/health"); rec.Code != http.StatusOK {
		t.Fatalf("liveness = %d during a dependency outage, want 200", rec.Code)
	}
}

func TestReadinessReportsUnavailableWhenADependencyFails(t *testing.T) {
	h, stub, _ := newHandler(t, 0)
	stub.fail(errors.New("connection refused"))

	rec := serve(h, "/health/ready")

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestReadinessDoesNotNameTheFailingDependency(t *testing.T) {
	// Naming it tells an unauthenticated caller which component is down, during
	// exactly the window when the service is least able to absorb attention.
	h, stub, buf := newHandler(t, 0)
	stub.fail(errors.New("connection refused: dial tcp 10.0.0.5:5432"))

	rec := serve(h, "/health/ready")

	body := rec.Body.String()
	for _, leak := range []string{"postgres", "connection refused", "10.0.0.5", "5432"} {
		if strings.Contains(strings.ToLower(body), strings.ToLower(leak)) {
			t.Errorf("readiness body leaked %q: %s", leak, body)
		}
	}
	// The detail is still useful, so it must be in the log — a check that hides
	// the failure from everyone is not an improvement.
	if !strings.Contains(buf.String(), "postgres") {
		t.Errorf("the failing dependency was not logged: %s", buf.String())
	}
}

func TestHealthReportsNoVersionOrCounts(t *testing.T) {
	// docs/BACKEND.md §1: health never reports version, build, or user counts.
	// They are free reconnaissance and help no orchestrator decide anything.
	h, _, _ := newHandler(t, 0)

	for _, path := range []string{"/health", "/health/ready"} {
		body := serve(h, path).Body.String()
		for _, forbidden := range []string{"version", "build", "commit", "uptime", "count"} {
			if strings.Contains(strings.ToLower(body), forbidden) {
				t.Errorf("%s leaked %q: %s", path, forbidden, body)
			}
		}
	}
}

func TestReadinessCachesItsVerdict(t *testing.T) {
	// Readiness is unauthenticated and touches both dependencies, so without a
	// cache it is a request amplifier pointed at the database.
	h, stub, _ := newHandler(t, time.Minute)

	for range 5 {
		serve(h, "/health/ready")
	}

	if got := stub.calls.Load(); got != 1 {
		t.Fatalf("probed %d times behind a 1m cache, want 1", got)
	}
}

func TestReadinessRecoversAfterTheCacheExpires(t *testing.T) {
	// A cache that never re-probes reports a failed dependency forever, which is
	// worse than no cache: the service never returns to rotation.
	h, stub, _ := newHandler(t, 0)
	stub.fail(errors.New("down"))

	if rec := serve(h, "/health/ready"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}

	stub.recover()

	if rec := serve(h, "/health/ready"); rec.Code != http.StatusOK {
		t.Fatalf("status = %d after recovery, want 200", rec.Code)
	}
}

func TestReadinessProbesEveryDependencyEvenAfterAFailure(t *testing.T) {
	// Returning on the first failure would leave the second dependency's state
	// unknown and unlogged, so an incident shows one cause when there are two.
	var buf bytes.Buffer
	h := New(logging.New(&buf, slog.LevelDebug), 0)
	first, second := &stubChecker{}, &stubChecker{}
	first.fail(errors.New("down"))
	second.fail(errors.New("also down"))
	h.Add("postgres", first)
	h.Add("redis", second)

	serve(h, "/health/ready")

	if second.calls.Load() == 0 {
		t.Fatal("the second dependency was never probed after the first failed")
	}
	if !strings.Contains(buf.String(), "redis") {
		t.Fatalf("the second failure was not logged: %s", buf.String())
	}
}

func TestReadinessProbeSurvivesAClientDisconnect(t *testing.T) {
	// The probe uses context.WithoutCancel: a client that hangs up mid-probe
	// must not cancel it, or the cached verdict becomes "failed" for everyone
	// because one caller pressed ctrl-C.
	h, stub, _ := newHandler(t, 0)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already gone before the probe starts

	if err := h.check(ctx); err != nil {
		t.Fatalf("check failed on a cancelled request context: %v", err)
	}
	if stub.calls.Load() != 1 {
		t.Fatalf("probed %d times, want 1", stub.calls.Load())
	}
}
