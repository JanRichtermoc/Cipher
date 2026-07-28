// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only

package httpx

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cipher.relay/internal/logging"
)

func testLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return logging.New(&buf, slog.LevelDebug), &buf
}

func TestWriteErrorDoesNotLeakDetail(t *testing.T) {
	// The whole point of WriteError taking only a status is that there is no
	// parameter through which a database error, a constraint name, or a row's
	// contents could reach the client. This asserts the body is derived from the
	// status and nothing else.
	rec := httptest.NewRecorder()
	WriteError(rec, http.StatusUnauthorized)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Unauthorized") {
		t.Fatalf("body = %q, want the status text", body)
	}
}

func TestLogRecordsThePatternNotThePopulatedPath(t *testing.T) {
	// This is the leak the access log exists to avoid: a populated path is a
	// metadata record hiding in a log line, and it survives every deletion the
	// retention policy performs on the database.
	log, buf := testLogger()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/keys/{aci}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := Chain(mux, Log(log))

	const aci = "3f2b8c14-0000-4000-8000-000000000001"
	req := httptest.NewRequest(http.MethodGet, "/v1/keys/"+aci, nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	out := buf.String()
	if strings.Contains(out, aci) {
		t.Fatalf("the populated path reached the log: %s", out)
	}
	if !strings.Contains(out, "/v1/keys/{aci}") {
		t.Fatalf("the route pattern is missing, so the line is useless: %s", out)
	}
}

func TestLogDoesNotEchoAnUnmatchedPath(t *testing.T) {
	// A 404 has no pattern. Falling back to the requested path would let an
	// attacker log arbitrary content by requesting it.
	log, buf := testLogger()
	handler := Chain(http.NewServeMux(), Log(log))

	req := httptest.NewRequest(http.MethodGet, "/attacker-controlled-value", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if strings.Contains(buf.String(), "attacker-controlled-value") {
		t.Fatalf("an unmatched path was echoed into the log: %s", buf.String())
	}
}

func TestRecoverReturns500AndKeepsTheStackOutOfTheResponse(t *testing.T) {
	log, buf := testLogger()

	const secret = "panic-carried-this-secret"
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic(secret)
	}), Recover(log))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatalf("the panic value reached the client: %s", rec.Body.String())
	}
	// A Go panic value routinely contains the data that caused it, which here
	// can mean an envelope, a token, or a key. It must not reach the log either.
	if strings.Contains(buf.String(), secret) {
		t.Fatalf("the panic value reached the log: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "panic recovered") {
		t.Fatalf("the panic was not logged at all: %s", buf.String())
	}
}

func TestRecoverStillProducesAnAccessLine(t *testing.T) {
	// Chain order is load-bearing and this test is why the comment on Chain says
	// the intuitive order is wrong. Recover outermost — which is what anyone
	// writes first — drops every panicking request from the access log, because
	// the panic unwinds past Log before Log can report anything.
	//
	// This pins the arrangement main.go actually uses: Log outside Recover.
	log, buf := testLogger()
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}), Log(log), Recover(log))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	out := buf.String()
	if !strings.Contains(out, `"msg":"request"`) {
		t.Fatalf("a panicking request produced no access line: %s", out)
	}
	// The status matters as much as the line's existence: a catastrophic failure
	// logged as a 200 is worse than no line, because it is believed.
	if !strings.Contains(out, `"status":500`) {
		t.Fatalf("the access line does not report 500: %s", out)
	}
	if strings.Contains(out, `"status":200`) {
		t.Fatalf("a panicking request was logged as a success: %s", out)
	}
}

func TestLogEmitsEvenIfAnInnerHandlerPanicsUnrecovered(t *testing.T) {
	// Belt to the braces above: even with no Recover at all, the deferred emit
	// means the request is not invisible. Ordering is then still wrong for the
	// status, but the request is on the record.
	log, buf := testLogger()
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}), Log(log))

	func() {
		defer func() { _ = recover() }()
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}()

	if !strings.Contains(buf.String(), `"msg":"request"`) {
		t.Fatalf("Log did not emit from its defer: %s", buf.String())
	}
}

func TestLimitBodyRejectsOversizeInput(t *testing.T) {
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			WriteError(w, http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	}), LimitBody(16))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", 64)))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}

func TestLimitBodyIsEnforcedOnTheReadNotContentLength(t *testing.T) {
	// A chunked request declares no length, so a Content-Length check reads as
	// protection while providing none. MaxBytesReader fails the read itself,
	// which is the only thing a client cannot lie about.
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			WriteError(w, http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	}), LimitBody(16))

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", 64)))
	req.ContentLength = -1 // as a chunked request arrives
	req.Header.Set("Transfer-Encoding", "chunked")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413 — a chunked body bypassed the limit", rec.Code)
	}
}

func TestLimitBodyAllowsInputAtTheLimit(t *testing.T) {
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			WriteError(w, http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	}), LimitBody(16))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", 16)))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — an exactly-at-limit body was rejected", rec.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), SecurityHeaders)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		// Responses carry undelivered ciphertext and prekeys; a cache anywhere
		// on the path is storage outside our control.
		"Cache-Control": "no-store",
	}
	for header, value := range want {
		if got := rec.Header().Get(header); got != value {
			t.Errorf("%s = %q, want %q", header, got, value)
		}
	}
	if rec.Header().Get("Content-Security-Policy") == "" {
		t.Error("Content-Security-Policy is missing")
	}
	// The only client is a native app, which is not subject to the same-origin
	// policy. Any CORS grant would open browser access for nothing in return.
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, want none", got)
	}
}

func TestChainAppliesOutermostFirst(t *testing.T) {
	var order []string
	mark := func(name string) Middleware {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, name)
				next.ServeHTTP(w, r)
			})
		}
	}

	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "handler")
	}), mark("first"), mark("second"))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	got := strings.Join(order, ",")
	if got != "first,second,handler" {
		t.Fatalf("order = %q, want first,second,handler", got)
	}
}
