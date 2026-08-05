// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only

package httpx

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
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

// ---------------------------------------------------------------------------
// RealIP
//
// Every test here is a negative one except the first: the value of this
// middleware is entirely in what it refuses. A version that simply believed the
// header would pass a "the client IP arrives" test and be a rate-limit bypass.
// ---------------------------------------------------------------------------

func mustPrefixes(t *testing.T, s ...string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, v := range s {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			t.Fatalf("bad test prefix %q: %v", v, err)
		}
		out = append(out, p)
	}
	return out
}

// seenAddr runs one request through RealIP and reports what a handler downstream
// would rate-limit against.
func seenAddr(trusted []netip.Prefix, remoteAddr, header string) string {
	var got string
	h := RealIP(trusted)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = ClientAddr(r)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr
	if header != "" {
		req.Header.Set(realIPHeader, header)
	}
	h.ServeHTTP(httptest.NewRecorder(), req)
	return got
}

func TestRealIPBelievesATrustedProxy(t *testing.T) {
	// The positive control. Without this the negative tests below could all pass
	// against a middleware that unconditionally does nothing.
	trusted := mustPrefixes(t, "172.18.0.0/16")
	if got := seenAddr(trusted, "172.18.0.1:41234", "203.0.113.9"); got != "203.0.113.9" {
		t.Fatalf("trusted proxy header ignored: got %q, want 203.0.113.9", got)
	}
}

func TestRealIPIgnoresTheHeaderWhenNoProxyIsTrusted(t *testing.T) {
	// The default configuration, and the P4 behaviour that must survive: an
	// operator who never sets RELAY_TRUSTED_PROXY gets a relay that cannot be
	// told who the client is, even by something on loopback.
	if got := seenAddr(nil, "127.0.0.1:9999", "203.0.113.9"); got != "127.0.0.1" {
		t.Fatalf("header honoured with no trusted proxies: got %q, want 127.0.0.1", got)
	}
}

func TestRealIPIgnoresTheHeaderFromAnUntrustedPeer(t *testing.T) {
	// The bypass this middleware exists to not be. An attacker who reaches the
	// relay directly sets X-Real-IP to a fresh value per request; if it were
	// believed, every request would land in its own bucket and the 5/hour limit
	// on invite redemption would not exist.
	trusted := mustPrefixes(t, "172.18.0.0/16")
	for _, spoof := range []string{"203.0.113.9", "10.0.0.1", "::1"} {
		got := seenAddr(trusted, "198.51.100.7:5555", spoof)
		if got != "198.51.100.7" {
			t.Fatalf("spoofed %q from untrusted peer was believed: got %q", spoof, got)
		}
	}
}

func TestRealIPRejectsAListEvenFromATrustedProxy(t *testing.T) {
	// Our Nginx sets exactly one value. A comma means something upstream is
	// appending, so the proxy depth is not what the configuration assumes and no
	// element of the list can be shown to be the client.
	trusted := mustPrefixes(t, "172.18.0.0/16")
	if got := seenAddr(trusted, "172.18.0.1:1", "203.0.113.9, 198.51.100.7"); got != "172.18.0.1" {
		t.Fatalf("comma-separated header accepted: got %q, want the proxy address", got)
	}
}

func TestRealIPFallsBackToTheProxyOnJunk(t *testing.T) {
	// Fails closed: the fallback over-throttles (everything shares the proxy's
	// bucket) rather than producing an empty or attacker-chosen bucket key.
	trusted := mustPrefixes(t, "172.18.0.0/16")
	for _, junk := range []string{"not-an-ip", "", "   ", "203.0.113.9:443", "999.1.1.1", "<script>"} {
		if got := seenAddr(trusted, "172.18.0.1:1", junk); got != "172.18.0.1" {
			t.Fatalf("junk header %q produced %q, want the proxy address", junk, got)
		}
	}
}

func TestRealIPNormalisesSoOneHostCannotBecomeTwoBuckets(t *testing.T) {
	// A rate-limit bucket is keyed on this string. If ::ffff:203.0.113.9 and
	// 203.0.113.9 produced different keys, a caller would get two budgets for
	// one address — and a zone suffix would give unbounded many.
	trusted := mustPrefixes(t, "172.18.0.0/16")
	for _, spelling := range []string{"203.0.113.9", "::ffff:203.0.113.9"} {
		if got := seenAddr(trusted, "172.18.0.1:1", spelling); got != "203.0.113.9" {
			t.Fatalf("%q normalised to %q, want 203.0.113.9", spelling, got)
		}
	}
	if got := seenAddr(trusted, "172.18.0.1:1", "fe80::1%eth0"); got != "fe80::1" {
		t.Fatalf("zone not stripped: got %q, want fe80::1", got)
	}
}

func TestRealIPTrustsIPv6ProxiesToo(t *testing.T) {
	trusted := mustPrefixes(t, "::1/128")
	if got := seenAddr(trusted, "[::1]:8080", "203.0.113.9"); got != "203.0.113.9" {
		t.Fatalf("IPv6 trusted proxy not honoured: got %q", got)
	}
	// And an IPv6 peer outside the trusted prefix is still not believed.
	if got := seenAddr(trusted, "[2001:db8::1]:8080", "203.0.113.9"); got != "2001:db8::1" {
		t.Fatalf("untrusted IPv6 peer was believed: got %q", got)
	}
}

func TestRealIPDoesNotMutateTheCallersRequest(t *testing.T) {
	// The middleware hands a copy downstream. Mutating the original would leak
	// the rewrite back out to anything holding the same *Request.
	trusted := mustPrefixes(t, "172.18.0.0/16")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "172.18.0.1:41234"
	req.Header.Set(realIPHeader, "203.0.113.9")

	h := RealIP(trusted)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	h.ServeHTTP(httptest.NewRecorder(), req)

	if req.RemoteAddr != "172.18.0.1:41234" {
		t.Fatalf("caller's request was mutated: RemoteAddr is now %q", req.RemoteAddr)
	}
}

func TestClientAddrNormalisesWithoutAProxy(t *testing.T) {
	// Direct connections get the same one-host-one-bucket guarantee.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "[::ffff:203.0.113.9]:1234"
	if got := ClientAddr(req); got != "203.0.113.9" {
		t.Fatalf("got %q, want 203.0.113.9", got)
	}
}

// --- DecodeJSON ------------------------------------------------------------
//
// AUDIT 5.27. json.Decoder is a stream decoder: Decode reads one value and
// leaves the rest, so a body carrying two values decoded as the first and
// discarded the second in silence.

func TestDecodeJSONAcceptsOneValue(t *testing.T) {
	// The positive control for every refusal below: an ordinary body must still
	// decode, or the check is refusing everything.
	var got struct {
		Code string `json:"code"`
	}
	if err := DecodeJSON(strings.NewReader(`{"code":"A"}`), &got); err != nil {
		t.Fatalf("a well-formed body was refused: %v", err)
	}
	if got.Code != "A" {
		t.Fatalf("decoded %q, want %q", got.Code, "A")
	}
}

func TestDecodeJSONAcceptsTrailingWhitespace(t *testing.T) {
	// Whitespace is not a second value. Refusing it would fail bodies that any
	// pretty-printer produces, which is a gate that cries wolf (AUDIT R2).
	var got struct {
		Code string `json:"code"`
	}
	if err := DecodeJSON(strings.NewReader("{\"code\":\"A\"}\n\t "), &got); err != nil {
		t.Fatalf("trailing whitespace was refused: %v", err)
	}
}

func TestDecodeJSONRefusesASecondValue(t *testing.T) {
	// The defect: this decoded as {"code":"A"} and said nothing about the rest,
	// so the request meant one thing to this decoder and another to any reader
	// of the raw body.
	var got struct {
		Code string `json:"code"`
	}
	err := DecodeJSON(strings.NewReader(`{"code":"A"}{"code":"B"}`), &got)
	if !errors.Is(err, ErrTrailingJSON) {
		t.Fatalf("second value: err = %v, want ErrTrailingJSON", err)
	}
}

func TestDecodeJSONRefusesTrailingGarbage(t *testing.T) {
	var got struct {
		Code string `json:"code"`
	}
	for _, body := range []string{
		`{"code":"A"} 7`,
		`{"code":"A"}]`,
		`{"code":"A"}null`,
	} {
		if err := DecodeJSON(strings.NewReader(body), &got); !errors.Is(err, ErrTrailingJSON) {
			t.Fatalf("body %q: err = %v, want ErrTrailingJSON", body, err)
		}
	}
}

func TestDecodeJSONRefusesAnUnknownField(t *testing.T) {
	// Carried over from the per-route decoders this replaced: a client sending
	// "registrationId" instead of "registration_id" would otherwise register
	// with id 0 and fail much later.
	var got struct {
		Code string `json:"code"`
	}
	if err := DecodeJSON(strings.NewReader(`{"code":"A","extra":1}`), &got); err == nil {
		t.Fatal("an unknown field was accepted")
	}
}
