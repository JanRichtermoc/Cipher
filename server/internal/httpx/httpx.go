// Package httpx holds the HTTP plumbing shared by every route: middleware,
// error responses, and the JSON writer.
//
// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
package httpx

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"runtime/debug"
	"strings"
	"time"
)

// WriteJSON writes v with the given status.
//
// Encoding into a buffer first would let an encoding failure be reported as an
// error status. It is not worth the allocation here: every value the relay
// encodes is a small struct of primitives that cannot fail to marshal, and a
// route that ever encodes something dynamic should not be using this helper.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ErrTrailingJSON reports a body carrying more than one JSON value.
var ErrTrailingJSON = errors.New("httpx: trailing data after the JSON body")

// DecodeJSON decodes exactly one JSON value from body into v.
//
// # Why every route must go through this
//
// `json.Decoder` is a *stream* decoder: `Decode` reads one value and stops, and
// whatever follows is neither read nor reported. So `{"code":"A"}{"code":"B"}`
// decoded as the first object and the second was discarded in silence — a
// request that means two different things depending on which end of it you
// read. That is the classic request-smuggling shape, and it matters most where
// the relay's own decisions are single-use: an invite redemption, an
// acknowledgement, a key publication. It also hid ordinary client bugs, since a
// double-encoded body looked like a working request.
//
// `DisallowUnknownFields` is set here rather than per route for the same reason
// it was set per route originally: a client sending `registrationId` instead of
// `registration_id` would otherwise register with id 0, and the failure appears
// much later as a session that cannot be established. Having one decoder means a
// route added later cannot forget either half.
func DecodeJSON(body io.Reader, v any) error {
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	// Trailing whitespace is fine; a second value, or any other non-space byte,
	// is not. Attempting the next decode and requiring io.EOF rather than asking
	// `dec.More()`: More is written for iterating the elements of an array or
	// object and reports false for a `]` or `}`, so a body ending
	// `{"code":"A"}]` passed it. That is the shape this check exists to refuse,
	// and the first version of this function did not.
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrTrailingJSON
	}
	return nil
}

// errorBody is the only error shape the relay emits.
type errorBody struct {
	Error string `json:"error"`
}

// WriteError writes a fixed, generic message for the status.
//
// The message is derived from the status code and never from the underlying
// error. An error string is written by a developer for a developer and routinely
// names a table, a constraint, a column, or a row that exists — which is a
// disclosure channel and, on an authentication path, an oracle. The detail goes
// to the log, where it is useful and not attacker-visible.
func WriteError(w http.ResponseWriter, status int) {
	WriteJSON(w, status, errorBody{Error: http.StatusText(status)})
}

// statusRecorder captures the status code for the access log.
//
// http.ResponseWriter does not expose what was written, and a handler that never
// calls WriteHeader has implicitly written 200.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

// Middleware is the standard decorator shape.
type Middleware func(http.Handler) http.Handler

// Chain applies middleware so that the first listed is the outermost.
//
// **Order is load-bearing, and the intuitive order is wrong.** Recover looks like
// it belongs outermost — catch everything — but [Log] must be outside it, and
// TestRecoverStillProducesAnAccessLine exists because the intuitive arrangement
// was written first and silently dropped every panicking request from the access
// log.
//
// With Recover outermost, a panic unwinds *past* Log on its way up, so Log's
// post-call work never runs. Log emits from a defer, so it still produces a line
// — but the 500 that Recover writes afterwards has not happened yet, and the line
// claims 200. A request that failed catastrophically, logged as a success, is
// worse than no line at all.
//
// With Log outermost, Recover handles the panic and writes 500 into the recorder
// Log installed, and Log then reports the status that was actually sent.
func Chain(h http.Handler, middleware ...Middleware) http.Handler {
	for i := len(middleware) - 1; i >= 0; i-- {
		h = middleware[i](h)
	}
	return h
}

// realIPHeader is the single header RealIP will believe.
//
// X-Real-IP and not X-Forwarded-For, because the two have different shapes and
// only one of them has a safe reading. X-Forwarded-For is an append-only list,
// so honouring it means choosing an element from a list an attacker contributed
// to — and every "take the last one" rule is correct only for a proxy depth that
// is assumed rather than checked. X-Real-IP as written by our Nginx is a single
// value that *overwrites* whatever arrived, so there is nothing to choose.
const realIPHeader = "X-Real-IP"

// RealIP rewrites r.RemoteAddr to the client address reported by a trusted proxy.
//
// # The problem it solves
//
// Behind a reverse proxy every request arrives from the proxy, so r.RemoteAddr
// is the proxy for all of them. api.clientAddr feeds that value to the rate
// limiter, and POST /v1/invite/redeem is limited to 5/hour/IP — so without this,
// the only per-IP control in the relay collapses into a single global bucket and
// any one caller denies invite redemption to everyone. See docs/BACKEND.md §9.2.
//
// # Why it is a middleware and not a helper
//
// One place decides, at the edge, and every handler downstream — including ones
// not yet written — reads the ordinary field and gets the right answer. A helper
// that must be remembered is a helper that will be forgotten by the second
// route that needs an address.
//
// # Every way it declines
//
// It rewrites nothing, leaving the proxy's own address in place, when:
//
//   - no proxies are trusted (the default, and how development and the
//     integration suite run);
//   - the peer that actually connected is not in trusted — which is what makes
//     the header unspoofable from the internet, since an attacker reaching the
//     relay directly is never a trusted peer;
//   - the header is absent, empty, or unparseable as an IP;
//   - the header contains a comma. Our proxy sets exactly one value, so a list
//     means something upstream is appending and the depth assumption is wrong.
//
// Declining always fails *closed* for the limiter: the fallback is the proxy
// address, which over-throttles. There is no input that produces no limit.
func RealIP(trusted []netip.Prefix) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if addr, ok := clientFromProxy(r, trusted); ok {
				// Shallow copy: the caller's Request must not be mutated, and
				// the port is deliberately zeroed rather than invented — the
				// client's source port is not something the proxy reports, and
				// net.SplitHostPort still has to succeed downstream.
				r2 := *r
				r2.RemoteAddr = net.JoinHostPort(addr.String(), "0")
				r = &r2
			}
			next.ServeHTTP(w, r)
		})
	}
}

// clientFromProxy returns the address to believe, and whether to believe it.
func clientFromProxy(r *http.Request, trusted []netip.Prefix) (netip.Addr, bool) {
	if len(trusted) == 0 {
		return netip.Addr{}, false
	}

	peer, ok := peerAddr(r.RemoteAddr)
	if !ok || !trustedContains(trusted, peer) {
		return netip.Addr{}, false
	}

	raw := strings.TrimSpace(r.Header.Get(realIPHeader))
	if raw == "" || strings.Contains(raw, ",") {
		return netip.Addr{}, false
	}

	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}, false
	}
	return normalise(addr), true
}

// peerAddr extracts the address of the peer that actually opened the connection.
func peerAddr(remoteAddr string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// Not every RemoteAddr carries a port — httptest sets bare values.
		host = remoteAddr
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return netip.Addr{}, false
	}
	return normalise(addr), true
}

func trustedContains(trusted []netip.Prefix, addr netip.Addr) bool {
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// normalise collapses the spellings of one address into one string.
//
// Both steps close a bucket-evasion hole rather than tidying output. The rate
// limiter keys on the textual form, so ::ffff:203.0.113.9 and 203.0.113.9 would
// otherwise be two buckets for one host, and a zone suffix would be unbounded
// many — %1, %2, %eth0 — for the same link-local address.
func normalise(addr netip.Addr) netip.Addr {
	return addr.Unmap().WithZone("")
}

// ClientAddr returns the textual address a request should be attributed to.
//
// This is the value rate-limit buckets are keyed on, so it is normalised for the
// same reason [normalise] exists: one host must not be able to present as two.
// It reads r.RemoteAddr, which [RealIP] has already made authoritative — a
// handler calling this needs to know nothing about proxies.
//
// Unparseable input is returned verbatim rather than replaced with a constant.
// A shared fallback string would merge every malformed peer into one bucket,
// which is a way for one client to throttle others.
func ClientAddr(r *http.Request) string {
	if addr, ok := peerAddr(r.RemoteAddr); ok {
		return addr.String()
	}
	return r.RemoteAddr
}

// Recover turns a panic into a 500 and a log line.
//
// The stack trace goes to the log and never to the response. A Go panic message
// routinely contains the values that caused it, which for this service can mean
// an envelope, a token, or a key.
func Recover(log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if v := recover(); v != nil {
					// The panic value itself is deliberately not logged: it is
					// arbitrary data from the failure site. What is actionable
					// is where it happened, which the stack gives.
					log.ErrorContext(r.Context(), "panic recovered",
						slog.String("route", pattern(r)),
						slog.String("stack", string(debug.Stack())))
					WriteError(w, http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// Log writes one access line per request.
//
// docs/BACKEND.md §7: method, route *pattern*, status, duration. Never the
// populated path — "/v1/keys/{aci}", never "/v1/keys/3f2b...". A populated path
// is a metadata record hiding in a log line, and it survives every deletion the
// retention policy performs on the database.
//
// No client IP. §3.6 allows 24 h retention for operational triage, and that
// belongs in the reverse proxy's own log with its own lifetime, not correlated
// with application events here.
func Log(log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w}

			// Deferred so a panic that escapes an inner handler still produces a
			// line. See Chain for why this middleware must also be outside
			// Recover — the defer alone gets a line, but not a truthful status.
			defer func() {
				if rec.status == 0 {
					rec.status = http.StatusOK
				}
				log.InfoContext(r.Context(), "request",
					slog.String("method", r.Method),
					slog.String("route", pattern(r)),
					slog.Int("status", rec.status),
					slog.Duration("duration", time.Since(start)))
			}()

			next.ServeHTTP(rec, r)
		})
	}
}

// pattern returns the matched route pattern, or a placeholder.
//
// r.Pattern is empty when no route matched (a 404), and returning the requested
// path in that case would reintroduce exactly the populated-path leak this
// function exists to avoid — an attacker would only have to request a path
// containing what they wanted logged.
func pattern(r *http.Request) string {
	if r.Pattern != "" {
		return r.Pattern
	}
	return "(unmatched)"
}

// LimitBody caps request bodies at n bytes, except on the exempt path prefixes.
//
// http.MaxBytesReader rather than a Content-Length check: a chunked request
// declares no length, so a length check reads as protection while providing
// none. MaxBytesReader fails the read itself, which is the only thing an
// attacker cannot lie about.
//
// # Why exemptions exist, and what they are not
//
// The global limit is sized for the largest JSON body the API has — an envelope
// plus framing, some tens of kilobytes. Attachment upload streams megabytes, so
// it cannot live under that limit, and raising the global one to suit it would
// let every other route accept a body a thousand times larger than anything it
// could legitimately receive.
//
// An exemption is **not** "unlimited". It means the handler owns the limit for
// that route and must apply its own MaxBytesReader — see api.BlobsHandler, which
// caps at MaxBlobBytes. The list is deliberately short, spelled out at the call
// site in main, and matched by prefix so it is greppable.
func LimitBody(n int64, exempt ...string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, prefix := range exempt {
				if strings.HasPrefix(r.URL.Path, prefix) {
					next.ServeHTTP(w, r)
					return
				}
			}
			r.Body = http.MaxBytesReader(w, r.Body, n)
			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders sets the headers appropriate to an API that serves no HTML.
//
// A JSON API is not a browsing context, so the useful set is small and the point
// of each is that it holds even when a response is mishandled downstream.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// Stops a browser from second-guessing Content-Type and executing a
		// response as script.
		h.Set("X-Content-Type-Options", "nosniff")
		// Nothing here is embeddable, and a CSP that denies everything is the
		// correct policy for a surface that renders nothing.
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		// Responses can carry undelivered ciphertext and prekeys. A cache
		// anywhere on the path is storage we do not control.
		h.Set("Cache-Control", "no-store")
		// No CORS headers at all. The only client is a native app, which is not
		// subject to the same-origin policy, so any Access-Control-Allow-Origin
		// would grant browser access without buying anything.
		next.ServeHTTP(w, r)
	})
}
