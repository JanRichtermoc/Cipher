// Package httpx holds the HTTP plumbing shared by every route: middleware,
// error responses, and the JSON writer.
//
// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
package httpx

import (
	"encoding/json"
	"log/slog"
	"net/http"
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
