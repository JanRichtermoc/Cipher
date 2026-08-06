// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"cipher.relay/internal/auth"
	"cipher.relay/internal/httpx"
	"cipher.relay/internal/ratelimit"
	"cipher.relay/internal/store"
)

// SessionTTL is how long an issued token remains valid without rotation.
//
// Long, because this is a messenger: a session that expires weekly trains people
// to re-authenticate reflexively, which is the habit phishing depends on. Long is
// affordable here only because revocation is immediate — `DELETE` on one row —
// so the TTL is a backstop for a forgotten device rather than the primary
// control.
const SessionTTL = 30 * 24 * time.Hour

// rotateLimit and issueLimit come from docs/BACKEND.md §5.
var (
	rotateLimit = ratelimit.Limit{Capacity: 10, Window: time.Hour}
	issueLimit  = ratelimit.Limit{Capacity: 3, Window: 24 * time.Hour}
)

// contextKey is unexported so no other package can write to this context slot.
//
// A string key would let any package — including a future dependency — overwrite
// the authenticated account with a value of its choosing. That is not a
// theoretical concern: it is the documented reason context keys should be
// unexported types, and the value here decides who the caller is.
type contextKey struct{ name string }

var accountContextKey = &contextKey{"aci"}

// AccountFrom returns the authenticated account.
//
// The boolean is not decoration. A handler that reads this and ignores the second
// return value gets uuid.Nil, which is a valid-looking UUID and would be used as
// an account identifier — so the failure mode of forgetting the check is
// "operates on the nil account" rather than a panic. Handlers behind
// [AuthHandler.Require] can rely on it being present; nothing else may.
func AccountFrom(ctx context.Context) (uuid.UUID, bool) {
	aci, ok := ctx.Value(accountContextKey).(uuid.UUID)
	return aci, ok
}

// AuthHandler issues, rotates and revokes session tokens, and provides the
// middleware that authenticates every other route.
type AuthHandler struct {
	db      *store.DB
	limiter *ratelimit.Limiter
	log     *slog.Logger
	ttl     time.Duration

	// Unix nanoseconds of the last activity-refresh warning, or 0 for never.
	// See reportLastSeenFailure for why this is throttled rather than logged
	// per request.
	lastSeenWarnedAt atomic.Int64
}

// NewAuthHandler builds the handler.
func NewAuthHandler(db *store.DB, limiter *ratelimit.Limiter, log *slog.Logger) *AuthHandler {
	return &AuthHandler{db: db, limiter: limiter, log: log, ttl: SessionTTL}
}

// Routes registers the endpoints. Both require authentication.
func (h *AuthHandler) Routes(mux *http.ServeMux) {
	mux.Handle("POST /v1/auth/rotate", h.Require(http.HandlerFunc(h.rotate)))
	mux.Handle("DELETE /v1/auth", h.Require(http.HandlerFunc(h.revoke)))
	mux.Handle("DELETE /v1/auth/all", h.Require(http.HandlerFunc(h.revokeAll)))
}

// Issue mints a token for an account and stores its hash.
//
// Returns the token to the caller; only the hash reaches the database.
func (h *AuthHandler) Issue(ctx context.Context, aci uuid.UUID) (auth.Token, error) {
	token, err := auth.Generate()
	if err != nil {
		return auth.Token{}, err
	}
	if err := h.db.CreateSession(ctx, token.Hash(), aci, time.Now().Add(h.ttl)); err != nil {
		return auth.Token{}, err
	}
	return token, nil
}

// Require authenticates the request and puts the account in its context.
//
// # Every rejection is the same
//
// Missing header, wrong scheme, malformed token, unknown token, expired token —
// all 401 with an identical body. Each distinction an attacker can observe is a
// bit of an oracle: a 400 for "malformed" would confirm which guesses had the
// right shape, and a distinct "expired" would confirm that a stolen value had
// once been real.
//
// WWW-Authenticate is deliberately omitted. It is the correct HTTP thing to send
// and it would tell an unauthenticated scanner exactly what this endpoint wants;
// the only client is a native app that already knows.
func (h *AuthHandler) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := auth.ParseBearer(r.Header.Get("Authorization"))
		if err != nil {
			httpx.WriteError(w, http.StatusUnauthorized)
			return
		}

		aci, err := h.db.LookupSession(r.Context(), token.Hash())
		if errors.Is(err, store.ErrLastSeenNotRefreshed) {
			// The token authenticated; only the activity write failed. Serve the
			// request — refusing it would turn bookkeeping into an outage — but
			// say so, because an account whose `last_seen` stops advancing is on
			// its way to the abandonment sweep while still in daily use.
			h.reportLastSeenFailure(r.Context())
			err = nil
		}
		if err != nil {
			if !errors.Is(err, store.ErrSessionNotFound) {
				// A database failure is not an authentication failure, and
				// reporting it as 401 would tell a user their session had ended
				// when it had not — and would hide an outage behind a
				// plausible-looking status.
				h.log.ErrorContext(r.Context(), "session lookup failed",
					slog.String("reason", err.Error()))
				httpx.WriteError(w, http.StatusServiceUnavailable)
				return
			}
			httpx.WriteError(w, http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), accountContextKey, aci)
		// The token is deliberately NOT put in the context. Only rotate and
		// revoke need the presented credential, and they re-read the header;
		// leaving it in the context would make it reachable from every handler
		// and from anything that dumps a context during debugging.
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// lastSeenWarnInterval is the minimum gap between activity-refresh warnings.
//
// docs/BACKEND.md §7: log volume is itself metadata, and a line that fires once
// per authenticated request is a request record — which is exactly the shape this
// warning would take, because a failing refresh leaves `last_seen` stale and every
// subsequent request retries and fails again. Throttling turns it back into what an
// operator actually wants: a signal that the fault is present, not a count of who
// was talking to the relay while it was.
const lastSeenWarnInterval = time.Minute

// reportLastSeenFailure warns at most once per lastSeenWarnInterval.
//
// No account identifier, deliberately. `aci` is not logged at info level
// (docs/BACKEND.md §7) and the redaction denylist does not cover it, so a field
// naming the affected account would be a per-account activity record written by
// the very code that exists to protect activity data. The operator's next step is
// to look at the database, not at which account it was.
func (h *AuthHandler) reportLastSeenFailure(ctx context.Context) {
	now := time.Now().UnixNano()
	last := h.lastSeenWarnedAt.Load()
	if last != 0 && now-last < int64(lastSeenWarnInterval) {
		return
	}
	// CompareAndSwap, not a plain Store: under concurrent requests every
	// goroutine would otherwise pass the check above and log, which is the
	// per-request volume this is here to avoid.
	if !h.lastSeenWarnedAt.CompareAndSwap(last, now) {
		return
	}
	h.log.WarnContext(ctx, "an authenticated account's activity date could not be "+
		"refreshed; while this persists, accounts in daily use are ageing towards "+
		"the abandonment sweep (docs/BACKEND.md §4)",
		slog.Duration("suppressing_further_warnings_for", lastSeenWarnInterval))
}

type tokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// rotate exchanges the presented token for a new one.
//
// The old token stops working immediately — see store.RotateSession for why the
// alternative is an issuance rather than a rotation.
func (h *AuthHandler) rotate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	aci, ok := AccountFrom(ctx)
	if !ok {
		// Unreachable behind Require, and handled rather than assumed: the cost
		// of being wrong is rotating a token for uuid.Nil.
		httpx.WriteError(w, http.StatusUnauthorized)
		return
	}

	if !h.allow(w, r, "auth-rotate", aci.String(), rotateLimit) {
		return
	}

	// Re-read rather than carry it through the context. One place holds the
	// presented credential, and it is the request.
	old, err := auth.ParseBearer(r.Header.Get("Authorization"))
	if err != nil {
		httpx.WriteError(w, http.StatusUnauthorized)
		return
	}

	fresh, err := auth.Generate()
	if err != nil {
		h.log.ErrorContext(ctx, "token generation failed",
			slog.String("reason", err.Error()))
		httpx.WriteError(w, http.StatusInternalServerError)
		return
	}

	expiresAt := time.Now().Add(h.ttl)
	if _, err := h.db.RotateSession(ctx, old.Hash(), fresh.Hash(), expiresAt); err != nil {
		if errors.Is(err, store.ErrSessionNotFound) {
			// The token was revoked between Require and here. Rare, and the
			// right answer is the same 401 as any other unusable credential.
			httpx.WriteError(w, http.StatusUnauthorized)
			return
		}
		h.log.ErrorContext(ctx, "rotate failed", slog.String("reason", err.Error()))
		httpx.WriteError(w, http.StatusInternalServerError)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, tokenResponse{
		Token:     fresh.String(),
		ExpiresAt: expiresAt,
	})
}

// revoke signs this session out.
func (h *AuthHandler) revoke(w http.ResponseWriter, r *http.Request) {
	token, err := auth.ParseBearer(r.Header.Get("Authorization"))
	if err != nil {
		httpx.WriteError(w, http.StatusUnauthorized)
		return
	}

	if err := h.db.DeleteSession(r.Context(), token.Hash()); err != nil {
		h.log.ErrorContext(r.Context(), "revoke failed", slog.String("reason", err.Error()))
		httpx.WriteError(w, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// revokeAll signs every session for this account out, including this one.
//
// Not rate limited. It is authenticated, it only ever destroys the caller's own
// access, and it is what someone reaches for when they think they have been
// compromised — throttling the panic button is the wrong trade.
func (h *AuthHandler) revokeAll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	aci, ok := AccountFrom(ctx)
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized)
		return
	}

	if _, err := h.db.DeleteSessionsForAccount(ctx, aci); err != nil {
		h.log.ErrorContext(ctx, "revoke all failed", slog.String("reason", err.Error()))
		httpx.WriteError(w, http.StatusInternalServerError)
		return
	}
	// The count is not returned. It is the number of devices the account has
	// signed in, which is not something the response needs to state and is not
	// something a stolen session should be able to ask.
	w.WriteHeader(http.StatusNoContent)
}

// allow applies a rate limit, writing the response itself when it refuses.
//
// Returns true when the caller should continue. Shared by every rate-limited
// handler so the fail-closed behaviour and the Retry-After header are written
// once rather than repeated per endpoint with a chance of divergence.
func (h *AuthHandler) allow(
	w http.ResponseWriter,
	r *http.Request,
	kind, value string,
	limit ratelimit.Limit,
) bool {
	subject := h.limiter.Subject(kind, value)
	decision, err := h.limiter.Allow(r.Context(), subject, limit)
	if err != nil {
		h.log.ErrorContext(r.Context(), "rate limiter unavailable, refusing",
			slog.String("route", kind),
			slog.String("reason", err.Error()))
		httpx.WriteError(w, http.StatusServiceUnavailable)
		return false
	}
	if !decision.OK {
		w.Header().Set("Retry-After", strconv.Itoa(int(decision.RetryAfter.Seconds())+1))
		httpx.WriteError(w, http.StatusTooManyRequests)
		return false
	}
	return true
}
