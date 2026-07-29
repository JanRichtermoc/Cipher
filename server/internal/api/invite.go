// Package api holds the relay's HTTP handlers.
//
// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"cipher.relay/internal/httpx"
	"cipher.relay/internal/invite"
	"cipher.relay/internal/ratelimit"
	"cipher.relay/internal/store"
)

// Identity key and registration id bounds, mirroring the schema's CHECKs.
//
// Validated here as well as in Postgres so a bad request is a 400 rather than a
// constraint violation surfacing as a 500. The schema remains the authority —
// this is the polite layer, not the enforcing one.
const (
	minIdentityKeyBytes = 32
	maxIdentityKeyBytes = 64
)

// InviteTTL is how long a freshly issued invite remains redeemable.
//
// Short on purpose. An unredeemed invite is a live credential for creating an
// account, and it is also a row recording that someone was invited — so its
// lifetime is both an attack window and a retention window.
const InviteTTL = 48 * time.Hour

// redeemLimit throttles redemption attempts per source address.
//
// docs/BACKEND.md §5: 5 per hour. Guessing a 128-bit code is infeasible with or
// without this, so the limit is not really anti-guessing — it stops the endpoint
// being a free amplifier, and it bounds the damage if the entropy is ever
// reduced by someone who does not read invite.EntropyBits first.
var redeemLimit = ratelimit.Limit{Capacity: 5, Window: time.Hour}

// InviteHandler serves invite redemption and authenticated issuance.
//
// The *first* invite is still not issued here. See docs/BACKEND.md §8: there is
// no admin API, and the first account cannot be authorised by an authenticated
// call because there is nobody to authenticate. That one comes from
// `relay --issue-invite` on the host. Every subsequent invite is issued by an
// account that already exists, through POST /v1/invite.
type InviteHandler struct {
	db      *store.DB
	limiter *ratelimit.Limiter
	auth    *AuthHandler
	log     *slog.Logger
	ttl     time.Duration
}

// NewInviteHandler builds the handler.
//
// It takes the AuthHandler because redemption issues a session: an account
// created without one would have to authenticate through some other path, and
// the only other path is the invite it just consumed.
func NewInviteHandler(
	db *store.DB,
	limiter *ratelimit.Limiter,
	authHandler *AuthHandler,
	log *slog.Logger,
) *InviteHandler {
	return &InviteHandler{
		db: db, limiter: limiter, auth: authHandler, log: log, ttl: InviteTTL,
	}
}

// Routes registers the endpoints.
func (h *InviteHandler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/invite/redeem", h.redeem)
	mux.Handle("POST /v1/invite", h.auth.Require(http.HandlerFunc(h.issue)))
}

type issueResponse struct {
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
}

// issue mints an invite on behalf of an authenticated account.
//
// **Who issued it is not recorded.** docs/BACKEND.md §2.2: the invite graph is
// the social graph of a closed circle and is the most valuable thing a seizure
// could recover, so the `invites` table has two columns and neither is
// `created_by`. The per-account limit that stops one account minting invites
// without bound is a Redis counter keyed by an HMAC of the account id — it
// expires, and a column would not.
//
// The account id reaches the rate limiter and nothing else. It is not logged, and
// it is not written anywhere that outlives the bucket's TTL.
func (h *InviteHandler) issue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	aci, ok := AccountFrom(ctx)
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized)
		return
	}

	if !h.auth.allow(w, r, "invite-issue", aci.String(), issueLimit) {
		return
	}

	code, err := IssueInvite(ctx, h.db, h.ttl)
	if err != nil {
		h.log.ErrorContext(ctx, "issue invite failed", slog.String("reason", err.Error()))
		httpx.WriteError(w, http.StatusInternalServerError)
		return
	}

	httpx.WriteJSON(w, http.StatusCreated, issueResponse{
		Code:      code.String(),
		ExpiresAt: time.Now().Add(h.ttl),
	})
}

type redeemRequest struct {
	Code string `json:"code"`
	// Base64 (standard, padded) — JSON has no byte type and hex doubles the
	// size of a value that is already being typed into a mobile client.
	IdentityKey    string `json:"identity_key"`
	RegistrationID uint32 `json:"registration_id"`
}

type redeemResponse struct {
	ACI string `json:"aci"`
	// The session that redemption establishes. Without it the new account would
	// have no way to authenticate: the only credential it ever held was the
	// invite, and that has just been consumed.
	Token          string    `json:"token"`
	TokenExpiresAt time.Time `json:"token_expires_at"`
}

// redeem consumes an invite and creates an account.
//
// # Every failure looks the same
//
// Unknown code, already-redeemed code, expired code, and lost race all return
// 401 with an identical body. The store returns one error for all of them
// (store.ErrInviteNotRedeemable) because the schema cannot tell them apart
// either — a redeemed invite is deleted, not flagged. Anything more specific
// would confirm to an attacker that a guessed code had once been real, which is
// the only useful signal a guessing loop can extract.
//
// Malformed input is 400 and is a different case: it says nothing about whether
// any code exists, only that this string could never be one.
func (h *InviteHandler) redeem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Rate limit BEFORE parsing. Parsing first would let an attacker spend the
	// server's CPU on JSON decoding at whatever rate they liked, and would
	// consume no token when the body was junk.
	subject := h.limiter.Subject("invite-redeem", clientAddr(r))
	decision, err := h.limiter.Allow(ctx, subject, redeemLimit)
	if err != nil {
		// Fails closed. See ratelimit.Allow: an attacker who can degrade Redis
		// must not thereby remove the brute-force limit.
		h.log.ErrorContext(ctx, "rate limiter unavailable, refusing",
			slog.String("route", "POST /v1/invite/redeem"),
			slog.String("reason", err.Error()))
		httpx.WriteError(w, http.StatusServiceUnavailable)
		return
	}
	if !decision.OK {
		w.Header().Set("Retry-After", strconv.Itoa(int(decision.RetryAfter.Seconds())+1))
		httpx.WriteError(w, http.StatusTooManyRequests)
		return
	}

	var req redeemRequest
	dec := json.NewDecoder(r.Body)
	// Unknown fields are refused rather than ignored: a client sending
	// "registrationId" instead of "registration_id" would otherwise silently
	// register with id 0, and the failure would appear much later as a session
	// that cannot be established.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest)
		return
	}

	code, err := invite.Parse(req.Code)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest)
		return
	}

	identityKey, err := base64.StdEncoding.DecodeString(req.IdentityKey)
	if err != nil ||
		len(identityKey) < minIdentityKeyBytes ||
		len(identityKey) > maxIdentityKeyBytes {
		httpx.WriteError(w, http.StatusBadRequest)
		return
	}
	if req.RegistrationID == 0 {
		httpx.WriteError(w, http.StatusBadRequest)
		return
	}

	// Server-generated. A client-supplied aci would let a caller choose their own
	// address — and therefore claim one already in use, or one they expect a
	// future peer to be given.
	aci, err := uuid.NewRandom()
	if err != nil {
		h.log.ErrorContext(ctx, "could not generate an account identifier",
			slog.String("reason", err.Error()))
		httpx.WriteError(w, http.StatusInternalServerError)
		return
	}

	err = h.db.RedeemInvite(ctx, code.Hash(), store.Account{
		ACI:            aci,
		IdentityKey:    identityKey,
		RegistrationID: req.RegistrationID,
	})
	switch {
	case errors.Is(err, store.ErrInviteNotRedeemable):
		// No detail, and no log of the presented code or its hash: the hash of a
		// guess is still a record of the guess, and a log of failed redemptions
		// keyed by hash would let anyone with log access replay a successful one.
		httpx.WriteError(w, http.StatusUnauthorized)
		return
	case err != nil:
		h.log.ErrorContext(ctx, "redeem failed",
			slog.String("reason", err.Error()))
		httpx.WriteError(w, http.StatusInternalServerError)
		return
	}

	// The account now exists and the invite is gone, so this is the only moment
	// at which a session can be established for it.
	//
	// Issued *after* the redemption transaction commits rather than inside it.
	// The two are not atomic, and that is the correct direction to fail: an
	// account with no session can redeem nothing further but can be recovered
	// with a fresh invite, whereas rolling back a committed redemption to undo a
	// failed token write would mean re-crediting a single-use invite — turning a
	// transient error into a way to redeem a code twice.
	token, err := h.auth.Issue(ctx, aci)
	if err != nil {
		h.log.ErrorContext(ctx, "account created but session issuance failed",
			slog.String("reason", err.Error()))
		httpx.WriteError(w, http.StatusInternalServerError)
		return
	}

	// Nothing identifying is logged here either. That an account was created is
	// the interesting operational fact; which account it was is a record linking
	// a time to an identifier, and the retention policy exists to not have those.
	h.log.InfoContext(ctx, "account created")

	httpx.WriteJSON(w, http.StatusCreated, redeemResponse{
		ACI:            aci.String(),
		Token:          token.String(),
		TokenExpiresAt: time.Now().Add(SessionTTL),
	})
}

// clientAddr returns the address to rate-limit against.
//
// **X-Forwarded-For is deliberately ignored.** In P4 there is no reverse proxy,
// so the header is attacker-controlled: honouring it would let a single client
// present a new value per request and defeat the limit entirely — turning the
// header from a convenience into the bypass. P5 introduces a proxy, and *that*
// is when a trusted-proxy configuration can be added, with the trust boundary
// stated explicitly rather than assumed.
func clientAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// IssueInvite mints one invite and returns the code.
//
// The code is returned to the caller and never stored; only its hash reaches the
// database. Used by the operator command in cmd/relay and, from P4.S04, by the
// authenticated user-to-user issuance endpoint.
func IssueInvite(ctx context.Context, db *store.DB, ttl time.Duration) (invite.Code, error) {
	code, err := invite.Generate()
	if err != nil {
		return invite.Code{}, err
	}
	if err := db.CreateInvite(ctx, code.Hash(), time.Now().Add(ttl)); err != nil {
		return invite.Code{}, err
	}
	return code, nil
}
