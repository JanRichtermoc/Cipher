// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"cipher.relay/internal/auth"
	"cipher.relay/internal/httpx"
	"cipher.relay/internal/ratelimit"
	"cipher.relay/internal/reauth"
	"cipher.relay/internal/store"
)

// SignatureContext is prefixed to every re-authentication signature.
//
// **Domain separation, and it is not decoration.** The account key must sign
// only things this protocol asked for: without a prefix, any other place that
// ever asks a device to sign a server-chosen blob becomes a signing oracle for
// re-authentication. The version suffix is what lets the payload change later
// without a signature minted for the old shape being valid for the new one.
//
// The client builds the identical string; both sides must change together.
const SignatureContext = "cipher-reauth-v1"

// Re-authentication rate limits.
//
// Both routes are UNAUTHENTICATED — they are the path for a caller with no
// working token, so they cannot require one. That makes limiting them the only
// thing standing between the relay and an offline-grade guessing loop against a
// public key, and between it and being an amplifier.
//
// The challenge route is limited per client address only: it takes an aci from
// the body, so limiting per aci would let anyone throttle a *chosen* account by
// spending its budget. The verify route is limited on both, because there the
// aci is one the caller is claiming to control and a per-account ceiling is what
// bounds signature guessing.
var (
	challengeLimit = ratelimit.Limit{Capacity: 30, Window: time.Hour}
	reauthIPLimit  = ratelimit.Limit{Capacity: 20, Window: time.Hour}
	reauthACILimit = ratelimit.Limit{Capacity: 10, Window: time.Hour}
	// Publishing is authenticated and write-once; this only stops a loop.
	publishKeyLimit = ratelimit.Limit{Capacity: 5, Window: time.Hour}
)

// ReauthHandler serves account-key publication and re-authentication.
type ReauthHandler struct {
	db         *store.DB
	limiter    *ratelimit.Limiter
	challenges *reauth.Store
	auth       *AuthHandler
	log        *slog.Logger
}

// NewReauthHandler builds the handler.
func NewReauthHandler(
	db *store.DB,
	limiter *ratelimit.Limiter,
	challenges *reauth.Store,
	authHandler *AuthHandler,
	log *slog.Logger,
) *ReauthHandler {
	return &ReauthHandler{
		db: db, limiter: limiter, challenges: challenges, auth: authHandler, log: log,
	}
}

// Routes registers the endpoints.
//
// `PUT /v1/auth/key` is authenticated: publishing a key is something an account
// with a working session does once, and it is how installations that predate
// migration 0003 acquire one. The other two cannot be authenticated, because
// having no usable token is the situation they exist for.
func (h *ReauthHandler) Routes(mux *http.ServeMux) {
	mux.Handle("PUT /v1/auth/key", h.auth.Require(http.HandlerFunc(h.publishKey)))
	mux.HandleFunc("POST /v1/auth/challenge", h.challenge)
	mux.HandleFunc("POST /v1/auth/reauth", h.verify)
}

type publishKeyRequest struct {
	// Base64 (standard, padded) Ed25519 public key. 32 bytes.
	Key string `json:"key"`
}

type challengeRequest struct {
	ACI string `json:"aci"`
}

type challengeResponse struct {
	Challenge string `json:"challenge"`
	ExpiresIn int    `json:"expires_in"`
}

type reauthRequest struct {
	ACI       string `json:"aci"`
	Challenge string `json:"challenge"`
	Signature string `json:"signature"`
}

// SigningPayload is the exact byte string a device signs.
//
// Context, then the account, then the challenge. The aci is inside the signature
// as well as being the Redis key, so a signature is bound to the account it
// authenticates and cannot be replayed against a different one even if a
// challenge ever escaped its namespace.
func SigningPayload(aci uuid.UUID, challenge string) []byte {
	payload := make([]byte, 0, len(SignatureContext)+1+36+1+len(challenge))
	payload = append(payload, SignatureContext...)
	payload = append(payload, ':')
	payload = append(payload, aci.String()...)
	payload = append(payload, ':')
	payload = append(payload, challenge...)
	return payload
}

// publishKey stores the caller's own account key, once.
func (h *ReauthHandler) publishKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	aci, ok := AccountFrom(ctx)
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized)
		return
	}
	if !h.auth.allow(w, r, "auth-publish-key", aci.String(), publishKeyLimit) {
		return
	}

	var req publishKeyRequest
	if err := httpx.DecodeJSON(r.Body, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest)
		return
	}
	key, err := base64.StdEncoding.DecodeString(req.Key)
	if err != nil || len(key) != ed25519.PublicKeySize {
		httpx.WriteError(w, http.StatusBadRequest)
		return
	}

	// The account named is always the authenticated one — never a body field.
	// A caller that could name the account would be publishing a key for someone
	// else, which is the whole attack this endpoint would otherwise be.
	if err := h.db.SetAccountKey(ctx, aci, key); err != nil {
		if errors.Is(err, store.ErrNoAccountKey) {
			// Already published, and to a different value. Refused rather than
			// overwritten: replacing this key would convert a stolen session
			// into permanent access and lock the real owner out for good.
			httpx.WriteError(w, http.StatusConflict)
			return
		}
		h.log.ErrorContext(ctx, "publish account key failed",
			slog.String("reason", err.Error()))
		httpx.WriteError(w, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// challenge issues a single-use value for the account to sign.
//
// **It answers identically for an account that does not exist.** A challenge is
// minted and stored either way. Nothing can redeem the unknown one, because
// verification needs a stored key; what matters is that the response says
// nothing about whether the account is real. In a five-person circle, an
// existence oracle is most of the metadata worth having.
func (h *ReauthHandler) challenge(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	subject := h.limiter.Subject("auth-challenge", clientAddr(r))
	decision, err := h.limiter.Allow(ctx, subject, challengeLimit)
	if err != nil {
		h.log.ErrorContext(ctx, "rate limiter unavailable, refusing",
			slog.String("route", "POST /v1/auth/challenge"),
			slog.String("reason", err.Error()))
		httpx.WriteError(w, http.StatusServiceUnavailable)
		return
	}
	if !decision.OK {
		w.Header().Set("Retry-After", strconv.Itoa(int(decision.RetryAfter.Seconds())+1))
		httpx.WriteError(w, http.StatusTooManyRequests)
		return
	}

	var req challengeRequest
	if err := httpx.DecodeJSON(r.Body, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest)
		return
	}
	aci, err := uuid.Parse(req.ACI)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest)
		return
	}

	challenge, err := h.challenges.Issue(ctx, aci)
	if err != nil {
		h.log.ErrorContext(ctx, "could not issue a re-authentication challenge",
			slog.String("reason", err.Error()))
		httpx.WriteError(w, http.StatusServiceUnavailable)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, challengeResponse{
		Challenge: challenge,
		ExpiresIn: int(reauth.TTL.Seconds()),
	})
}

// verify consumes a challenge, checks the signature, and issues a session.
//
// # Every failure is one response
//
// Unknown account, no published key, wrong signature, unknown/expired/reused
// challenge, and malformed base64 all return 401 with an identical body. The
// same rule invite redemption follows, and for the same reason: anything more
// specific tells a caller which half of a guess was right.
func (h *ReauthHandler) verify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if !h.allowByAddress(w, r) {
		return
	}

	var req reauthRequest
	if err := httpx.DecodeJSON(r.Body, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest)
		return
	}
	aci, err := uuid.Parse(req.ACI)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest)
		return
	}

	// Per-account ceiling, after the address one. Charged before the signature
	// is checked, so a guessing loop spends budget whether or not it is close.
	if !h.auth.allow(w, r, "auth-reauth-aci", aci.String(), reauthACILimit) {
		return
	}

	if !h.authenticateSignature(ctx, aci, req) {
		httpx.WriteError(w, http.StatusUnauthorized)
		return
	}

	token, err := auth.Generate()
	if err != nil {
		h.log.ErrorContext(ctx, "could not generate a session",
			slog.String("reason", err.Error()))
		httpx.WriteError(w, http.StatusInternalServerError)
		return
	}
	expiresAt := time.Now().Add(SessionTTL)
	if err := h.db.CreateSession(ctx, token.Hash(), aci, expiresAt); err != nil {
		h.log.ErrorContext(ctx, "could not store a re-authenticated session",
			slog.String("reason", err.Error()))
		httpx.WriteError(w, http.StatusInternalServerError)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, tokenResponse{
		Token:     token.String(),
		ExpiresAt: expiresAt,
	})
}

func (h *ReauthHandler) allowByAddress(w http.ResponseWriter, r *http.Request) bool {
	ctx := r.Context()
	subject := h.limiter.Subject("auth-reauth-ip", clientAddr(r))
	decision, err := h.limiter.Allow(ctx, subject, reauthIPLimit)
	if err != nil {
		h.log.ErrorContext(ctx, "rate limiter unavailable, refusing",
			slog.String("route", "POST /v1/auth/reauth"),
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

// authenticateSignature consumes the challenge and verifies the signature.
//
// The challenge is consumed **before** the signature is checked and regardless
// of the outcome, so a wrong signature burns it. Otherwise one challenge could
// be attacked repeatedly, which is the whole point of it being single use.
func (h *ReauthHandler) authenticateSignature(
	ctx context.Context, aci uuid.UUID, req reauthRequest,
) bool {
	if err := h.challenges.Consume(ctx, aci, req.Challenge); err != nil {
		if !errors.Is(err, reauth.ErrNotRedeemable) {
			h.log.ErrorContext(ctx, "challenge store unavailable, refusing",
				slog.String("reason", err.Error()))
		}
		return false
	}

	signature, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return false
	}

	key, err := h.db.AccountKey(ctx, aci)
	if err != nil {
		if !errors.Is(err, store.ErrNoAccountKey) {
			h.log.ErrorContext(ctx, "could not read an account key",
				slog.String("reason", err.Error()))
		}
		return false
	}
	if len(key) != ed25519.PublicKeySize {
		return false
	}

	return ed25519.Verify(ed25519.PublicKey(key), SigningPayload(aci, req.Challenge), signature)
}
