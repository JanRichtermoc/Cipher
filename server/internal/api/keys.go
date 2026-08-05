// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"cipher.relay/internal/httpx"
	"cipher.relay/internal/ratelimit"
	"cipher.relay/internal/store"
)

// Bounds, mirroring the schema's CHECKs. Validated here so a bad request is a
// 400 rather than a constraint violation surfacing as a 500; the schema remains
// the authority.
const (
	minCurveKeyBytes = 32
	maxCurveKeyBytes = 64
	minKyberKeyBytes = 32
	// Loose upper bound. ML-KEM public keys are far larger than Curve25519 ones
	// and the exact serialized size including libsignal's type prefix is not
	// something this file can assert; the bound catches nonsense, not off-by-one.
	maxKyberKeyBytes = 4096
	minSignatureLen  = 32
	maxSignatureLen  = 128

	// maxPreKeysPerUpload caps one request. Storage per account is otherwise
	// unbounded by anything except the body limit, and an account uploading
	// hundreds of thousands of prekeys is not replenishing a pool.
	maxPreKeysPerUpload = 200

	// maxPreKeyID is the protocol's own ceiling: Signal keeps prekey ids inside
	// 24 bits, and `CipherProtocolStore.maxPreKeyId` refuses to mint one above it,
	// so this bound refuses nothing a real client sends.
	//
	// Two things went wrong without it. The field decodes as `uint32` while the
	// column is `INTEGER`, so an id above 2147483647 reached PostgreSQL and came
	// back as an out-of-range error — a 500 and a logged database failure for what
	// is a malformed request. And an id between 2^24 and that limit stored
	// successfully but is outside what the peer's libsignal will accept in a
	// bundle, so the key sat in the pool waiting to be dispensed into a session
	// that could never be established.
	maxPreKeyID = 0xFF_FFFF
)

// Prekey-fetch limits (docs/BACKEND.md §5). Both apply; the burst limit stops a
// flood and the daily limit stops a slow drain that stays under it.
//
// **This is the mitigation for AUDIT 3.1, not a capacity control.** Every fetch
// consumes one of the target's one-time prekeys, so an unthrottled directory lets
// any authenticated caller drain any peer's pool purely by asking — no message
// sent, no interaction with the victim at all. P4.S06 makes it mandatory in this
// phase for that reason, and "defer to P6" is the step's stated anti-goal.
var (
	fetchBurstLimit = ratelimit.Limit{Capacity: 10, Window: time.Hour}
	fetchDailyLimit = ratelimit.Limit{Capacity: 30, Window: 24 * time.Hour}
	publishLimit    = ratelimit.Limit{Capacity: 6, Window: 24 * time.Hour}
)

// KeysHandler serves the prekey directory.
type KeysHandler struct {
	db   *store.DB
	auth *AuthHandler
	log  *slog.Logger
}

// NewKeysHandler builds the handler.
func NewKeysHandler(db *store.DB, authHandler *AuthHandler, log *slog.Logger) *KeysHandler {
	return &KeysHandler{db: db, auth: authHandler, log: log}
}

// Routes registers the endpoints. **Both require authentication.**
//
// The fetch route especially: an unauthenticated prekey directory would make the
// per-account limit unenforceable, and would let anyone on the internet drain any
// pool. It would also be a membership oracle for the whole circle.
func (h *KeysHandler) Routes(mux *http.ServeMux) {
	mux.Handle("PUT /v1/keys", h.auth.Require(http.HandlerFunc(h.publish)))
	mux.Handle("GET /v1/keys/{aci}", h.auth.Require(http.HandlerFunc(h.fetch)))
}

type signedKeyJSON struct {
	KeyID     uint32 `json:"key_id"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

type preKeyJSON struct {
	KeyID     uint32 `json:"key_id"`
	PublicKey string `json:"public_key"`
}

type publishRequest struct {
	SignedPreKey signedKeyJSON `json:"signed_prekey"`
	// Mandatory. See validate: an upload without it is rejected, which is the
	// P4.S05 gate — "a non-PQ bundle is refused by the server".
	KyberLastResort signedKeyJSON   `json:"kyber_last_resort"`
	KyberPreKeys    []signedKeyJSON `json:"kyber_prekeys"`
	OneTimePreKeys  []preKeyJSON    `json:"one_time_prekeys"`
}

type publishResponse struct {
	// The account's own remaining counts, so the client replenishes on a
	// threshold rather than a schedule. Never disclosed for anyone else: a peer's
	// pool size is precisely the measurement an attacker draining it wants.
	OneTimePreKeys int `json:"one_time_prekeys"`
	KyberPreKeys   int `json:"kyber_prekeys"`
}

type bundleResponse struct {
	RegistrationID        uint32 `json:"registration_id"`
	IdentityKey           string `json:"identity_key"`
	PreKeyID              uint32 `json:"prekey_id"`
	PreKey                string `json:"prekey"`
	SignedPreKeyID        uint32 `json:"signed_prekey_id"`
	SignedPreKey          string `json:"signed_prekey"`
	SignedPreKeySignature string `json:"signed_prekey_signature"`
	KyberPreKeyID         uint32 `json:"kyber_prekey_id"`
	KyberPreKey           string `json:"kyber_prekey"`
	KyberPreKeySignature  string `json:"kyber_prekey_signature"`
}

// decodeKey decodes and length-checks a base64 key.
func decodeKey(s string, minLen, maxLen int) ([]byte, bool) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) < minLen || len(b) > maxLen {
		return nil, false
	}
	return b, true
}

func decodeSigned(k signedKeyJSON, minKey, maxKey int) (store.SignedPreKey, bool) {
	if k.KeyID > maxPreKeyID {
		return store.SignedPreKey{}, false
	}
	pub, ok := decodeKey(k.PublicKey, minKey, maxKey)
	if !ok {
		return store.SignedPreKey{}, false
	}
	sig, ok := decodeKey(k.Signature, minSignatureLen, maxSignatureLen)
	if !ok {
		return store.SignedPreKey{}, false
	}
	return store.SignedPreKey{KeyID: k.KeyID, PublicKey: pub, Signature: sig}, true
}

// validate converts the request into a store upload, refusing anything incomplete.
//
// The refusal that matters is the Kyber one. PQXDH is a locked decision — Kyber is
// mandatory, never optional — so an upload carrying only classical key material is
// rejected outright rather than stored. Storing it would mean the omission
// surfaces at dispense time as a bundle that cannot be served, or worse, as a
// bundle served without its KEM half, which is a silent downgrade to X3DH.
func (r publishRequest) validate() (store.PreKeyUpload, bool) {
	signed, ok := decodeSigned(r.SignedPreKey, minCurveKeyBytes, maxCurveKeyBytes)
	if !ok {
		return store.PreKeyUpload{}, false
	}

	// An absent kyber_last_resort decodes to the zero value, whose empty strings
	// fail the length check — so "missing" and "malformed" are the same refusal
	// without needing a pointer or an explicit presence flag.
	kyber, ok := decodeSigned(r.KyberLastResort, minKyberKeyBytes, maxKyberKeyBytes)
	if !ok {
		return store.PreKeyUpload{}, false
	}

	if len(r.KyberPreKeys) > maxPreKeysPerUpload ||
		len(r.OneTimePreKeys) > maxPreKeysPerUpload {
		return store.PreKeyUpload{}, false
	}

	up := store.PreKeyUpload{SignedPreKey: signed, KyberLastResort: kyber}

	for _, k := range r.KyberPreKeys {
		decoded, ok := decodeSigned(k, minKyberKeyBytes, maxKyberKeyBytes)
		if !ok {
			return store.PreKeyUpload{}, false
		}
		up.KyberOneTime = append(up.KyberOneTime, decoded)
	}
	for _, k := range r.OneTimePreKeys {
		if k.KeyID > maxPreKeyID {
			return store.PreKeyUpload{}, false
		}
		pub, ok := decodeKey(k.PublicKey, minCurveKeyBytes, maxCurveKeyBytes)
		if !ok {
			return store.PreKeyUpload{}, false
		}
		up.OneTimePreKeys = append(up.OneTimePreKeys, store.PreKey{KeyID: k.KeyID, PublicKey: pub})
	}
	return up, true
}

// publish stores the caller's own key material.
//
// An account can only ever publish its own keys — the target is the authenticated
// account, never a path or body parameter. Allowing a caller to name the account
// would let anyone replace anyone's prekeys, which is a complete break of the
// protocol: every new session with the victim would be established against keys
// the attacker chose.
func (h *KeysHandler) publish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	aci, ok := AccountFrom(ctx)
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized)
		return
	}
	if !h.auth.allow(w, r, "keys-publish", aci.String(), publishLimit) {
		return
	}

	var req publishRequest
	if err := httpx.DecodeJSON(r.Body, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest)
		return
	}

	upload, ok := req.validate()
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest)
		return
	}

	if err := h.db.PublishPreKeys(ctx, aci, upload); err != nil {
		h.log.ErrorContext(ctx, "publish prekeys failed", slog.String("reason", err.Error()))
		httpx.WriteError(w, http.StatusInternalServerError)
		return
	}

	curve, err := h.db.CountOneTimePreKeys(ctx, aci)
	if err != nil {
		h.log.ErrorContext(ctx, "count prekeys failed", slog.String("reason", err.Error()))
		httpx.WriteError(w, http.StatusInternalServerError)
		return
	}
	kyber, err := h.db.CountKyberOneTimePreKeys(ctx, aci)
	if err != nil {
		h.log.ErrorContext(ctx, "count kyber prekeys failed", slog.String("reason", err.Error()))
		httpx.WriteError(w, http.StatusInternalServerError)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, publishResponse{
		OneTimePreKeys: curve,
		KyberPreKeys:   kyber,
	})
}

// fetch dispenses a peer's bundle, consuming a one-time prekey.
//
// # Both limits, and the target is not the subject
//
// The buckets are keyed by the *caller*, not by the account being fetched. Keying
// by target would let one attacker with several accounts drain a pool at N times
// the rate while each bucket looked healthy, and would let anyone deny service to
// a peer by exhausting the bucket that peer's fetches share.
//
// # Every failure is 404, with one body
//
// Unknown account, never published, empty pool — one response. docs/BACKEND.md §8
// forbids account enumeration, and for a five-person circle "does this account
// exist" is most of the metadata worth having. The caller cannot act on the
// distinction anyway: all three mean "no session can be started right now".
func (h *KeysHandler) fetch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	caller, ok := AccountFrom(ctx)
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized)
		return
	}

	// Limits before parsing the path parameter, so a flood of malformed targets
	// costs tokens rather than work.
	if !h.auth.allow(w, r, "keys-fetch-burst", caller.String(), fetchBurstLimit) {
		return
	}
	if !h.auth.allow(w, r, "keys-fetch-daily", caller.String(), fetchDailyLimit) {
		return
	}

	target, err := uuid.Parse(r.PathValue("aci"))
	if err != nil {
		// 404, not 400. A malformed identifier and an unknown one must be
		// indistinguishable, or the shape of a valid account id becomes probeable.
		httpx.WriteError(w, http.StatusNotFound)
		return
	}

	bundle, err := h.db.DispenseBundle(ctx, target)
	if err != nil {
		if errors.Is(err, store.ErrBundleUnavailable) {
			httpx.WriteError(w, http.StatusNotFound)
			return
		}
		h.log.ErrorContext(ctx, "dispense failed", slog.String("reason", err.Error()))
		httpx.WriteError(w, http.StatusInternalServerError)
		return
	}

	if bundle.KyberWasLastResort {
		// Operationally interesting: it means someone's one-time Kyber pool is
		// empty, which is the observable symptom of a drain (AUDIT 3.1). Logged
		// without either account — whose pool is empty and who asked are exactly
		// the two facts the retention policy exists to not accumulate.
		h.log.WarnContext(ctx, "served the last-resort kyber prekey; a one-time pool is empty")
	}

	httpx.WriteJSON(w, http.StatusOK, bundleResponse{
		RegistrationID:        bundle.RegistrationID,
		IdentityKey:           base64.StdEncoding.EncodeToString(bundle.IdentityKey),
		PreKeyID:              bundle.PreKey.KeyID,
		PreKey:                base64.StdEncoding.EncodeToString(bundle.PreKey.PublicKey),
		SignedPreKeyID:        bundle.SignedPreKey.KeyID,
		SignedPreKey:          base64.StdEncoding.EncodeToString(bundle.SignedPreKey.PublicKey),
		SignedPreKeySignature: base64.StdEncoding.EncodeToString(bundle.SignedPreKey.Signature),
		KyberPreKeyID:         bundle.KyberPreKey.KeyID,
		KyberPreKey:           base64.StdEncoding.EncodeToString(bundle.KyberPreKey.PublicKey),
		KyberPreKeySignature:  base64.StdEncoding.EncodeToString(bundle.KyberPreKey.Signature),
	})
}
