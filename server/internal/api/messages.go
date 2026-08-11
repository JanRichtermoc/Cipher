// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"encoding/base64"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"cipher.relay/internal/httpx"
	"cipher.relay/internal/ratelimit"
	"cipher.relay/internal/store"
)

// MessageTTL is how long an undelivered message survives (docs/BACKEND.md §4).
//
// 30 days. The trade it encodes: a device offline past this loses its
// undelivered mail. That is the correct direction — the alternative is a relay
// that accumulates ciphertext for devices that will never return, which is the
// archive §3.1 says does not exist — and it must be surfaced honestly in the UI
// rather than presented as delivery.
const MessageTTL = 30 * 24 * time.Hour

// maxFetchBatch bounds one fetch response.
//
// Without it, an account returning after a long absence would receive every
// pending envelope in one body — potentially tens of megabytes, allocated in full
// on both sides. The client pages by acknowledging what it has stored and asking
// again.
const maxFetchBatch = 100

// maxAckBatch bounds one acknowledgement. Larger than a fetch batch so a client
// can always acknowledge everything it was just given.
const maxAckBatch = 200

// DefaultMaxPendingBytes is the per-recipient ceiling on undelivered envelope
// bytes (AUDIT 5.39, docs/BACKEND.md §5). 32 MiB, and the number is argued
// rather than round.
//
// **What it costs an honest recipient: nothing reachable.** A short message pads
// to the 256-byte plaintext bucket (MessagePadding) and travels in a ~350-byte
// sealed-sender container, so a typical envelope is around 700 bytes — 32 MiB is
// roughly 48,000 of them, or about 510 at the largest legal size of
// store.MaxEnvelopeBytes. To reach it, a recipient must stay offline while ~1,600
// messages a day are addressed to them, every day, for the whole 30-day TTL: ten
// peers each sending 160 messages into a silence. Acknowledgement deletes, so an
// online recipient's queue sits near zero and never approaches this.
//
// **What it costs a hostile sender: the attack.** The send limit is 60/minute
// against a 65,567-byte maximum, so one account could write ≈3.75 MiB/minute,
// ≈5.3 GiB/day, retained 30 days — against a 40 GB disk, and a full disk is what
// stops the retention sweep, the highest-value control in the design. The same
// account now fills one recipient's ceiling in under nine minutes and is then
// refused. Total undelivered storage becomes 32 MiB × accounts: ≈640 MiB for a
// twenty-member circle, where the honest queue is a rounding error.
//
// It does **not** bound what the recipient's *device* must do: a queue at the
// ceiling is still ~48,000 envelopes to fetch and decrypt, and blocking is
// client-side and happens after decryption. The ceiling bounds the relay's disk
// and, with it, the drain — it does not make a flood free to receive.
const DefaultMaxPendingBytes int64 = 32 << 20

var (
	sendLimit  = ratelimit.Limit{Capacity: 60, Window: time.Minute}
	fetchLimit = ratelimit.Limit{Capacity: 120, Window: time.Minute}
	// Acknowledgement had no limit at all (AUDIT 5.23). It is cheap per call but
	// it is a `DELETE ... WHERE aci = $1 AND id = ANY($2)` with up to 200 ids, so
	// an authenticated caller could hold a database connection busy indefinitely
	// for free.
	//
	// Sized against the client's real behaviour rather than guessed: one receive
	// cycle drains at most 20 pages and acknowledges once per page, so 120 per
	// minute is six full drains a minute — far more than a device that is told
	// about new mail by push will ever need, and still a ceiling.
	ackLimit = ratelimit.Limit{Capacity: 120, Window: time.Minute}
)

// MessagesHandler is the store-and-forward relay.
//
// It is the part of this service that most obviously *could* be curious and is
// most carefully not. It moves opaque bytes between accounts and forgets them the
// moment it is told they arrived.
type MessagesHandler struct {
	db   *store.DB
	auth *AuthHandler
	log  *slog.Logger
	ttl  time.Duration

	// maxPendingBytes is the per-recipient ceiling passed to every enqueue
	// (AUDIT 5.39). Never zero: the constructor refuses a non-positive value
	// back to DefaultMaxPendingBytes, because zero would refuse all mail and
	// "unset" must not be able to mean either that or no ceiling at all.
	maxPendingBytes int64
}

// MessagesOption configures the handler.
//
// Variadic rather than another parameter, following store.Open: five of the six
// call sites open a relay whose ceiling is the default and should not have to
// name it, and a number repeated at every construction is a number that drifts.
type MessagesOption func(*MessagesHandler)

// WithPendingCeiling overrides the per-recipient pending-byte ceiling.
//
// A non-positive value keeps the default rather than removing the ceiling. That
// direction is deliberate: a quota must never be switched off by a value that
// was not set, which is the state AUDIT 5.39 describes. `config.Load` reports 0
// for an unset RELAY_MAX_PENDING_BYTES and refuses an explicit non-positive one,
// so `main` can pass the configured value unconditionally.
func WithPendingCeiling(n int64) MessagesOption {
	return func(h *MessagesHandler) {
		if n <= 0 {
			return
		}
		h.maxPendingBytes = n
	}
}

// NewMessagesHandler builds the handler.
func NewMessagesHandler(
	db *store.DB,
	authHandler *AuthHandler,
	log *slog.Logger,
	opts ...MessagesOption,
) *MessagesHandler {
	h := &MessagesHandler{
		db:              db,
		auth:            authHandler,
		log:             log,
		ttl:             MessageTTL,
		maxPendingBytes: DefaultMaxPendingBytes,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// Routes registers the endpoints. All require authentication.
func (h *MessagesHandler) Routes(mux *http.ServeMux) {
	mux.Handle("POST /v1/messages", h.auth.Require(http.HandlerFunc(h.send)))
	mux.Handle("GET /v1/messages", h.auth.Require(http.HandlerFunc(h.fetch)))
	mux.Handle("POST /v1/messages/ack", h.auth.Require(http.HandlerFunc(h.acknowledge)))
}

type sendRequest struct {
	Recipient string `json:"recipient"`
	Envelope  string `json:"envelope"`
}

type fetchResponse struct {
	Messages []fetchedMessage `json:"messages"`
	// More reports that the batch was capped, so the client knows to ask again
	// after acknowledging. It is the caller's own queue depth, not anyone else's.
	More bool `json:"more"`
}

type fetchedMessage struct {
	ID       string `json:"id"`
	Envelope string `json:"envelope"`
}

type ackRequest struct {
	IDs []string `json:"ids"`
}

type ackResponse struct {
	Acknowledged int64 `json:"acknowledged"`
}

// send accepts an envelope for a recipient.
//
// # What the relay checks, and what it refuses to
//
// Length, and that the recipient is a well-formed UUID. Nothing else. The
// envelope's wire version, payload type, sender field and timestamp are all in
// those bytes and all readable without any key — and the relay reads none of
// them. That is P4.S07's stated anti-goal ("do not parse into the ciphertext")
// and the reason is not purity: a server that understands the wire format
// acquires opinions about it, every opinion is a coupling that must be revised in
// lockstep with the client, and each one is a place where a hostile operator
// could make a decision about someone's mail.
//
// In particular the relay does **not** check that the envelope's `sender` field
// matches the authenticated account. It looks like a free integrity win and is
// not one: the field is documented as an untrusted routing hint, the client
// attributes messages by which session decrypted them and never by that field,
// and enforcing it here would mean the server both parses the format and appears
// to vouch for a value nothing should trust.
//
// # 202 regardless
//
// A send to an account that does not exist is accepted and dropped. Reporting it
// would be an enumeration oracle — see store.EnqueueMessage for why that matters
// more than the lost debuggability, and why it costs a real client nothing.
//
// **A send to a recipient whose queue is at its ceiling is accepted and dropped
// too** (AUDIT 5.39), through the same path and with the same response, because
// "that account's queue is full" says the account exists and is not collecting
// its mail. The enqueue result is discarded here rather than inspected, so there
// is no branch a later change could accidentally make observable. It is not
// logged either: a line per refused message is a per-message record naming a
// recipient, which is what §7 and TestNoLogLineIsEmittedPerDeliveredMessage
// exist to prevent, and the relay has no metrics endpoint to put a counter on.
// The drop is therefore invisible on both sides, and the only thing standing
// between that and lost mail is a ceiling set high enough that honest traffic
// never reaches it — see DefaultMaxPendingBytes for that argument.
func (h *MessagesHandler) send(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	sender, ok := AccountFrom(ctx)
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized)
		return
	}
	if !h.auth.allow(w, r, "message-send", sender.String(), sendLimit) {
		return
	}

	var req sendRequest
	if err := httpx.DecodeJSON(r.Body, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest)
		return
	}

	recipient, err := uuid.Parse(req.Recipient)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest)
		return
	}

	envelope, err := base64.StdEncoding.DecodeString(req.Envelope)
	if err != nil ||
		len(envelope) < store.MinEnvelopeBytes ||
		len(envelope) > store.MaxEnvelopeBytes {
		httpx.WriteError(w, http.StatusBadRequest)
		return
	}

	if _, err := h.db.EnqueueMessage(ctx, recipient, envelope, h.ttl, h.maxPendingBytes); err != nil {
		h.log.ErrorContext(ctx, "enqueue failed", slog.String("reason", err.Error()))
		httpx.WriteError(w, http.StatusInternalServerError)
		return
	}

	// Neither account is logged, and neither is the envelope. That a message was
	// relayed is the operational fact; who sent it to whom is the record the
	// retention policy exists to not accumulate, and a log line survives every
	// deletion performed on the database.
	w.WriteHeader(http.StatusAccepted)
}

// fetch returns pending envelopes for the caller.
//
// The caller can only ever read its own queue: the recipient is the authenticated
// account and there is no parameter through which to name another. Reading does
// not delete — see store.PendingMessages.
func (h *MessagesHandler) fetch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	aci, ok := AccountFrom(ctx)
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized)
		return
	}
	if !h.auth.allow(w, r, "message-fetch", aci.String(), fetchLimit) {
		return
	}

	// One more than the batch, so a full page can be distinguished from a page
	// that happens to end exactly at the limit without a second query.
	pending, err := h.db.PendingMessages(ctx, aci, maxFetchBatch+1)
	if err != nil {
		h.log.ErrorContext(ctx, "fetch failed", slog.String("reason", err.Error()))
		httpx.WriteError(w, http.StatusInternalServerError)
		return
	}

	more := len(pending) > maxFetchBatch
	if more {
		pending = pending[:maxFetchBatch]
	}

	// Non-nil so an empty queue encodes as [] rather than null. A client that
	// has to handle both is a client that will handle one of them wrongly.
	out := make([]fetchedMessage, 0, len(pending))
	for _, m := range pending {
		out = append(out, fetchedMessage{
			ID:       m.ID.String(),
			Envelope: base64.StdEncoding.EncodeToString(m.Envelope),
		})
	}

	httpx.WriteJSON(w, http.StatusOK, fetchResponse{Messages: out, More: more})
}

// acknowledge deletes messages the client has durably stored.
//
// # This is the highest-value control on the server
//
// docs/THREAT_MODEL.md §3.1: encryption makes a seized database unreadable,
// deletion makes it empty, and only the second is not a bet on the cipher holding
// for as long as the data is retained. The row is removed, not flagged — see
// store.AcknowledgeMessages, and the test that asserts absence rather than
// invisibility.
//
// Acknowledging is scoped to the caller's own queue, and a message that does not
// exist acknowledges successfully: the client is telling the server something it
// already believes, and returning an error for a repeated acknowledgement would
// make a retried request look like a failure.
func (h *MessagesHandler) acknowledge(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	aci, ok := AccountFrom(ctx)
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized)
		return
	}
	if !h.auth.allow(w, r, "message-ack", aci.String(), ackLimit) {
		return
	}

	var req ackRequest
	if err := httpx.DecodeJSON(r.Body, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest)
		return
	}
	if len(req.IDs) > maxAckBatch {
		httpx.WriteError(w, http.StatusBadRequest)
		return
	}

	ids := make([]uuid.UUID, 0, len(req.IDs))
	for _, raw := range req.IDs {
		id, err := uuid.Parse(raw)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest)
			return
		}
		ids = append(ids, id)
	}

	deleted, err := h.db.AcknowledgeMessages(ctx, aci, ids)
	if err != nil {
		h.log.ErrorContext(ctx, "acknowledge failed", slog.String("reason", err.Error()))
		httpx.WriteError(w, http.StatusInternalServerError)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, ackResponse{Acknowledged: deleted})
}
