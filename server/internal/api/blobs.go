// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"cipher.relay/internal/blob"
	"cipher.relay/internal/httpx"
	"cipher.relay/internal/ratelimit"
	"cipher.relay/internal/store"
)

const (
	// MaxBlobBytes caps one attachment. Photos and short video; anything larger
	// is not a message attachment.
	MaxBlobBytes = 100 << 20 // 100 MiB

	// AttachmentTTL is how long a slot survives unfetched (docs/BACKEND.md §4).
	// Shorter than a message's 30 days: an attachment is useless without the
	// message that carries its key, and that message expires first.
	AttachmentTTL = 7 * 24 * time.Hour

	// BlobPathPrefix is exempted from the global request-body limit in main.
	// Declared here so the exemption and the handler that owns the real limit
	// cannot drift apart.
	BlobPathPrefix = "/v1/blobs"
)

// docs/BACKEND.md §5: 100 uploads and 500 MB per day per account.
//
// The byte quota is charged in whole megabytes so one Redis bucket can express
// it: capacity 500 with a 24-hour window, one token per megabyte.
var (
	blobUploadLimit   = ratelimit.Limit{Capacity: 100, Window: 24 * time.Hour}
	blobBytesLimit    = ratelimit.Limit{Capacity: 500, Window: 24 * time.Hour}
	blobDownloadLimit = ratelimit.Limit{Capacity: 300, Window: time.Hour}
)

// BlobsHandler serves attachment slots.
//
// # The id is the capability
//
// There is no owner and no recipient, in the schema or here. The id is 122 bits
// of randomness delivered to the recipient inside the end-to-end ciphertext, so
// the server never learns who uploaded a blob or who is entitled to read it —
// and therefore never records the edge, which is the point (docs/BACKEND.md
// §2.8).
//
// Anyone holding the id can download the bytes. Those bytes are encrypted with a
// key carried in the same ciphertext, so the capability grants access to a blob
// and not to its contents.
type BlobsHandler struct {
	db    *store.DB
	blobs *blob.Store
	auth  *AuthHandler
	log   *slog.Logger
	ttl   time.Duration
}

// NewBlobsHandler builds the handler.
func NewBlobsHandler(
	db *store.DB,
	blobs *blob.Store,
	authHandler *AuthHandler,
	log *slog.Logger,
) *BlobsHandler {
	return &BlobsHandler{db: db, blobs: blobs, auth: authHandler, log: log, ttl: AttachmentTTL}
}

// Routes registers the endpoints. All require authentication.
//
// Download requires a session even though the id is the capability. That is not
// a second authorisation check — the server still cannot tell who *should* read
// a blob — it is what makes the download rate limit enforceable and keeps the
// store off the open internet. Without it, an id leaked into a log or a proxy
// trace would be fetchable by anyone at any rate.
func (h *BlobsHandler) Routes(mux *http.ServeMux) {
	mux.Handle("POST /v1/blobs", h.auth.Require(http.HandlerFunc(h.upload)))
	mux.Handle("GET /v1/blobs/{id}", h.auth.Require(http.HandlerFunc(h.download)))
	mux.Handle("DELETE /v1/blobs/{id}", h.auth.Require(http.HandlerFunc(h.delete)))
}

type uploadResponse struct {
	ID        string    `json:"id"`
	Size      int64     `json:"size"`
	ExpiresAt time.Time `json:"expires_at"`
}

// upload streams a blob to disk and records the slot.
//
// # Nothing about the content is read, recorded, or trusted
//
// No content type, no filename, no extension, no magic-byte sniffing, no
// scanning of any kind — P4.S09's stated anti-goal is "content scanning
// theatre". The bytes arrive encrypted, so there is nothing to inspect; a server
// that inspected them anyway would be recording a property of data it cannot
// read, and would break the moment the client changed its container format.
//
// # The file is written before the row, and cleaned up if the row fails
//
// The other order orphans bytes: a row pointing at a file that was never written
// is a download that 500s, and it is recoverable. A file with no row is a blob
// nothing remembers, which the sweep will never find, sitting on disk until
// someone notices the directory growing — a retention leak invisible to every
// query.
func (h *BlobsHandler) upload(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	aci, ok := AccountFrom(ctx)
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized)
		return
	}

	if !h.auth.allow(w, r, "blob-upload", aci.String(), blobUploadLimit) {
		return
	}

	id, err := uuid.NewRandom()
	if err != nil {
		h.log.ErrorContext(ctx, "blob id generation failed",
			slog.String("reason", err.Error()))
		httpx.WriteError(w, http.StatusInternalServerError)
		return
	}

	// This route is exempt from the global body limit (see httpx.LimitBody), so
	// the cap is applied here and is the only one. MaxBytesReader rather than a
	// Content-Length check, for the reason that function documents.
	body := http.MaxBytesReader(w, r.Body, MaxBlobBytes+1)

	size, err := h.blobs.Put(id, body, MaxBlobBytes)
	if err != nil {
		if errors.Is(err, blob.ErrTooLarge) {
			httpx.WriteError(w, http.StatusRequestEntityTooLarge)
			return
		}
		h.log.ErrorContext(ctx, "blob write failed", slog.String("reason", err.Error()))
		httpx.WriteError(w, http.StatusInternalServerError)
		return
	}

	// Charge the byte quota after the fact, because the size is not known until
	// the upload finishes and Content-Length is a claim. A single upload can
	// therefore exceed the remaining daily allowance by up to one blob; the next
	// one is refused. Bounding it exactly would mean trusting the declared
	// length, which is the thing MaxBytesReader exists to avoid.
	megabytes := int(size >> 20)
	for range megabytes {
		if _, err := h.auth.limiter.Allow(ctx,
			h.auth.limiter.Subject("blob-bytes", aci.String()), blobBytesLimit); err != nil {
			break
		}
	}

	if err := h.db.CreateAttachment(ctx, id, size, h.ttl); err != nil {
		// Remove the bytes we just wrote. Leaving them would be an orphan no
		// sweep can find.
		if rmErr := h.blobs.Delete(id); rmErr != nil {
			h.log.ErrorContext(ctx, "orphaned blob could not be removed",
				slog.String("reason", rmErr.Error()))
		}
		h.log.ErrorContext(ctx, "attachment record failed",
			slog.String("reason", err.Error()))
		httpx.WriteError(w, http.StatusInternalServerError)
		return
	}

	httpx.WriteJSON(w, http.StatusCreated, uploadResponse{
		ID:        id.String(),
		Size:      size,
		ExpiresAt: time.Now().Add(h.ttl),
	})
}

// download streams a blob back.
//
// # The response describes nothing
//
// `application/octet-stream`, always, and `Content-Disposition: attachment`.
// The server does not know what these bytes are — they are ciphertext — and a
// content type echoed from upload would be an attacker-chosen instruction to
// whatever eventually renders them. `X-Content-Type-Options: nosniff` is already
// set globally, which stops a browser second-guessing that.
func (h *BlobsHandler) download(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	aci, ok := AccountFrom(ctx)
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized)
		return
	}
	if !h.auth.allow(w, r, "blob-download", aci.String(), blobDownloadLimit) {
		return
	}

	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		// 404, not 400: a malformed id and an unknown one must be
		// indistinguishable, or the shape of a valid capability becomes probeable.
		httpx.WriteError(w, http.StatusNotFound)
		return
	}

	// The row is consulted first so an expired slot is refused even before the
	// sweep has removed its bytes. Serving from disk alone would keep lapsed
	// attachments available for up to one sweep interval.
	if _, err := h.db.AttachmentSize(ctx, id); err != nil {
		if errors.Is(err, store.ErrAttachmentNotFound) {
			httpx.WriteError(w, http.StatusNotFound)
			return
		}
		h.log.ErrorContext(ctx, "attachment lookup failed",
			slog.String("reason", err.Error()))
		httpx.WriteError(w, http.StatusInternalServerError)
		return
	}

	f, size, err := h.blobs.Open(id)
	if err != nil {
		if errors.Is(err, blob.ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound)
			return
		}
		h.log.ErrorContext(ctx, "blob read failed", slog.String("reason", err.Error()))
		httpx.WriteError(w, http.StatusInternalServerError)
		return
	}
	defer func() { _ = f.Close() }()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("Content-Disposition", "attachment")
	http.ServeContent(w, r, "", time.Time{}, f)
}

// delete removes a slot and its bytes.
//
// Anyone holding the id may delete it, exactly as anyone holding it may read it —
// the id is the whole capability and the server has no notion of an owner to
// check against. The realistic caller is the recipient shredding an attachment
// once it has been decrypted and stored locally, which is the early end of the
// retention window rather than a change to it.
//
// The row goes first here, unlike upload. If the file removal then fails the
// sweep cannot find it, so it is logged loudly — but a slot whose row is gone is
// already unreachable through the API, whereas removing the file first would
// leave a live row pointing at nothing.
func (h *BlobsHandler) delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if _, ok := AccountFrom(ctx); !ok {
		httpx.WriteError(w, http.StatusUnauthorized)
		return
	}

	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound)
		return
	}

	if _, err := h.db.DeleteAttachment(ctx, id); err != nil {
		h.log.ErrorContext(ctx, "attachment delete failed",
			slog.String("reason", err.Error()))
		httpx.WriteError(w, http.StatusInternalServerError)
		return
	}
	if err := h.blobs.Delete(id); err != nil {
		h.log.ErrorContext(ctx, "blob bytes could not be removed after the row went",
			slog.String("reason", err.Error()))
	}

	// 204 whether or not anything was there. The caller holds the capability, so
	// there is nothing to learn from the distinction, and a retried delete must
	// not look like a failure.
	w.WriteHeader(http.StatusNoContent)
}
