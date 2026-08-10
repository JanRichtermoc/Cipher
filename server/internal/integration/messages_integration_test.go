//go:build integration

// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
//
// P4.S07's "Done when": a relay round trip.
// P4.S08's "Done when": after acknowledgement the row is **gone, not flagged**,
// and the TTL sweep removes stale undelivered rows.
//
// The second assertion is the one that needs a real database. "The message no
// longer comes back from the API" is satisfied by a `delivered` boolean, by a
// filtered read, and by actual deletion — three designs with completely different
// properties under docs/THREAT_MODEL.md §1.1, where the adversary reads the disk
// rather than the API. Only a query that looks for the row can tell them apart.

package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"cipher.relay/internal/api"
	"cipher.relay/internal/logging"
	"cipher.relay/internal/store"
	"cipher.relay/internal/sweep"
)

func relayStack(t *testing.T) (http.Handler, *store.DB) {
	t.Helper()
	return relayStackWithCeiling(t, api.DefaultMaxPendingBytes)
}

// relayStackWithCeiling is relayStack with an explicit per-recipient
// pending-byte ceiling (AUDIT 5.39).
//
// It exists because the production ceiling is 32 MiB and a test that reached it
// honestly would write 32 MiB per run and pin the number rather than the
// mechanism. A configurable ceiling is what makes the quota observable at all —
// AUDIT 5.22's "an unmeasurable quota is the same as no quota" is the sentence
// 5.39's row quotes about itself.
func relayStackWithCeiling(t *testing.T, maxPendingBytes int64) (http.Handler, *store.DB) {
	t.Helper()
	db := testDB(t)
	limiter := testLimiter(t)
	log := logging.New(io.Discard, slog.LevelError)

	authHandler := api.NewAuthHandler(db, limiter, log)
	mux := http.NewServeMux()
	authHandler.Routes(mux)
	api.NewInviteHandler(db, limiter, authHandler, log).Routes(mux)
	api.NewKeysHandler(db, authHandler, log).Routes(mux)
	api.NewMessagesHandler(db, authHandler, log,
		api.WithPendingCeiling(maxPendingBytes)).Routes(mux)
	return mux, db
}

// envelope builds bytes that are a plausible wire-format v1 envelope.
//
// Only the length matters to the relay, which is the property under test — but
// the shape is realistic so a future change that starts parsing has something to
// parse, and fails a test rather than passing against nonsense.
func envelope(n int, fill byte) []byte {
	if n < store.MinEnvelopeBytes {
		n = store.MinEnvelopeBytes
	}
	b := make([]byte, n)
	b[0] = 0x01 // wireVersion
	b[1] = 0x02 // whisper
	for i := 31; i < n; i++ {
		b[i] = fill
	}
	return b
}

func sendBody(recipient uuid.UUID, env []byte) io.Reader {
	raw, _ := json.Marshal(map[string]string{
		"recipient": recipient.String(),
		"envelope":  base64.StdEncoding.EncodeToString(env),
	})
	return strings.NewReader(string(raw))
}

func ackBody(ids ...string) io.Reader {
	raw, _ := json.Marshal(map[string]any{"ids": ids})
	return strings.NewReader(string(raw))
}

func fetchMessages(t *testing.T, h http.Handler, token, from string) ([]fetchedMsg, bool) {
	t.Helper()
	rec := do(h, http.MethodGet, "/v1/messages", token, from, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("fetch: status %d: %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Messages []fetchedMsg `json:"messages"`
		More     bool         `json:"more"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return got.Messages, got.More
}

type fetchedMsg struct {
	ID       string `json:"id"`
	Envelope string `json:"envelope"`
}

// --- P4.S07: the round trip ------------------------------------------------

func TestRelayRoundTrip(t *testing.T) {
	h, db := relayStack(t)
	alice, aliceToken := enrol(t, h, db, "198.51.100.90")
	bob, bobToken := enrol(t, h, db, "198.51.100.91")
	_ = alice

	payload := envelope(200, 0x7F)
	if rec := do(h, http.MethodPost, "/v1/messages", aliceToken, "198.51.100.90",
		sendBody(bob, payload)); rec.Code != http.StatusAccepted {
		t.Fatalf("send: status %d: %s", rec.Code, rec.Body.String())
	}

	msgs, more := fetchMessages(t, h, bobToken, "198.51.100.91")
	if len(msgs) != 1 {
		t.Fatalf("bob has %d messages, want 1", len(msgs))
	}
	if more {
		t.Error("More is set for a single message")
	}

	got, err := base64.StdEncoding.DecodeString(msgs[0].Envelope)
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	// Byte-identical. The relay stores and returns opaque bytes; any difference
	// means something in the path is interpreting them.
	if string(got) != string(payload) {
		t.Fatal("the relayed envelope differs from the one sent")
	}
}

func TestTheRelayDoesNotInspectTheEnvelope(t *testing.T) {
	// P4.S07's anti-goal: do not parse into the ciphertext. These envelopes are
	// the right length and otherwise meaningless — an unknown wire version, a
	// reserved payload type, and a type the client explicitly refuses. All must
	// relay unchanged: rejecting them would mean the server understands the
	// format, and understanding it is a coupling that has to be revised in
	// lockstep with the client.
	h, db := relayStack(t)
	_, aliceToken := enrol(t, h, db, "198.51.100.92")
	bob, bobToken := enrol(t, h, db, "198.51.100.93")

	var sent [][]byte
	for _, hdr := range [][2]byte{
		{0xFF, 0x02}, // wire version the client would reject
		{0x01, 0x03}, // reserved plaintext type, deliberately not live
		{0x01, 0x07}, // sender-key: groups, which the client refuses outright
		{0x00, 0x00}, // nonsense
	} {
		e := envelope(64, 0x11)
		e[0], e[1] = hdr[0], hdr[1]
		sent = append(sent, e)
		if rec := do(h, http.MethodPost, "/v1/messages", aliceToken, "198.51.100.92",
			sendBody(bob, e)); rec.Code != http.StatusAccepted {
			t.Fatalf("the relay rejected envelope %v: status %d", hdr, rec.Code)
		}
	}

	msgs, _ := fetchMessages(t, h, bobToken, "198.51.100.93")
	if len(msgs) != len(sent) {
		t.Fatalf("relayed %d of %d envelopes", len(msgs), len(sent))
	}
}

func TestEnvelopeSizeIsEnforcedAtBothEnds(t *testing.T) {
	// The bounds come from Envelope.swift: headerSize 31 plus 1..65536 of
	// ciphertext. They are the only thing the relay knows about the format, and
	// the cap is what stops a caller inducing a huge allocation.
	h, db := relayStack(t)
	_, token := enrol(t, h, db, "198.51.100.94")
	bob, _ := enrol(t, h, db, "198.51.100.95")

	cases := map[string]int{
		"one byte under the minimum": store.MinEnvelopeBytes - 1,
		"empty":                      0,
		"one byte over the maximum":  store.MaxEnvelopeBytes + 1,
	}
	for name, size := range cases {
		body := make([]byte, size)
		raw, _ := json.Marshal(map[string]string{
			"recipient": bob.String(),
			"envelope":  base64.StdEncoding.EncodeToString(body),
		})
		rec := do(h, http.MethodPost, "/v1/messages", token, "198.51.100.94",
			strings.NewReader(string(raw)))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s (%d bytes): status %d, want 400", name, size, rec.Code)
		}
	}

	// And the boundaries themselves are accepted, so the check is a bound rather
	// than an off-by-one that quietly rejects the largest legal message.
	for name, size := range map[string]int{
		"exactly the minimum": store.MinEnvelopeBytes,
		"exactly the maximum": store.MaxEnvelopeBytes,
	} {
		rec := do(h, http.MethodPost, "/v1/messages", token, "198.51.100.94",
			sendBody(bob, envelope(size, 0x22)))
		if rec.Code != http.StatusAccepted {
			t.Errorf("%s (%d bytes): status %d, want 202", name, size, rec.Code)
		}
	}
}

func TestSendingToAStrangerIsAcceptedAndDropped(t *testing.T) {
	// Reporting "no such account" would be an enumeration oracle, and a cleaner
	// one than the prekey directory, which answers identically for unknown,
	// never-published and drained accounts precisely so membership cannot be
	// probed. A real sender never addresses a stranger: an aci is only obtainable
	// by fetching a bundle.
	ctx := context.Background()
	h, db := relayStack(t)
	_, token := enrol(t, h, db, "198.51.100.96")
	bob, _ := enrol(t, h, db, "198.51.100.97")

	stranger := uuid.New()
	real := do(h, http.MethodPost, "/v1/messages", token, "198.51.100.96",
		sendBody(bob, envelope(64, 0x33)))
	ghost := do(h, http.MethodPost, "/v1/messages", token, "198.51.100.96",
		sendBody(stranger, envelope(64, 0x33)))

	if ghost.Code != real.Code ||
		strings.TrimSpace(ghost.Body.String()) != strings.TrimSpace(real.Body.String()) {
		t.Fatalf("a stranger is distinguishable from a member:\n  member:   %d %q\n  stranger: %d %q",
			real.Code, real.Body.String(), ghost.Code, ghost.Body.String())
	}

	// Dropped, not stored: no row may accumulate for an account that cannot
	// collect it.
	n, err := db.CountPendingMessages(ctx, stranger)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("%d messages were stored for a nonexistent account", n)
	}
}

// --- AUDIT 5.39: the per-recipient pending-byte ceiling ---------------------
//
// A ceiling small enough to reach in a handful of sends, and envelopes that
// divide into it exactly, so the boundary is asserted rather than approached:
// four 1024-byte envelopes are the ceiling, to the byte.
const (
	quotaCeiling     int64 = 4096
	quotaEnvelopeLen       = 1024
)

func TestAPendingQueueStopsGrowingAtItsCeiling(t *testing.T) {
	// The control itself. Before this, `messages` was the one authenticated
	// growth path with no quota at all: 60 sends a minute at 65567 bytes is
	// ≈5.3 GiB a day per sending account, retained for the 30-day TTL, and a full
	// disk is what stops the retention sweep.
	//
	// Both sides of the boundary are asserted. The message that lands exactly on
	// the ceiling must be *stored* — a `<` where `<=` belongs would silently cost
	// one message per queue — and the one after it must not be.
	ctx := context.Background()
	h, db := relayStackWithCeiling(t, quotaCeiling)
	_, token := enrol(t, h, db, "198.51.100.190")
	bob, _ := enrol(t, h, db, "198.51.100.191")

	for i := range 4 {
		rec := do(h, http.MethodPost, "/v1/messages", token, "198.51.100.190",
			sendBody(bob, envelope(quotaEnvelopeLen, 0xA1)))
		if rec.Code != http.StatusAccepted {
			t.Fatalf("send %d: status %d: %s", i, rec.Code, rec.Body.String())
		}
	}

	pending, err := db.PendingBytes(ctx, bob)
	if err != nil {
		t.Fatalf("pending bytes: %v", err)
	}
	if pending != quotaCeiling {
		t.Fatalf("%d bytes pending after filling the queue exactly, want %d — "+
			"the message that lands on the ceiling was refused", pending, quotaCeiling)
	}

	// One more, of the smallest legal size, so the refusal cannot be blamed on
	// the envelope rather than on the queue.
	rec := do(h, http.MethodPost, "/v1/messages", token, "198.51.100.190",
		sendBody(bob, envelope(store.MinEnvelopeBytes, 0xA2)))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("the refused send answered %d; it must answer exactly as an "+
			"accepted one does (AUDIT 5.39)", rec.Code)
	}

	pending, err = db.PendingBytes(ctx, bob)
	if err != nil {
		t.Fatalf("pending bytes: %v", err)
	}
	if pending != quotaCeiling {
		t.Fatalf("the queue grew to %d bytes past a ceiling of %d — it is unbounded",
			pending, quotaCeiling)
	}
	n, err := db.CountPendingMessages(ctx, bob)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 4 {
		t.Fatalf("%d rows are queued, want 4: a row was stored over the ceiling", n)
	}
}

func TestAQueueAtItsCeilingIsIndistinguishableFromAnEmptyOne(t *testing.T) {
	// The reason the drop is silent. "That account's queue is full" says the
	// account exists and is not collecting its mail — a better oracle about a
	// recipient than the one the accepted-and-dropped stranger path exists to
	// avoid, and reachable by any authenticated member.
	//
	// Byte-for-byte on status and body, like TestSendingToAStrangerIsAccepted-
	// AndDropped, because a difference in either is the whole leak.
	ctx := context.Background()
	h, db := relayStackWithCeiling(t, quotaCeiling)
	_, token := enrol(t, h, db, "198.51.100.192")
	full, _ := enrol(t, h, db, "198.51.100.193")
	empty, _ := enrol(t, h, db, "198.51.100.194")

	for range 4 {
		if rec := do(h, http.MethodPost, "/v1/messages", token, "198.51.100.192",
			sendBody(full, envelope(quotaEnvelopeLen, 0xB1))); rec.Code != http.StatusAccepted {
			t.Fatalf("filling the queue: status %d", rec.Code)
		}
	}

	refused := do(h, http.MethodPost, "/v1/messages", token, "198.51.100.192",
		sendBody(full, envelope(quotaEnvelopeLen, 0xB2)))
	accepted := do(h, http.MethodPost, "/v1/messages", token, "198.51.100.192",
		sendBody(empty, envelope(quotaEnvelopeLen, 0xB2)))

	if refused.Code != accepted.Code ||
		strings.TrimSpace(refused.Body.String()) != strings.TrimSpace(accepted.Body.String()) {
		t.Fatalf("a full queue is distinguishable from an empty one:\n  empty: %d %q\n  full:  %d %q",
			accepted.Code, accepted.Body.String(), refused.Code, refused.Body.String())
	}

	// And the premise the comparison rests on: one was stored and one was not, so
	// the two responses really did describe different outcomes.
	stored, err := db.PendingBytes(ctx, empty)
	if err != nil {
		t.Fatalf("pending bytes: %v", err)
	}
	if stored != quotaEnvelopeLen {
		t.Fatalf("the accepted send stored %d bytes, want %d", stored, quotaEnvelopeLen)
	}
	dropped, err := db.PendingBytes(ctx, full)
	if err != nil {
		t.Fatalf("pending bytes: %v", err)
	}
	if dropped != quotaCeiling {
		t.Fatalf("the full queue holds %d bytes, want exactly the ceiling %d — the "+
			"send that should have been dropped was not", dropped, quotaCeiling)
	}
}

func TestAcknowledgingMakesRoomUnderTheCeiling(t *testing.T) {
	// The ceiling is a live measurement of what is waiting, not a counter that
	// only goes up. A quota implemented as an ever-increasing tally would pass
	// the two tests above and permanently brick a queue that had once been busy.
	ctx := context.Background()
	h, db := relayStackWithCeiling(t, quotaCeiling)
	_, token := enrol(t, h, db, "198.51.100.195")
	bob, bobToken := enrol(t, h, db, "198.51.100.196")

	for range 4 {
		if rec := do(h, http.MethodPost, "/v1/messages", token, "198.51.100.195",
			sendBody(bob, envelope(quotaEnvelopeLen, 0xC1))); rec.Code != http.StatusAccepted {
			t.Fatalf("filling the queue: status %d", rec.Code)
		}
	}

	msgs, _ := fetchMessages(t, h, bobToken, "198.51.100.196")
	if len(msgs) != 4 {
		t.Fatalf("setup: %d messages", len(msgs))
	}
	if rec := do(h, http.MethodPost, "/v1/messages/ack", bobToken, "198.51.100.196",
		ackBody(msgs[0].ID)); rec.Code != http.StatusOK {
		t.Fatalf("ack: %d", rec.Code)
	}

	if rec := do(h, http.MethodPost, "/v1/messages", token, "198.51.100.195",
		sendBody(bob, envelope(quotaEnvelopeLen, 0xC2))); rec.Code != http.StatusAccepted {
		t.Fatalf("send after ack: status %d", rec.Code)
	}
	pending, err := db.PendingBytes(ctx, bob)
	if err != nil {
		t.Fatalf("pending bytes: %v", err)
	}
	if pending != quotaCeiling {
		t.Fatalf("%d bytes pending after acknowledging one and sending one, want %d — "+
			"collecting mail did not free the allowance", pending, quotaCeiling)
	}
}

func TestAnExpiredButUnsweptMessageStillCountsAgainstTheCeiling(t *testing.T) {
	// The decision, pinned so it is a choice rather than an accident of the
	// query. The ceiling protects disk; a lapsed row is on the disk until the
	// hourly sweep reaches it, so it is charged for. Excluding it would let a
	// queue hold up to a sweep interval of storage the quota could not see, which
	// is the shape AUDIT 5.22 records.
	//
	// The recipient sees no difference either way: every read path already
	// filters on expiry, which is what the second half asserts is *not* what the
	// ceiling is reading.
	ctx := context.Background()
	h, db := relayStackWithCeiling(t, quotaCeiling)
	_, token := enrol(t, h, db, "198.51.100.197")
	bob, bobToken := enrol(t, h, db, "198.51.100.198")

	for range 4 {
		if rec := do(h, http.MethodPost, "/v1/messages", token, "198.51.100.197",
			sendBody(bob, envelope(quotaEnvelopeLen, 0xD1))); rec.Code != http.StatusAccepted {
			t.Fatalf("filling the queue: status %d", rec.Code)
		}
	}
	msgs, _ := fetchMessages(t, h, bobToken, "198.51.100.198")
	if len(msgs) != 4 {
		t.Fatalf("setup: %d messages", len(msgs))
	}
	if err := db.ExpireMessageNow(ctx, uuid.MustParse(msgs[0].ID)); err != nil {
		t.Fatalf("expire: %v", err)
	}

	// Invisible to the recipient, and still charged for.
	if after, _ := fetchMessages(t, h, bobToken, "198.51.100.198"); len(after) != 3 {
		t.Fatalf("the expired message is still served: %d visible", len(after))
	}
	if rec := do(h, http.MethodPost, "/v1/messages", token, "198.51.100.197",
		sendBody(bob, envelope(quotaEnvelopeLen, 0xD2))); rec.Code != http.StatusAccepted {
		t.Fatalf("the send over the ceiling answered %d, not the 202 an accepted "+
			"one answers", rec.Code)
	}
	pending, err := db.PendingBytes(ctx, bob)
	if err != nil {
		t.Fatalf("pending bytes: %v", err)
	}
	if pending != quotaCeiling {
		t.Fatalf("%d bytes pending: an expired row stopped counting before the sweep "+
			"removed it, so the quota is under-measuring the disk", pending)
	}

	// And the sweep is what actually returns the allowance.
	if _, err := db.DeleteExpiredMessages(ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if rec := do(h, http.MethodPost, "/v1/messages", token, "198.51.100.197",
		sendBody(bob, envelope(quotaEnvelopeLen, 0xD3))); rec.Code != http.StatusAccepted {
		t.Fatalf("send after sweep: status %d", rec.Code)
	}
	pending, err = db.PendingBytes(ctx, bob)
	if err != nil {
		t.Fatalf("pending bytes: %v", err)
	}
	if pending != quotaCeiling {
		t.Fatalf("%d bytes pending after the sweep freed a slot, want %d", pending, quotaCeiling)
	}
}

// --- P4.S08: gone, not flagged ---------------------------------------------

func TestAcknowledgementDeletesTheRow(t *testing.T) {
	// The assertion that separates deletion from a `delivered` flag. Checking
	// only that the message stops coming back would pass against a design that
	// retains every message forever.
	ctx := context.Background()
	h, db := relayStack(t)
	_, aliceToken := enrol(t, h, db, "198.51.100.98")
	bob, bobToken := enrol(t, h, db, "198.51.100.99")

	if rec := do(h, http.MethodPost, "/v1/messages", aliceToken, "198.51.100.98",
		sendBody(bob, envelope(64, 0x44))); rec.Code != http.StatusAccepted {
		t.Fatalf("send: %d", rec.Code)
	}

	msgs, _ := fetchMessages(t, h, bobToken, "198.51.100.99")
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1", len(msgs))
	}
	id := uuid.MustParse(msgs[0].ID)

	present, err := db.MessageExists(ctx, id)
	if err != nil {
		t.Fatalf("exists: %v", err)
	}
	if !present {
		t.Fatal("the message is not in the database before acknowledgement")
	}

	rec := do(h, http.MethodPost, "/v1/messages/ack", bobToken, "198.51.100.99",
		ackBody(msgs[0].ID))
	if rec.Code != http.StatusOK {
		t.Fatalf("ack: status %d: %s", rec.Code, rec.Body.String())
	}

	// **Gone from the table**, not merely absent from the API.
	present, err = db.MessageExists(ctx, id)
	if err != nil {
		t.Fatalf("exists: %v", err)
	}
	if present {
		t.Fatal("the row survived acknowledgement — it was flagged, not deleted " +
			"(THREAT_MODEL.md §3.1)")
	}
}

func TestFetchingDoesNotDelete(t *testing.T) {
	// Delete-on-read looks simpler and loses mail: a response lost in transit
	// would destroy the message, with the client holding no copy and the server
	// no row.
	ctx := context.Background()
	h, db := relayStack(t)
	_, aliceToken := enrol(t, h, db, "198.51.100.100")
	bob, bobToken := enrol(t, h, db, "198.51.100.101")

	do(h, http.MethodPost, "/v1/messages", aliceToken, "198.51.100.100",
		sendBody(bob, envelope(64, 0x55)))

	first, _ := fetchMessages(t, h, bobToken, "198.51.100.101")
	second, _ := fetchMessages(t, h, bobToken, "198.51.100.101")

	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("fetch is destructive: first %d, second %d", len(first), len(second))
	}
	if first[0].ID != second[0].ID {
		t.Fatal("two fetches returned different messages")
	}

	n, err := db.CountPendingMessages(ctx, bob)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("%d messages pending after two fetches, want 1", n)
	}
}

func TestAcknowledgementIsScopedToTheCaller(t *testing.T) {
	// Without `AND recipient_aci = $2` this is a silent, unattributable
	// message-loss primitive: any account could delete any other's undelivered
	// mail given an id, and ids travel in fetch responses.
	ctx := context.Background()
	h, db := relayStack(t)
	_, aliceToken := enrol(t, h, db, "198.51.100.102")
	bob, bobToken := enrol(t, h, db, "198.51.100.103")
	_, mallory := enrol(t, h, db, "198.51.100.104")

	do(h, http.MethodPost, "/v1/messages", aliceToken, "198.51.100.102",
		sendBody(bob, envelope(64, 0x66)))
	msgs, _ := fetchMessages(t, h, bobToken, "198.51.100.103")
	if len(msgs) != 1 {
		t.Fatalf("setup: %d messages", len(msgs))
	}

	// Mallory knows the id and acknowledges it.
	rec := do(h, http.MethodPost, "/v1/messages/ack", mallory, "198.51.100.104",
		ackBody(msgs[0].ID))
	if rec.Code != http.StatusOK {
		t.Fatalf("ack: %d", rec.Code)
	}
	var got struct {
		Acknowledged int64 `json:"acknowledged"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Acknowledged != 0 {
		t.Fatalf("mallory acknowledged %d of bob's messages", got.Acknowledged)
	}

	present, err := db.MessageExists(ctx, uuid.MustParse(msgs[0].ID))
	if err != nil {
		t.Fatalf("exists: %v", err)
	}
	if !present {
		t.Fatal("another account deleted bob's message")
	}
}

func TestAcknowledgingTwiceSucceeds(t *testing.T) {
	// A retried acknowledgement must not look like a failure. The client is
	// telling the server something it already believes.
	h, db := relayStack(t)
	_, aliceToken := enrol(t, h, db, "198.51.100.105")
	bob, bobToken := enrol(t, h, db, "198.51.100.106")

	do(h, http.MethodPost, "/v1/messages", aliceToken, "198.51.100.105",
		sendBody(bob, envelope(64, 0x77)))
	msgs, _ := fetchMessages(t, h, bobToken, "198.51.100.106")

	for i := range 2 {
		rec := do(h, http.MethodPost, "/v1/messages/ack", bobToken, "198.51.100.106",
			ackBody(msgs[0].ID))
		if rec.Code != http.StatusOK {
			t.Fatalf("ack %d: status %d", i, rec.Code)
		}
	}
}

func TestAcknowledgingAnUnknownIDSucceeds(t *testing.T) {
	h, db := relayStack(t)
	_, token := enrol(t, h, db, "198.51.100.107")

	rec := do(h, http.MethodPost, "/v1/messages/ack", token, "198.51.100.107",
		ackBody(uuid.NewString()))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
}

func TestThereIsNoArchiveTable(t *testing.T) {
	// P4.S08's anti-goal is "add a just-in-case archive". Asserted against
	// information_schema rather than the migration file, so a table created by a
	// later migration — or by hand on a running deployment — is caught too.
	ctx := context.Background()
	_, db := relayStack(t)

	tables, err := db.TableNames(ctx)
	if err != nil {
		t.Fatalf("tables: %v", err)
	}
	for _, name := range tables {
		lower := strings.ToLower(name)
		for _, forbidden := range []string{"archive", "history", "audit", "backup", "deleted", "log"} {
			if strings.Contains(lower, forbidden) {
				t.Errorf("table %q looks like a retention channel (matches %q) — "+
					"delivered means deleted (THREAT_MODEL.md §3.1)", name, forbidden)
			}
		}
	}
}

// --- P4.S08: the TTL sweep -------------------------------------------------

func TestSweepRemovesExpiredMessages(t *testing.T) {
	ctx := context.Background()
	h, db := relayStack(t)
	_, aliceToken := enrol(t, h, db, "198.51.100.108")
	bob, bobToken := enrol(t, h, db, "198.51.100.109")

	// Two messages; one is aged past its TTL.
	for range 2 {
		do(h, http.MethodPost, "/v1/messages", aliceToken, "198.51.100.108",
			sendBody(bob, envelope(64, 0x88)))
	}
	msgs, _ := fetchMessages(t, h, bobToken, "198.51.100.109")
	if len(msgs) != 2 {
		t.Fatalf("setup: %d messages", len(msgs))
	}
	stale := uuid.MustParse(msgs[0].ID)
	live := uuid.MustParse(msgs[1].ID)
	if err := db.ExpireMessageNow(ctx, stale); err != nil {
		t.Fatalf("expire: %v", err)
	}

	if _, err := db.DeleteExpiredMessages(ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	present, err := db.MessageExists(ctx, stale)
	if err != nil {
		t.Fatalf("exists: %v", err)
	}
	if present {
		t.Fatal("the expired message survived the sweep")
	}
	// The live one must not go. A sweep that deletes everything passes a naive
	// "the stale one is gone" assertion while destroying the service.
	present, err = db.MessageExists(ctx, live)
	if err != nil {
		t.Fatalf("exists: %v", err)
	}
	if !present {
		t.Fatal("the sweep deleted a live message")
	}
}

func TestAnExpiredMessageIsNotServedEvenBeforeTheSweep(t *testing.T) {
	// Expiry is enforced on read as well as by the sweep. Relying on the sweep
	// alone would serve lapsed mail for up to one sweep interval.
	ctx := context.Background()
	h, db := relayStack(t)
	_, aliceToken := enrol(t, h, db, "198.51.100.110")
	bob, bobToken := enrol(t, h, db, "198.51.100.111")

	do(h, http.MethodPost, "/v1/messages", aliceToken, "198.51.100.110",
		sendBody(bob, envelope(64, 0x99)))
	msgs, _ := fetchMessages(t, h, bobToken, "198.51.100.111")
	if err := db.ExpireMessageNow(ctx, uuid.MustParse(msgs[0].ID)); err != nil {
		t.Fatalf("expire: %v", err)
	}

	after, _ := fetchMessages(t, h, bobToken, "198.51.100.111")
	if len(after) != 0 {
		t.Fatalf("an expired message was served: %d", len(after))
	}
}

func TestSweeperRunsOnItsOwn(t *testing.T) {
	// The goroutine, not just the query. A sweep function nobody calls is a
	// retention policy nobody enforces — and it sweeps once immediately rather
	// than waiting out the first interval, because a relay returning from an
	// outage is holding the rows it should least like to keep.
	ctx := context.Background()
	h, db := relayStack(t)
	_, aliceToken := enrol(t, h, db, "198.51.100.112")
	bob, bobToken := enrol(t, h, db, "198.51.100.113")

	do(h, http.MethodPost, "/v1/messages", aliceToken, "198.51.100.112",
		sendBody(bob, envelope(64, 0xAB)))
	msgs, _ := fetchMessages(t, h, bobToken, "198.51.100.113")
	stale := uuid.MustParse(msgs[0].ID)
	if err := db.ExpireMessageNow(ctx, stale); err != nil {
		t.Fatalf("expire: %v", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	go sweep.New(db, nil, logging.New(io.Discard, slog.LevelError), time.Hour).Run(runCtx)
	defer cancel()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		present, err := db.MessageExists(ctx, stale)
		if err != nil {
			t.Fatalf("exists: %v", err)
		}
		if !present {
			return // swept
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the sweeper did not remove an expired message within 5s of starting")
}

// --- Authentication and isolation ------------------------------------------

func TestMessageRoutesRequireAuthentication(t *testing.T) {
	h, db := relayStack(t)
	bob, _ := enrol(t, h, db, "198.51.100.114")

	for name, code := range map[string]int{
		"send":  do(h, http.MethodPost, "/v1/messages", "", "198.51.100.115", sendBody(bob, envelope(64, 1))).Code,
		"fetch": do(h, http.MethodGet, "/v1/messages", "", "198.51.100.115", nil).Code,
		"ack":   do(h, http.MethodPost, "/v1/messages/ack", "", "198.51.100.115", ackBody(uuid.NewString())).Code,
	} {
		if code != http.StatusUnauthorized {
			t.Errorf("unauthenticated %s: status %d, want 401", name, code)
		}
	}
}

func TestAnAccountOnlyEverReadsItsOwnQueue(t *testing.T) {
	// There is no parameter through which to name another recipient, which is
	// the point; this checks the queues are actually separate.
	h, db := relayStack(t)
	_, aliceToken := enrol(t, h, db, "198.51.100.116")
	bob, bobToken := enrol(t, h, db, "198.51.100.117")
	_, malloryToken := enrol(t, h, db, "198.51.100.118")

	do(h, http.MethodPost, "/v1/messages", aliceToken, "198.51.100.116",
		sendBody(bob, envelope(64, 0xCD)))

	if msgs, _ := fetchMessages(t, h, malloryToken, "198.51.100.118"); len(msgs) != 0 {
		t.Fatalf("mallory sees %d of bob's messages", len(msgs))
	}
	if msgs, _ := fetchMessages(t, h, bobToken, "198.51.100.117"); len(msgs) != 1 {
		t.Fatalf("bob sees %d of his own messages, want 1", len(msgs))
	}
}

func TestFetchIsBatchedAndReportsMore(t *testing.T) {
	// An account returning after a long absence must not receive its entire
	// queue in one body.
	ctx := context.Background()
	h, db := relayStack(t)
	bob, bobToken := enrol(t, h, db, "198.51.100.120")

	// Enqueued through the store, not the endpoint. 105 sends would hit the
	// 60/minute limit — correctly, as TestSendIsRateLimited asserts — and what
	// is under test here is batching, not the send path. The first version of
	// this test went through HTTP and failed on a 429, which was the rate limit
	// being right about something the fixture had not accounted for.
	const sent = 105
	for range sent {
		stored, err := db.EnqueueMessage(ctx, bob, envelope(64, 0xEF),
			api.MessageTTL, api.DefaultMaxPendingBytes)
		if err != nil || !stored {
			t.Fatalf("enqueue: stored=%v err=%v", stored, err)
		}
	}

	msgs, more := fetchMessages(t, h, bobToken, "198.51.100.120")
	if len(msgs) != 100 {
		t.Fatalf("first batch has %d messages, want 100", len(msgs))
	}
	if !more {
		t.Fatal("More is not set with 5 messages still queued")
	}

	ids := make([]string, 0, len(msgs))
	for _, m := range msgs {
		ids = append(ids, m.ID)
	}
	if rec := do(h, http.MethodPost, "/v1/messages/ack", bobToken, "198.51.100.120",
		ackBody(ids...)); rec.Code != http.StatusOK {
		t.Fatalf("ack: %d", rec.Code)
	}

	rest, more := fetchMessages(t, h, bobToken, "198.51.100.120")
	if len(rest) != sent-100 {
		t.Fatalf("second batch has %d messages, want %d", len(rest), sent-100)
	}
	if more {
		t.Error("More is set with an empty queue behind it")
	}
}

func TestSendIsRateLimited(t *testing.T) {
	h, db := relayStack(t)
	_, token := enrol(t, h, db, "198.51.100.121")
	bob, _ := enrol(t, h, db, "198.51.100.122")

	var throttled bool
	for i := range 80 {
		rec := do(h, http.MethodPost, "/v1/messages", token, "198.51.100.121",
			sendBody(bob, envelope(64, 0x01)))
		if rec.Code == http.StatusTooManyRequests {
			throttled = true
			if i < 60 {
				t.Errorf("throttled after %d sends; capacity is 60", i)
			}
			break
		}
		if rec.Code != http.StatusAccepted {
			t.Fatalf("send %d: status %d", i, rec.Code)
		}
	}
	if !throttled {
		t.Fatal("sending was never throttled")
	}
}

func TestMalformedRequestsAreRefused(t *testing.T) {
	h, db := relayStack(t)
	_, token := enrol(t, h, db, "198.51.100.123")
	bob, _ := enrol(t, h, db, "198.51.100.124")

	send := map[string]io.Reader{
		"not json":           strings.NewReader("{"),
		"unknown field":      strings.NewReader(`{"recipientAci":"x","envelope":"y"}`),
		"recipient not uuid": strings.NewReader(`{"recipient":"nope","envelope":"AAAA"}`),
		"envelope not base64": strings.NewReader(
			`{"recipient":"` + bob.String() + `","envelope":"!!!!"}`),
	}
	for name, body := range send {
		if rec := do(h, http.MethodPost, "/v1/messages", token, "198.51.100.123", body); rec.Code != http.StatusBadRequest {
			t.Errorf("send %s: status %d, want 400", name, rec.Code)
		}
	}

	ack := map[string]io.Reader{
		"not json":      strings.NewReader("{"),
		"unknown field": strings.NewReader(`{"identifiers":[]}`),
		"id not uuid":   strings.NewReader(`{"ids":["nope"]}`),
	}
	for name, body := range ack {
		if rec := do(h, http.MethodPost, "/v1/messages/ack", token, "198.51.100.123", body); rec.Code != http.StatusBadRequest {
			t.Errorf("ack %s: status %d, want 400", name, rec.Code)
		}
	}
}

// --- Acknowledgement limit (AUDIT 5.23) -----------------------------------

func TestAcknowledgeIsRateLimited(t *testing.T) {
	// Acknowledgement had no limit at all. Each call is a `DELETE ... WHERE
	// aci = $1 AND id = ANY($2)` with up to 200 ids, so an authenticated caller
	// could hold a database connection busy indefinitely for free.
	//
	// The ids need not exist: acknowledging something already gone succeeds by
	// design, so an attacker's cheapest version of this attack is exactly the
	// request this test makes.
	h, db := relayStack(t)
	_, token := enrol(t, h, db, "198.51.100.180")

	var refusedAt int
	for i := 1; i <= 130; i++ {
		rec := do(h, http.MethodPost, "/v1/messages/ack", token, "198.51.100.180",
			ackBody(uuid.NewString()))
		if rec.Code == http.StatusTooManyRequests {
			refusedAt = i
			break
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("ack %d: status %d: %s", i, rec.Code, rec.Body.String())
		}
	}
	if refusedAt == 0 {
		t.Fatal("130 acknowledgements were all accepted — the endpoint is unthrottled")
	}
	if refusedAt <= 120 {
		t.Fatalf("refused at %d, before the documented capacity of 120", refusedAt)
	}
}
