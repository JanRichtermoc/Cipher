//
//  RelayMailbox.swift
//  Cipher
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

/// The store-and-forward mailbox: hand an envelope over, collect what is waiting, and tell the
/// relay what has arrived so it can forget it.
///
/// ## Acknowledgement is the point, not the cleanup
///
/// `THREAT_MODEL.md` §3.1: encryption makes a seized database unreadable, deletion makes it
/// empty, and only the second is not a bet on the cipher holding for as long as the data is
/// retained. `acknowledge` is what turns that policy from a server-side intention into
/// something that actually happens — the relay cannot delete a message until a client says it
/// has it. A client that fetched and never acknowledged would leave ciphertext on the box for
/// the full 30-day TTL.
///
/// The caller's obligation is therefore precise, and `MessageRepository` is where it is
/// discharged: **acknowledge only what is durably stored.**
nonisolated struct RelayMailbox: Sendable {

    private let client: RelayClient

    init(client: RelayClient = RelayClient()) {
        self.client = client
    }

    enum Failure: Error, Equatable {
        case unauthenticated
        case rateLimited
        case unreachable
        case malformedResponse
        /// The relay refused the request as malformed — an envelope outside the accepted size
        /// range, or a recipient that is not a UUID. Not retryable: it will fail identically.
        case rejected
        /// The relay answered, repeatedly, with a server error. Distinct from ``unreachable``
        /// because it is not the network: something is wrong on the box, and reporting "check
        /// your connection" would send the user looking in the wrong place.
        case serverUnavailable
    }

    /// One envelope waiting on the relay.
    struct Pending: Sendable, Equatable {
        /// The relay's id for this queued copy. Opaque, random (`BACKEND.md` §2.7 — a serial
        /// would leak the relay's total message volume), and the only thing `acknowledge`
        /// takes. It is *not* a message identity: the same content resent is a different id.
        let id: UUID
        /// Envelope bytes, still encrypted. Nothing here has looked inside them.
        let envelope: Data
    }

    struct Batch: Sendable, Equatable {
        let messages: [Pending]
        /// The relay capped the batch. Acknowledge what was stored, then ask again.
        let more: Bool
    }

    // MARK: - Sending

    /// Hands `envelope` to the relay for `recipient`.
    ///
    /// ## Never retried, and the reason is not politeness
    ///
    /// A send that times out may already have been accepted. `RelayClient` will not retry a
    /// request marked non-idempotent, so a lost response surfaces to the caller as a failure it
    /// must decide about, rather than becoming a second copy on the relay. That matters more
    /// than the duplicate itself: the peer's ratchet consumes the message key on the first copy,
    /// so the second decrypts to nothing and is dropped — meaning a silent auto-retry would
    /// spend the sender's rate budget to deliver a message the recipient will discard, and would
    /// look to the sender like it worked.
    ///
    /// Retrying is the *user's* action, and it re-encrypts: a fresh envelope, a fresh ratchet
    /// step, and a message the peer can actually read.
    ///
    /// A send to an account that does not exist returns 202 exactly like a real one
    /// (`BACKEND.md` §2.7 — no enumeration oracle). There is deliberately no way to ask the
    /// relay whether a recipient is real.
    func send(envelope: Data, to recipient: UUID, token: String) async throws {
        let body: Data
        do {
            body = try JSONEncoder().encode(
                SendRequest(
                    recipient: recipient.uuidString.lowercased(),
                    envelope: envelope.base64EncodedString()))
        } catch {
            throw Failure.malformedResponse
        }

        let response = try await perform(
            RelayRequest(
                method: "POST", path: "/v1/messages", body: body,
                bearerToken: token, isIdempotent: false))

        switch response.status {
        case 202:
            return
        case 400:
            throw Failure.rejected
        case 401:
            throw Failure.unauthenticated
        case 429:
            throw Failure.rateLimited
        default:
            throw Failure.malformedResponse
        }
    }

    // MARK: - Fetching

    /// Everything waiting for this account.
    ///
    /// Idempotent, and genuinely so: reading does not delete (`BACKEND.md` §2.7), and the
    /// recipient is the authenticated account with no parameter through which to name another.
    /// A repeated fetch returns the same envelopes.
    func fetch(token: String) async throws -> Batch {
        let response = try await perform(
            RelayRequest(
                method: "GET", path: "/v1/messages", body: nil, contentType: nil,
                bearerToken: token, isIdempotent: true,
                maxResponseBytes: Self.maxFetchResponseBytes))

        switch response.status {
        case 200:
            break
        case 401:
            throw Failure.unauthenticated
        case 429:
            throw Failure.rateLimited
        default:
            throw Failure.malformedResponse
        }

        let decoded: FetchResponse
        do {
            decoded = try JSONDecoder().decode(FetchResponse.self, from: response.body)
        } catch {
            throw Failure.malformedResponse
        }

        // The relay caps a batch at `api.maxFetchBatch` and says so in `BACKEND.md` §2.7, so a
        // longer one is not this relay answering. Bounded here rather than trusted because the
        // caller loops on `more` and stores every entry: an unbounded batch is unbounded work
        // and unbounded rows behind the quota that AUDIT 4.14 exists to keep meaningful.
        guard decoded.messages.count <= Self.maxFetchBatch else {
            throw Failure.malformedResponse
        }

        var pending: [Pending] = []
        var seen = Set<UUID>()
        pending.reserveCapacity(decoded.messages.count)
        for message in decoded.messages {
            guard let id = UUID(uuidString: message.id),
                  // Duplicate ids in one batch would be acknowledged once and stored twice —
                  // the same ciphertext decrypting a second time is a replay the ratchet
                  // refuses, but the count returned to the caller would already be wrong, and
                  // a relay repeating an id is not a relay this client should keep parsing.
                  seen.insert(id).inserted,
                  let envelope = Data(base64Encoded: message.envelope),
                  // The relay refuses anything outside `store.MinEnvelopeBytes ...
                  // store.MaxEnvelopeBytes` on the way in, so anything outside it on the way
                  // out did not come through the documented path.
                  envelope.count >= Self.minEnvelopeBytes,
                  envelope.count <= Self.maxEnvelopeBytes
            else {
                // One malformed entry invalidates the batch rather than being skipped. A skip
                // would leave an un-acknowledgeable message on the relay forever *and* hide
                // that the relay is sending something this client does not understand.
                throw Failure.malformedResponse
            }
            pending.append(Pending(id: id, envelope: envelope))
        }

        return Batch(messages: pending, more: decoded.more)
    }

    // MARK: - Acknowledging

    /// Tells the relay these messages have arrived, so it deletes them.
    ///
    /// Idempotent by design on the server: acknowledging something already gone succeeds, so a
    /// retried acknowledgement is not an error (`BACKEND.md` §2.7). That is what makes it safe
    /// for `RelayClient` to retry this one — and it must be retried, because a lost
    /// acknowledgement is ciphertext left on a box that is assumed seizable.
    ///
    /// - Returns: how many rows the relay actually deleted. Fewer than asked for is normal — a
    ///   repeat, or a TTL sweep that got there first.
    @discardableResult
    func acknowledge(ids: [UUID], token: String) async throws -> Int {
        guard !ids.isEmpty else { return 0 }
        // The relay 400s a longer list, and a request that is certain to be refused still
        // spends one of this account's 120/minute acknowledgement tokens (AUDIT 5.23) and
        // leaves the messages unacknowledged on a box assumed seizable. `MessageRepository`
        // chunks by `maxAcknowledgeBatch`; this refuses a caller that forgets to.
        guard ids.count <= Self.maxAcknowledgeBatch else { throw Failure.rejected }

        let body: Data
        do {
            body = try JSONEncoder().encode(
                AckRequest(ids: ids.map { $0.uuidString.lowercased() }))
        } catch {
            throw Failure.malformedResponse
        }

        let response = try await perform(
            RelayRequest(
                method: "POST", path: "/v1/messages/ack", body: body,
                bearerToken: token, isIdempotent: true))

        switch response.status {
        case 200:
            break
        case 400:
            throw Failure.rejected
        case 401:
            throw Failure.unauthenticated
        case 429:
            throw Failure.rateLimited
        default:
            throw Failure.malformedResponse
        }

        let acknowledged: Int
        do {
            acknowledged = try JSONDecoder()
                .decode(AckResponse.self, from: response.body).acknowledged
        } catch {
            throw Failure.malformedResponse
        }

        // Fewer than asked for is normal; more than asked for is not arithmetic this relay can
        // do. Negative is not a count at all. Neither is load-bearing today — the caller
        // discards the number — which is exactly why it is bounded here: an unchecked value
        // that nobody reads is the one that becomes a loop bound in a later step.
        guard acknowledged >= 0, acknowledged <= ids.count else {
            throw Failure.malformedResponse
        }
        return acknowledged
    }

    // MARK: - The relay's limits, mirrored

    // These four are the relay's, not ours: `api.maxFetchBatch`, `api.maxAckBatch`,
    // `store.MinEnvelopeBytes` and `store.MaxEnvelopeBytes`. They are copied here because the
    // client must bound a hostile answer before parsing it, and a bound cannot be fetched from
    // the party it constrains. Changing one of them on the relay means changing it here in the
    // same step; `BACKEND.md` §2.7 is the shared authority for all four.

    /// The relay's own ceiling on one acknowledgement (`api.maxAckBatch`). Exceeding it is a
    /// 400, so the caller chunks rather than discovering it in production.
    static let maxAcknowledgeBatch = 200

    /// The relay's own ceiling on one fetch response (`api.maxFetchBatch`).
    static let maxFetchBatch = 100

    /// `store.MinEnvelopeBytes` — below this there is no envelope, only a header.
    static let minEnvelopeBytes = 32

    /// `store.MaxEnvelopeBytes`.
    static let maxEnvelopeBytes = 65_567

    /// Ceiling on the bytes one fetch response may occupy.
    ///
    /// Derived rather than picked: a full batch is ``maxFetchBatch`` entries, each carrying a
    /// base64 envelope of at most `4 * ceil(maxEnvelopeBytes / 3)` characters plus a 36-character
    /// id and its JSON punctuation. That is a little under 8.8 MB, and 10 MiB leaves room for
    /// whitespace and a longer key set without leaving room for an attack.
    static let maxFetchResponseBytes = 10 * 1024 * 1024

    // MARK: - Transport

    private func perform(_ request: RelayRequest) async throws -> RelayClient.Response {
        do {
            return try await client.send(request)
        } catch RelayClient.TransportError.exhaustedRetries(let lastStatus) {
            // The relay answered every time; it just kept failing. 429 here means the limiter
            // held across every attempt, which is a rate limit and not an outage.
            throw lastStatus == 429 ? Failure.rateLimited : Failure.serverUnavailable
        } catch RelayClient.TransportError.responseTooLarge {
            // Not an outage: the relay answered, with more than an answer. Reporting this as
            // unreachable would send the user to look at their connection.
            throw Failure.malformedResponse
        } catch is CancellationError {
            // Rethrown rather than folded into a `Failure`. The caller stopped asking; the
            // relay did nothing wrong, and `MessageRepository` must not log a network fault
            // for a cancelled receive cycle.
            throw CancellationError()
        } catch {
            throw Failure.unreachable
        }
    }

    // MARK: - Wire shapes

    private struct SendRequest: Encodable {
        let recipient: String
        let envelope: String
    }

    private struct FetchResponse: Decodable {
        struct Message: Decodable {
            let id: String
            let envelope: String
        }
        let messages: [Message]
        let more: Bool
    }

    private struct AckRequest: Encodable {
        let ids: [String]
    }

    private struct AckResponse: Decodable {
        let acknowledged: Int
    }
}
