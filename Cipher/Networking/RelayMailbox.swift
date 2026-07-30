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
                bearerToken: token, isIdempotent: true))

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

        var pending: [Pending] = []
        pending.reserveCapacity(decoded.messages.count)
        for message in decoded.messages {
            guard let id = UUID(uuidString: message.id),
                  let envelope = Data(base64Encoded: message.envelope),
                  !envelope.isEmpty
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

        do {
            return try JSONDecoder().decode(AckResponse.self, from: response.body).acknowledged
        } catch {
            throw Failure.malformedResponse
        }
    }

    /// The relay's own ceiling on one acknowledgement (`api.maxAckBatch`). Exceeding it is a
    /// 400, so the caller chunks rather than discovering it in production.
    static let maxAcknowledgeBatch = 200

    // MARK: - Transport

    private func perform(_ request: RelayRequest) async throws -> RelayClient.Response {
        do {
            return try await client.send(request)
        } catch RelayClient.TransportError.exhaustedRetries(let lastStatus) {
            // The relay answered every time; it just kept failing. 429 here means the limiter
            // held across every attempt, which is a rate limit and not an outage.
            throw lastStatus == 429 ? Failure.rateLimited : Failure.serverUnavailable
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
