//
//  RelayBlobStore.swift
//  Cipher
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import CipherCrypto
import Foundation

/// The relay's attachment slots: put opaque bytes in, take opaque bytes out, shred them early.
///
/// ## This type never sees a key and never sees a plaintext
///
/// It moves `Data` that `AttachmentCipher.seal` produced and that `AttachmentCipher.open` will
/// consume, and it has no way to do either. That is not a coincidence of layering — it is the
/// property the roadmap row's anti-goal names. "Upload then encrypt" would be a version of this
/// file that took the picked image; this one cannot, because its parameter is already
/// ciphertext and nothing here can make ciphertext.
///
/// ## The id is the whole capability
///
/// `BACKEND.md` §2.8: an attachment row has no owner column, so the relay cannot tell who
/// uploaded a blob or who may read it, and therefore never records the edge. The id reaches the
/// recipient inside the end-to-end ciphertext of the message that points at it. Downloading
/// still requires a session — not as a second authorisation, which the relay cannot express,
/// but so the download rate limit is enforceable and the store is not on the open internet.
nonisolated struct RelayBlobStore: Sendable {

    private let client: RelayClient

    init(client: RelayClient? = nil) {
        // A larger whole-call budget than the default, because one attempt is already
        // `RelayClient.blobTimeout`; see `blobResourceTimeout`.
        self.client = client ?? RelayClient(callDeadline: RelayClient.blobResourceTimeout)
    }

    enum Failure: Error, Equatable {
        case unauthenticated
        case rateLimited
        case unreachable
        case malformedResponse
        /// The blob is gone: never uploaded, already deleted, or past the relay's seven-day
        /// TTL (`BACKEND.md` §4). Not retryable.
        case notFound
        /// The relay refused the upload as too large. The client's own ceiling is smaller
        /// (`AttachmentCipher.maxPlaintextBytes`), so reaching this means the two disagree.
        case tooLarge
        case serverUnavailable
    }

    // MARK: - Upload

    /// Hands `ciphertext` to the relay and returns the slot id.
    ///
    /// **Not idempotent, and not retried.** Each POST mints a fresh id, so a retry after a lost
    /// response would leave the first blob on the relay with nothing pointing at it — bytes no
    /// sweep can attribute and no recipient will ever fetch, occupying the account's daily
    /// quota until the TTL. A failed upload surfaces to the caller, which has not yet stored or
    /// sent anything that refers to it.
    func upload(ciphertext: Data, token: String) async throws -> UUID {
        guard !ciphertext.isEmpty,
              ciphertext.count <= CryptoEngine.maxAttachmentCiphertextBytes
        else {
            throw Failure.tooLarge
        }

        let response = try await perform(
            RelayRequest(
                method: "POST", path: Self.path, body: ciphertext,
                contentType: "application/octet-stream",
                bearerToken: token, isIdempotent: false,
                attemptTimeout: RelayClient.blobTimeout))

        switch response.status {
        case 201:
            break
        case 401:
            throw Failure.unauthenticated
        case 413:
            throw Failure.tooLarge
        case 429:
            throw Failure.rateLimited
        default:
            throw Failure.malformedResponse
        }

        let decoded: UploadResponse
        do {
            decoded = try JSONDecoder().decode(UploadResponse.self, from: response.body)
        } catch {
            throw Failure.malformedResponse
        }
        guard let id = UUID(uuidString: decoded.id),
              // The relay reports what it committed. A size that is not the one that was sent
              // describes a different object, and the caller is about to publish a digest for
              // this one.
              decoded.size == ciphertext.count
        else {
            throw Failure.malformedResponse
        }
        return id
    }

    // MARK: - Download

    /// Fetches the blob for `id`, refusing anything that is not exactly `expectedByteCount`.
    ///
    /// The ceiling is the expected length rather than a generous constant, and it is derived
    /// from the sender's own declaration inside the authenticated message. So a relay that
    /// answers with more bytes than the message describes has the transfer cancelled while it
    /// is still arriving — the integrity checks in `AttachmentCipher.open` would refuse it
    /// afterwards regardless, but not before the device had read it all into memory.
    func download(id: UUID, expectedByteCount: Int, token: String) async throws -> Data {
        guard expectedByteCount > 0,
              expectedByteCount <= CryptoEngine.maxAttachmentCiphertextBytes
        else {
            throw Failure.tooLarge
        }

        let response = try await perform(
            RelayRequest(
                method: "GET", path: "\(Self.path)/\(id.uuidString.lowercased())",
                body: nil, contentType: nil,
                bearerToken: token, isIdempotent: true,
                responseByteCeiling: expectedByteCount,
                attemptTimeout: RelayClient.blobTimeout))

        switch response.status {
        case 200:
            break
        case 401:
            throw Failure.unauthenticated
        case 404:
            throw Failure.notFound
        case 429:
            throw Failure.rateLimited
        default:
            throw Failure.malformedResponse
        }

        guard response.body.count == expectedByteCount else { throw Failure.malformedResponse }
        return response.body
    }

    // MARK: - Delete

    /// Removes the blob and its row.
    ///
    /// Idempotent on the relay — 204 whether or not anything was there — which is what makes it
    /// safe to retry and safe to call twice. The realistic caller is the recipient shredding an
    /// attachment it has already stored locally, which ends the relay's retention early instead
    /// of waiting out the seven-day TTL on a host the threat model assumes is seizable.
    func delete(id: UUID, token: String) async throws {
        let response = try await perform(
            RelayRequest(
                method: "DELETE", path: "\(Self.path)/\(id.uuidString.lowercased())",
                body: nil, contentType: nil,
                bearerToken: token, isIdempotent: true))

        switch response.status {
        case 204:
            return
        case 401:
            throw Failure.unauthenticated
        case 429:
            throw Failure.rateLimited
        default:
            throw Failure.malformedResponse
        }
    }

    // MARK: - Transport

    private static let path = "/v1/blobs"

    private func perform(_ request: RelayRequest) async throws -> RelayClient.Response {
        do {
            return try await client.send(request)
        } catch RelayClient.TransportError.exhaustedRetries(let lastStatus) {
            throw lastStatus == 429 ? Failure.rateLimited : Failure.serverUnavailable
        } catch RelayClient.TransportError.responseTooLarge {
            // The relay answered with more than the message said the blob was. Reported as a
            // malformed response rather than as a size problem the user could act on: nothing
            // they do changes what the relay sends.
            throw Failure.malformedResponse
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw Failure.unreachable
        }
    }

    private struct UploadResponse: Decodable {
        let id: String
        let size: Int
    }
}
