//
//  RelayKeyDirectory.swift
//  Cipher
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import CipherCrypto
import Foundation

/// The prekey directory: publish this installation's keys, fetch a peer's bundle.
///
/// Both endpoints require authentication (`BACKEND.md` §1). An unauthenticated directory would
/// make the per-account fetch limit unenforceable and would be a membership oracle for the
/// whole circle.
nonisolated struct RelayKeyDirectory: Sendable {

    private let client: RelayClient

    init(client: RelayClient = RelayClient()) {
        self.client = client
    }

    enum Failure: Error, Equatable {
        /// The relay rejected the session token. The caller must sign in again; retrying with
        /// the same token cannot succeed.
        case unauthenticated
        /// No bundle can be served for that account right now. The relay answers **404 for
        /// unknown account, never-published, and empty pool alike** (`BACKEND.md` §8: no
        /// account enumeration), so this carries no more detail than the server does.
        case unavailable
        /// A publish or fetch limit was hit. Publication is 6/day, bundle fetches are 10/hour
        /// and 30/day per caller — the latter two are the mitigation for AUDIT 3.1 and are
        /// expected to bite eventually rather than never.
        case rateLimited
        /// Unreachable, or the connection was refused — which includes a pin mismatch, since
        /// `RelayClient` collapses every TLS failure into one case.
        case unreachable
        /// The relay answered, repeatedly, with a server error. Not the network — see
        /// `RelayMailbox.Failure.serverUnavailable`.
        case serverUnavailable
        case malformedResponse
    }

    // MARK: - Publishing

    /// Publishes this installation's public prekey material.
    ///
    /// **Marked idempotent, which is a statement about the database and not about the cost.**
    /// Every insert in `store.PublishPreKeys` is an upsert or a `DO NOTHING`, so replaying the
    /// same body converges on the same state — no prekey is duplicated and no signed prekey is
    /// orphaned. A repeat does spend one of the six daily publication tokens, which is why the
    /// app records that it has published and does not do it on every launch; that is a
    /// scheduling decision, not a safety one, and retrying a 5xx here is strictly better than
    /// leaving an account whose peers cannot start a session with it.
    func publish(_ keys: PublishedKeys, token: String) async throws {
        let payload = PublishRequest(
            signedPreKey: .init(keys.signedPreKey),
            kyberLastResort: .init(keys.kyberLastResort),
            kyberPreKeys: keys.kyberPreKeys.map(SignedKeyJSON.init),
            oneTimePreKeys: keys.oneTimePreKeys.map(OneTimeKeyJSON.init))

        let body: Data
        do {
            body = try JSONEncoder().encode(payload)
        } catch {
            throw Failure.malformedResponse
        }

        let response = try await perform(
            RelayRequest(
                method: "PUT", path: "/v1/keys", body: body,
                bearerToken: token, isIdempotent: true))

        switch response.status {
        case 200:
            return
        case 401:
            throw Failure.unauthenticated
        case 429:
            throw Failure.rateLimited
        default:
            throw Failure.malformedResponse
        }
    }

    // MARK: - Fetching

    /// Fetches `aci`'s bundle so a session can be started with them.
    ///
    /// ## A GET that must never be retried
    ///
    /// This request is marked **non-idempotent** even though it is a `GET`, because on the
    /// server it is a mutation: the dispense deletes the one-time prekey it serves, in the same
    /// transaction (`BACKEND.md` §2.4). A retry after a lost response therefore burns a second
    /// prekey from the peer's pool and a second token from this caller's fetch budget — and
    /// draining that pool is precisely the attack the budget exists to bound (AUDIT 3.1). A
    /// client that retries its own fetches is a client that helps.
    ///
    /// The returned bundle is **unverified**: `PeerKeyBundle` validates structure only, and the
    /// signatures are checked by libsignal inside `processPreKeyBundle` on every use. Whether
    /// the identity key is *the peer's* is not answerable here at all — that is trust on first
    /// use until safety numbers land (P5.S12, AUDIT 3.3).
    func bundle(for aci: UUID, token: String) async throws -> PeerKeyBundle {
        let response = try await perform(
            RelayRequest(
                method: "GET", path: "/v1/keys/\(aci.uuidString.lowercased())",
                body: nil, contentType: nil,
                bearerToken: token, isIdempotent: false))

        switch response.status {
        case 200:
            break
        case 401:
            throw Failure.unauthenticated
        case 404:
            throw Failure.unavailable
        case 429:
            throw Failure.rateLimited
        default:
            throw Failure.malformedResponse
        }

        let decoded: BundleResponse
        do {
            decoded = try JSONDecoder().decode(BundleResponse.self, from: response.body)
        } catch {
            throw Failure.malformedResponse
        }
        return try decoded.peerKeyBundle()
    }

    // MARK: - Transport

    private func perform(_ request: RelayRequest) async throws -> RelayClient.Response {
        do {
            return try await client.send(request)
        } catch RelayClient.TransportError.exhaustedRetries(let lastStatus) {
            throw lastStatus == 429 ? Failure.rateLimited : Failure.serverUnavailable
        } catch {
            throw Failure.unreachable
        }
    }

    // MARK: - Wire shapes

    /// Field names are the relay's. It refuses unknown fields, so a rename here is a 400
    /// rather than a silently dropped key.
    private struct SignedKeyJSON: Encodable {
        let keyId: UInt32
        let publicKey: String
        let signature: String

        init(_ key: PublishedKeys.SignedKey) {
            keyId = key.keyId
            publicKey = key.publicKey.base64EncodedString()
            signature = key.signature.base64EncodedString()
        }

        enum CodingKeys: String, CodingKey {
            case keyId = "key_id"
            case publicKey = "public_key"
            case signature
        }
    }

    private struct OneTimeKeyJSON: Encodable {
        let keyId: UInt32
        let publicKey: String

        init(_ key: PublishedKeys.OneTimeKey) {
            keyId = key.keyId
            publicKey = key.publicKey.base64EncodedString()
        }

        enum CodingKeys: String, CodingKey {
            case keyId = "key_id"
            case publicKey = "public_key"
        }
    }

    private struct PublishRequest: Encodable {
        let signedPreKey: SignedKeyJSON
        let kyberLastResort: SignedKeyJSON
        let kyberPreKeys: [SignedKeyJSON]
        let oneTimePreKeys: [OneTimeKeyJSON]

        enum CodingKeys: String, CodingKey {
            case signedPreKey = "signed_prekey"
            case kyberLastResort = "kyber_last_resort"
            case kyberPreKeys = "kyber_prekeys"
            case oneTimePreKeys = "one_time_prekeys"
        }
    }

    private struct BundleResponse: Decodable {
        let registrationId: UInt32
        let identityKey: String
        let preKeyId: UInt32
        let preKey: String
        let signedPreKeyId: UInt32
        let signedPreKey: String
        let signedPreKeySignature: String
        let kyberPreKeyId: UInt32
        let kyberPreKey: String
        let kyberPreKeySignature: String

        enum CodingKeys: String, CodingKey {
            case registrationId = "registration_id"
            case identityKey = "identity_key"
            case preKeyId = "prekey_id"
            case preKey = "prekey"
            case signedPreKeyId = "signed_prekey_id"
            case signedPreKey = "signed_prekey"
            case signedPreKeySignature = "signed_prekey_signature"
            case kyberPreKeyId = "kyber_prekey_id"
            case kyberPreKey = "kyber_prekey"
            case kyberPreKeySignature = "kyber_prekey_signature"
        }

        /// Decodes base64 into the boundary type.
        ///
        /// An empty or undecodable field is refused here rather than passed on: every one of
        /// these is attacker-chosen under the hostile-relay model, and a zero-length "key" that
        /// reached `PeerKeyBundle` would surface later as a structural parse failure whose
        /// cause was two layers away.
        func peerKeyBundle() throws -> PeerKeyBundle {
            func decode(_ value: String) throws -> Data {
                guard let data = Data(base64Encoded: value), !data.isEmpty else {
                    throw Failure.malformedResponse
                }
                return data
            }

            return PeerKeyBundle(
                registrationId: registrationId,
                deviceId: PeerAddress.primaryDevice,
                identityKey: try decode(identityKey),
                preKeyId: preKeyId,
                preKey: try decode(preKey),
                signedPreKeyId: signedPreKeyId,
                signedPreKey: try decode(signedPreKey),
                signedPreKeySignature: try decode(signedPreKeySignature),
                kyberPreKeyId: kyberPreKeyId,
                kyberPreKey: try decode(kyberPreKey),
                kyberPreKeySignature: try decode(kyberPreKeySignature))
        }
    }
}
