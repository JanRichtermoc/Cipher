//
//  InviteRedemption.swift
//  Cipher
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import CipherCrypto
import Foundation

/// Redeems an invite code against the relay and stores the session it returns.
///
/// ## This is the only way an installation becomes authenticated
///
/// AUDIT C-01: the previous flow gated on `code.count >= 4` in a SwiftUI button and then set a
/// boolean. Nothing verified the code, so "authenticated" meant "typed four characters". A
/// credential now exists only if the relay issued one, and the relay issues one only in
/// exchange for a code it can find, has not already spent, and has not expired — a decision
/// made by one atomic `DELETE … RETURNING` on the server (`BACKEND.md` §2.2).
///
/// ## Redemption is not idempotent, and that is load-bearing
///
/// An invite is single-use: the row is deleted on success. Retrying a redeem whose response
/// was lost would spend a second code, or — worse, if the first actually succeeded — create a
/// second account and discard the first, stranding the token the user needed. So the request
/// is marked `isIdempotent: false`, which stops ``RelayClient`` retrying it at all. The cost is
/// that a genuinely lost response means the user must ask for another invite. That is the
/// correct trade: an invite is cheap, a silently orphaned account is not.
///
/// ## Failures are deliberately indistinguishable
///
/// The relay answers unknown, already-redeemed, expired and lost-race with an identical 401
/// because its schema cannot tell them apart either — a redeemed invite is deleted, not
/// flagged. This type preserves that: ``Failure/refused`` carries no detail, because anything
/// more specific would confirm to a guessing loop that a code had once been real.
nonisolated struct InviteRedemption: Sendable {

    private let client: RelayClient

    init(client: RelayClient = RelayClient()) {
        self.client = client
    }

    enum Failure: Error, Equatable {
        /// The code was not redeemable. Unknown, spent, expired, or lost a race — the server
        /// does not say which, and neither does this.
        case refused
        /// Too many attempts from this address. The relay allows 5/hour (`BACKEND.md` §5).
        case rateLimited
        /// The relay could not be reached, or the connection was refused — which includes a
        /// pin mismatch, since `RelayClient` collapses TLS failures into one case.
        case unreachable
        /// The relay answered with something this version cannot parse.
        case malformedResponse
    }

    /// What redemption produced.
    ///
    /// The credential is **returned rather than stored here**. `AppSession.signIn(with:)` is
    /// the single owner of the signed-in transition — it writes the Keychain *and* updates the
    /// observable state — so storing from this type would leave the UI showing a signed-out
    /// app until the next launch, and would give the Keychain two writers.
    // Not Equatable: SessionCredential's conformance is MainActor-isolated by the
    // project-wide default, and widening a credential type's isolation to satisfy a
    // convenience conformance is not a trade worth making.
    struct Redeemed: Sendable {
        /// This account's identifier on the relay. Not a secret; peers learn it to fetch a
        /// prekey bundle.
        ///
        /// A `UUID`, not a `String`, since P5.S10: it is adopted as this installation's
        /// `PeerAddress` and every use of it downstream requires a UUID. Parsing it here means a
        /// relay that answers with a non-UUID is a refused redemption rather than an account that
        /// authenticates and then cannot send.
        let aci: UUID
        let expiresAt: Date
        /// Marked `.serverIssued`, which is the only origin a Release build will read back.
        let credential: SessionCredential
    }

    /// Redeem `code`, publishing this installation's identity, and return the session it buys.
    ///
    /// - Parameter engine: supplies the identity key and registration id the relay records for
    ///   this account. Injected rather than opened here so a test can drive the whole flow
    ///   against a temporary container.
    func redeem(code: String, using engine: CryptoEngine) async throws -> Redeemed {
        let trimmed = code.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw Failure.refused }

        let identityKey: Data
        let registrationId: UInt32
        do {
            // `await`: CryptoEngine is isolated to CryptoActor, which is what makes the
            // module's "every libsignal call happens on one queue" claim structural rather
            // than a convention. Reaching in synchronously is exactly what that isolation
            // exists to prevent.
            identityKey = try await engine.localIdentityKey
            registrationId = try await engine.localRegistrationId
        } catch {
            // The crypto module is the source of both values; if it cannot produce them there
            // is nothing to register and no useful way to continue.
            throw Failure.malformedResponse
        }

        let payload = RedeemRequest(code: trimmed,
                                    identityKey: identityKey.base64EncodedString(),
                                    registrationId: registrationId)

        let body: Data
        do {
            body = try JSONEncoder().encode(payload)
        } catch {
            throw Failure.malformedResponse
        }

        let request = RelayRequest(method: "POST",
                                   path: "/v1/invite/redeem",
                                   body: body,
                                   bearerToken: nil,
                                   // Single-use. See the type comment.
                                   isIdempotent: false)

        let response: RelayClient.Response
        do {
            response = try await client.send(request)
        } catch {
            throw Failure.unreachable
        }

        switch response.status {
        case 200, 201:
            break
        case 401:
            throw Failure.refused
        case 429:
            throw Failure.rateLimited
        default:
            throw Failure.malformedResponse
        }

        let decoded: RedeemResponse
        do {
            decoded = try JSONDecoder().decode(RedeemResponse.self, from: response.body)
        } catch {
            throw Failure.malformedResponse
        }

        guard let token = decoded.token.data(using: .utf8), !token.isEmpty,
              let aci = UUID(uuidString: decoded.aci) else {
            throw Failure.malformedResponse
        }

        return Redeemed(aci: aci,
                        expiresAt: decoded.tokenExpiresAt,
                        credential: SessionCredential(token: token,
                                                      issuedAt: Date(),
                                                      origin: .serverIssued))
    }

    // MARK: - Wire shapes

    /// Field names are the relay's, which uses snake_case. The server refuses unknown fields
    /// (`DisallowUnknownFields`), so a rename here is a 400 rather than a silent default.
    private struct RedeemRequest: Encodable {
        let code: String
        let identityKey: String
        let registrationId: UInt32

        enum CodingKeys: String, CodingKey {
            case code
            case identityKey = "identity_key"
            case registrationId = "registration_id"
        }
    }

    private struct RedeemResponse: Decodable {
        let aci: String
        let token: String
        let tokenExpiresAt: Date

        enum CodingKeys: String, CodingKey {
            case aci, token
            case tokenExpiresAt = "token_expires_at"
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            aci = try container.decode(String.self, forKey: .aci)
            token = try container.decode(String.self, forKey: .token)

            // The relay emits RFC 3339 with fractional seconds. `.iso8601` alone rejects
            // those, so the format is parsed explicitly rather than left to a default that
            // happens to work until the server's precision changes.
            let raw = try container.decode(String.self, forKey: .tokenExpiresAt)
            let withFraction = ISO8601DateFormatter()
            withFraction.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            let plain = ISO8601DateFormatter()
            plain.formatOptions = [.withInternetDateTime]

            guard let date = withFraction.date(from: raw) ?? plain.date(from: raw) else {
                throw DecodingError.dataCorruptedError(
                    forKey: .tokenExpiresAt, in: container,
                    debugDescription: "not an RFC 3339 timestamp: \(raw)")
            }
            tokenExpiresAt = date
        }
    }
}
