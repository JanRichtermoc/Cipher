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
    private let now: @Sendable () -> Date

    init(client: RelayClient = RelayClient(), now: @escaping @Sendable () -> Date = { Date() }) {
        self.client = client
        self.now = now
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
    /// The credential is **returned rather than stored here**. `AppSession.beginRegistration`
    /// owns the transition: it writes the Keychain and observable state together, leaving one
    /// credential writer and a persisted recovery point before crypto registration starts.
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
        // Refused here, as ``Failure/refused`` and not a distinct case, because the whole
        // point of that error is that it says nothing: a locally-refused code and a code the
        // relay has never heard of must look identical to the caller, or the UI copy becomes
        // the oracle the uniform 401 exists to deny.
        guard let canonical = InviteCode.canonical(code) else { throw Failure.refused }

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

        let payload = RedeemRequest(code: canonical,
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
        } catch is CancellationError {
            // Rethrown, not reported as a network failure: the user backed out of the screen.
            // Telling them the relay could not be reached would be a false claim about a
            // server that was never asked, and — since redemption is never retried — the
            // wrong thing to have on screen next to a code they may still be able to spend.
            throw CancellationError()
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

        let issuedAt = now()
        let zeroACI = UUID(uuidString: "00000000-0000-0000-0000-000000000000")!
        guard SessionCredential.isValidServerToken(decoded.token),
              let token = decoded.token.data(using: .utf8),
              let aci = UUID(uuidString: decoded.aci),
              aci != zeroACI,
              decoded.tokenExpiresAt > issuedAt,
              decoded.tokenExpiresAt.timeIntervalSince(issuedAt) <=
                SessionCredential.maximumLifetime else {
            throw Failure.malformedResponse
        }

        return Redeemed(aci: aci,
                        expiresAt: decoded.tokenExpiresAt,
                        credential: SessionCredential(token: token,
                                                      aci: aci,
                                                      issuedAt: issuedAt,
                                                      expiresAt: decoded.tokenExpiresAt,
                                                      origin: .serverIssued,
                                                      phase: .registering))
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
            guard let date = RelayTimestamp.parse(raw) else {
                throw DecodingError.dataCorruptedError(
                    forKey: .tokenExpiresAt, in: container,
                    debugDescription: "not an RFC 3339 timestamp: \(raw)")
            }
            tokenExpiresAt = date
        }
    }
}

/// Rotation and revocation for an already-issued relay credential.
///
/// Rotation is deliberately non-idempotent: the server consumes the old token
/// atomically. Retrying after a lost response would only turn an uncertain result
/// into a guaranteed 401, so the app keeps the old credential unless one complete
/// response supplied its replacement.
nonisolated struct SessionLifecycle: Sendable {
    private let client: RelayClient
    private let now: @Sendable () -> Date

    init(client: RelayClient = RelayClient(), now: @escaping @Sendable () -> Date = { Date() }) {
        self.client = client
        self.now = now
    }

    enum Failure: Error, Equatable {
        case rejected
        case rateLimited
        case unreachable
        case serverUnavailable
        case malformedResponse
    }

    func rotate(_ current: SessionCredential) async throws -> SessionCredential {
        guard current.origin == .serverIssued,
              current.phase == .active,
              !current.isExpired(at: now()),
              let token = current.bearerToken else {
            throw Failure.rejected
        }

        let response: RelayClient.Response
        do {
            response = try await client.send(RelayRequest(
                method: "POST", path: "/v1/auth/rotate", bearerToken: token,
                isIdempotent: false))
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw Failure.unreachable
        }

        switch response.status {
        case 200: break
        case 401: throw Failure.rejected
        case 429: throw Failure.rateLimited
        case 500...599: throw Failure.serverUnavailable
        default: throw Failure.malformedResponse
        }

        let decoded: RotateResponse
        do {
            decoded = try JSONDecoder().decode(RotateResponse.self, from: response.body)
        } catch {
            throw Failure.malformedResponse
        }

        let issuedAt = now()
        guard SessionCredential.isValidServerToken(decoded.token),
              let bytes = decoded.token.data(using: .utf8),
              decoded.expiresAt > current.expiresAt,
              decoded.expiresAt > issuedAt,
              decoded.expiresAt.timeIntervalSince(issuedAt) <=
                SessionCredential.maximumLifetime else {
            throw Failure.malformedResponse
        }

        return SessionCredential(token: bytes, aci: current.aci,
                                 issuedAt: issuedAt, expiresAt: decoded.expiresAt,
                                 origin: .serverIssued, phase: .active)
    }

    /// Best-effort server revocation before local cryptographic erasure. Local
    /// cleanup must continue even if the relay is offline; the token still has a
    /// hard expiry and the wiped device no longer holds message keys.
    func revokeBestEffort(_ credential: SessionCredential?) async {
        guard let token = credential?.bearerToken else { return }
        _ = try? await client.send(RelayRequest(
            method: "DELETE", path: "/v1/auth", bearerToken: token,
            isIdempotent: true))
    }

    private struct RotateResponse: Decodable {
        let token: String
        let expiresAt: Date

        enum CodingKeys: String, CodingKey {
            case token
            case expiresAt = "expires_at"
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            token = try container.decode(String.self, forKey: .token)
            let raw = try container.decode(String.self, forKey: .expiresAt)
            guard let parsed = RelayTimestamp.parse(raw) else {
                throw DecodingError.dataCorruptedError(
                    forKey: .expiresAt, in: container,
                    debugDescription: "not an RFC 3339 timestamp")
            }
            expiresAt = parsed
        }
    }
}

/// The invite-code format, checked before a code is spent.
///
/// ## Why the client validates at all
///
/// An invite code is the only thing that creates an account (`THREAT_MODEL.md` §3.4), and
/// `POST /v1/invite/redeem` is the relay's **only per-IP rate limit** — 5 per hour, and the one
/// AUDIT 5.15 exists about. A code that cannot possibly be valid still spends one of those five
/// when it is sent, so a user mistyping a 26-symbol string four times locks themselves out of
/// the one flow they were trying to complete, for an hour, on a device that has no other way in.
/// Refusing locally costs nothing and is not a security check on the code — the relay's atomic
/// `DELETE … RETURNING` is the only thing that decides whether a code is real.
///
/// ## Why the transcription rules are copied and not simplified
///
/// This mirrors `server/internal/invite/code.go`. Both sides accept lowercase, hyphens and
/// spaces, and both apply Crockford's substitutions — `I` and `L` mean `1`, `O` means `0` — so
/// that a code read off another screen is accepted as written. A client that normalised *less*
/// than the relay would refuse codes the relay would take, which is the same lockout by another
/// route. The alphabet, the symbol count and the substitutions must change on both sides in one
/// step; `invite.EntropyBits` is the reason the count is 26 and is the value that governs.
nonisolated enum InviteCode {

    /// `codeLen` on the relay: `ceil(EntropyBits / 5)` symbols of a 32-symbol alphabet.
    static let symbolCount = 26

    /// Crockford base32 — digits and uppercase letters without `I`, `L`, `O` and `U`.
    private static let alphabet = Set("0123456789ABCDEFGHJKMNPQRSTVWXYZ")

    /// The canonical (ungrouped, uppercase) form of `raw`, or `nil` if it is not a code.
    static func canonical(_ raw: String) -> String? {
        var symbols = ""
        symbols.reserveCapacity(symbolCount)

        for character in raw.trimmingCharacters(in: .whitespacesAndNewlines) {
            // Grouping is for transcription only and is stripped, exactly as `invite.Parse`
            // strips it — a code is read aloud and typed back with whatever separators the
            // reader used.
            if character == "-" || character == " " { continue }

            // ASCII a–z only, which is what `invite.Parse` uppercases. `Character.uppercased()`
            // would be wrong twice over: it returns a `String` that is not always one character
            // (ß uppercases to SS), so building a `Character` from it can trap on input a
            // hostile or careless paste controls.
            var symbol = character
            if let ascii = symbol.asciiValue, ascii >= 97, ascii <= 122 {
                symbol = Character(UnicodeScalar(ascii - 32))
            }

            switch symbol {
            case "I", "L": symbol = "1"
            case "O": symbol = "0"
            default: break
            }

            guard alphabet.contains(symbol) else { return nil }
            symbols.append(symbol)
            // Bounded as it goes: a pasted megabyte would otherwise be normalised in full
            // before its length was found to be wrong.
            guard symbols.count <= symbolCount else { return nil }
        }

        return symbols.count == symbolCount ? symbols : nil
    }
}

private nonisolated enum RelayTimestamp {
    static func parse(_ raw: String) -> Date? {
        let withFraction = ISO8601DateFormatter()
        withFraction.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let plain = ISO8601DateFormatter()
        plain.formatOptions = [.withInternetDateTime]
        return withFraction.date(from: raw) ?? plain.date(from: raw)
    }
}
