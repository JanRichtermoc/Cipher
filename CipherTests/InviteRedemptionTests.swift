//
//  InviteRedemptionTests.swift
//  CipherTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import CipherCrypto
import Foundation
import Testing

@testable import Cipher

/// Drives ``InviteRedemption`` against a stubbed relay.
///
/// `URLProtocol` rather than a protocol-witness fake, because the point of several of these
/// tests is what ``RelayClient`` does — retry or refuse to — and a fake client would let the
/// test assert its own stub instead of the behaviour that ships.
final class StubRelay: URLProtocol, @unchecked Sendable {

    struct Reply: Sendable {
        let status: Int
        let body: Data
        let headers: [String: String]

        init(status: Int, json: String, headers: [String: String] = [:]) {
            self.status = status
            self.body = Data(json.utf8)
            self.headers = headers
        }
    }

    /// Replies handed out in order; the last one repeats once exhausted.
    nonisolated(unsafe) static var replies: [Reply] = []
    /// Every request the client actually made, so "did it retry?" is observable.
    nonisolated(unsafe) static var received: [URLRequest] = []

    static func reset(_ replies: [Reply]) {
        self.replies = replies
        self.received = []
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.received.append(request)
        let reply = Self.replies.count > 1 ? Self.replies.removeFirst() : (Self.replies.first ?? Reply(status: 500, json: "{}"))

        let response = HTTPURLResponse(url: request.url!,
                                       statusCode: reply.status,
                                       httpVersion: "HTTP/1.1",
                                       headerFields: reply.headers)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: reply.body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

// @MainActor because SessionCredential's stored properties are MainActor-isolated under the
// project-wide default isolation, and these tests read them. Running the suite on the main
// actor is the cheap side of that trade — the alternative is widening a credential type's
// isolation to suit a test, which is the wrong direction.
@Suite("Invite redemption", .serialized)
@MainActor
struct InviteRedemptionTests {

    /// A client whose transport is the stub. Pinning is not exercised here — it has its own
    /// suite — and a stubbed `URLProtocol` never reaches TLS.
    private func stubbedClient() -> RelayClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubRelay.self]
        let session = URLSession(configuration: configuration)
        // Zero jitter so a retrying test does not actually sleep.
        return RelayClient(session: session, jitter: { _ in 0 })
    }

    private static let redemptionNow = Date(timeIntervalSince1970: 1_785_499_200)

    /// A code of the shape the relay actually issues: 26 Crockford base32 symbols, grouped in
    /// fives for transcription. These tests are about what happens *after* a code is presented,
    /// so it has to be one the client will present — `InviteCode` refuses anything else before
    /// the request is built, and `RelayTransportTests` is where that refusal is tested.
    private static let validCode = "ABCDE-FGHJK-MNPQR-STVWX-YZ234-5"
    private static let canonicalCode = "ABCDEFGHJKMNPQRSTVWXYZ2345"

    private func redemption() -> InviteRedemption {
        let now = Self.redemptionNow
        return InviteRedemption(client: stubbedClient(), now: { now })
    }

    private func engine() async throws -> CryptoEngine {
        let container = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("redeem-\(UUID().uuidString)", isDirectory: true)
        return try await CryptoEngine.open(container: container)
    }

    private static let goodBody = """
    {"aci":"3f2b1c4d-0000-4000-8000-000000000001",\
    "token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",\
    "token_expires_at":"2026-08-30T12:00:00.000Z"}
    """

    // MARK: The point of the whole step

    @Test("a redeemed code yields a SERVER-ISSUED credential")
    func successProducesServerIssuedCredential() async throws {
        StubRelay.reset([.init(status: 201, json: Self.goodBody)])

        let redeemed = try await redemption()
            .redeem(code: Self.validCode, using: try await engine())

        // `.serverIssued` is the only origin a Release build reads back, so this is the
        // assertion that separates a real session from the DEBUG development credential.
        #expect(redeemed.credential.origin == .serverIssued)
        #expect(redeemed.credential.phase == .registering)
        #expect(!redeemed.credential.token.isEmpty)
        #expect(redeemed.aci == UUID(uuidString: "3f2b1c4d-0000-4000-8000-000000000001"))
        #expect(redeemed.credential.aci == redeemed.aci)
        #expect(redeemed.credential.expiresAt == redeemed.expiresAt)
    }

    @Test("the request carries the real identity key and registration id, in the relay's shape")
    func requestMatchesTheRelayContract() async throws {
        StubRelay.reset([.init(status: 201, json: Self.goodBody)])
        let engine = try await engine()
        let expectedKey = try await engine.localIdentityKey
        let expectedRegistration = try await engine.localRegistrationId

        _ = try await redemption().redeem(code: Self.validCode, using: engine)

        let request = try #require(StubRelay.received.first)
        #expect(request.httpMethod == "POST")
        #expect(request.url?.path == "/v1/invite/redeem")

        // URLProtocol strips httpBody into httpBodyStream, so read it back out.
        let body = try #require(request.httpBody ?? request.httpBodyStream.map { stream in
            stream.open(); defer { stream.close() }
            var data = Data(); var buffer = [UInt8](repeating: 0, count: 4096)
            while stream.hasBytesAvailable {
                let read = stream.read(&buffer, maxLength: buffer.count)
                if read <= 0 { break }
                data.append(buffer, count: read)
            }
            return data
        })
        let json = try #require(try JSONSerialization.jsonObject(with: body) as? [String: Any])

        // snake_case, because the relay refuses unknown fields rather than defaulting them:
        // "registrationId" would register the account with id 0 and fail much later.
        // The canonical form, not what was typed: hyphens are transcription and the relay
        // strips them, so sending the grouped string would make the wire shape depend on how
        // the user happened to space the code out.
        #expect(json["code"] as? String == Self.canonicalCode)
        #expect(json["identity_key"] as? String == expectedKey.base64EncodedString())
        #expect(json["registration_id"] as? UInt32 == expectedRegistration)
    }

    // MARK: Nothing here may authenticate

    @Test("a refused code produces no credential")
    func refusedCodeProducesNothing() async throws {
        StubRelay.reset([.init(status: 401, json: #"{"error":"unauthorized"}"#)])

        await #expect(throws: InviteRedemption.Failure.refused) {
            try await redemption()
                .redeem(code: Self.validCode, using: try await engine())
        }
    }

    @Test("rate limiting is reported as such and issues nothing")
    func rateLimited() async throws {
        StubRelay.reset([.init(status: 429, json: "{}", headers: ["Retry-After": "3600"])])

        await #expect(throws: InviteRedemption.Failure.rateLimited) {
            try await redemption()
                .redeem(code: Self.validCode, using: try await engine())
        }
    }

    @Test("an empty code never reaches the relay")
    func emptyCodeIsRefusedLocally() async throws {
        StubRelay.reset([.init(status: 201, json: Self.goodBody)])

        await #expect(throws: InviteRedemption.Failure.refused) {
            try await redemption()
                .redeem(code: "   ", using: try await engine())
        }
        #expect(StubRelay.received.isEmpty, "an empty code must not spend a rate-limit token")
    }

    @Test("a 200 carrying an EMPTY token does not authenticate")
    func emptyTokenIsNotASession() async throws {
        // The dangerous shape: the server said OK, so a careless implementation signs in.
        //
        // The timestamp here is deliberately VALID. An earlier version of this test omitted
        // it, so decoding failed on the missing field and the test passed without the
        // empty-token guard ever running — it was green against a build that accepted an
        // empty credential. Every field except the one under test must be well-formed, or
        // the test proves something other than what it claims.
        StubRelay.reset([.init(status: 200, json: """
        {"aci":"3f2b1c4d-0000-4000-8000-000000000001","token":"",\
        "token_expires_at":"2026-08-30T12:00:00.000Z"}
        """)])

        await #expect(throws: InviteRedemption.Failure.malformedResponse) {
            try await redemption()
                .redeem(code: Self.validCode, using: try await engine())
        }
    }

    @Test("a non-canonical server token is refused")
    func nonCanonicalTokenIsNotASession() async throws {
        // 43 base64url characters that decode to 32 bytes, but whose unused
        // low bits make it a second spelling of another token.
        let token = String(repeating: "A", count: 42) + "B"
        StubRelay.reset([.init(status: 200, json: """
        {"aci":"3f2b1c4d-0000-4000-8000-000000000001","token":"\(token)",\
        "token_expires_at":"2026-08-30T12:00:00.000Z"}
        """)])

        await #expect(throws: InviteRedemption.Failure.malformedResponse) {
            try await redemption().redeem(code: Self.validCode, using: try await engine())
        }
    }

    @Test("a 200 with an empty aci does not authenticate")
    func emptyACIIsNotASession() async throws {
        StubRelay.reset([.init(status: 200, json: """
        {"aci":"","token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",\
        "token_expires_at":"2026-08-30T12:00:00.000Z"}
        """)])

        await #expect(throws: InviteRedemption.Failure.malformedResponse) {
            try await redemption()
                .redeem(code: Self.validCode, using: try await engine())
        }
    }

    @Test("a 200 with a non-UUID aci does not authenticate")
    func nonUUIDACIIsNotASession() async throws {
        // P5.S10 made `aci` a `UUID`, because it is adopted as this installation's address. A
        // relay answering with something that is not one must be a refused redemption: the
        // alternative is an account that holds a valid token and can never send, which looks
        // like a messaging bug rather than a registration failure. Varies only this field.
        StubRelay.reset([.init(status: 200, json: """
        {"aci":"not-a-uuid","token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",\
        "token_expires_at":"2026-08-30T12:00:00.000Z"}
        """)])

        await #expect(throws: InviteRedemption.Failure.malformedResponse) {
            try await redemption()
                .redeem(code: Self.validCode, using: try await engine())
        }
    }

    @Test("a 200 with the nil UUID does not create an account binding")
    func zeroACIIsNotASession() async throws {
        StubRelay.reset([.init(status: 200, json: """
        {"aci":"00000000-0000-0000-0000-000000000000",\
        "token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",\
        "token_expires_at":"2026-08-30T12:00:00.000Z"}
        """)])

        await #expect(throws: InviteRedemption.Failure.malformedResponse) {
            try await redemption().redeem(code: Self.validCode, using: try await engine())
        }
    }

    @Test("a 200 with an unparseable expiry does not authenticate")
    func badTimestampIsNotASession() async throws {
        // Separated from the tests above so each one fails for its own reason.
        StubRelay.reset([.init(status: 200, json: """
        {"aci":"3f2b1c4d-0000-4000-8000-000000000001",\
        "token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","token_expires_at":"whenever"}
        """)])

        await #expect(throws: InviteRedemption.Failure.malformedResponse) {
            try await redemption()
                .redeem(code: Self.validCode, using: try await engine())
        }
    }

    @Test("an already-expired token does not authenticate locally")
    func expiredTimestampIsNotASession() async throws {
        StubRelay.reset([.init(status: 200, json: """
        {"aci":"3f2b1c4d-0000-4000-8000-000000000001",\
        "token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",\
        "token_expires_at":"2026-07-30T12:00:00.000Z"}
        """)])

        await #expect(throws: InviteRedemption.Failure.malformedResponse) {
            try await redemption().redeem(code: Self.validCode, using: try await engine())
        }
    }

    @Test("a relay cannot extend local authentication beyond the session policy")
    func overlongTimestampIsNotASession() async throws {
        StubRelay.reset([.init(status: 200, json: """
        {"aci":"3f2b1c4d-0000-4000-8000-000000000001",\
        "token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",\
        "token_expires_at":"2026-09-15T12:00:00.000Z"}
        """)])

        await #expect(throws: InviteRedemption.Failure.malformedResponse) {
            try await redemption().redeem(code: Self.validCode, using: try await engine())
        }
    }

    // MARK: Single-use means never retried

    @Test("redemption is sent exactly once, even when the relay 5xxs")
    func redemptionIsNeverRetried() async throws {
        // The failure this prevents: a retry spends a second invite, or — if the first
        // attempt actually succeeded and only the response was lost — creates a second
        // account and throws away the token the user needed.
        StubRelay.reset([.init(status: 503, json: "{}")])

        await #expect(throws: InviteRedemption.Failure.self) {
            try await redemption()
                .redeem(code: Self.validCode, using: try await engine())
        }

        #expect(StubRelay.received.count == 1,
                "a single-use code was sent \(StubRelay.received.count) times")
    }

    @Test("an idempotent request IS retried — the positive control for the test above")
    func idempotentRequestsAreRetried() async throws {
        // Without this, `redemptionIsNeverRetried` would also pass if retries were broken
        // altogether, which would silently remove resilience everywhere else.
        StubRelay.reset([.init(status: 503, json: "{}")])

        _ = try? await stubbedClient().send(
            RelayRequest(method: "POST", path: "/v1/messages/ack", body: Data("{}".utf8),
                         bearerToken: "t", isIdempotent: true))

        #expect(StubRelay.received.count == RelayClient.maxAttempts,
                "expected \(RelayClient.maxAttempts) attempts, saw \(StubRelay.received.count)")
    }

    // MARK: Session rotation

    @Test("rotation is sent exactly once because it consumes the old token")
    func rotationIsNeverRetried() async throws {
        StubRelay.reset([.init(status: 503, json: "{}")])
        let current = activeCredential(expiresInDays: 6)

        await #expect(throws: SessionLifecycle.Failure.serverUnavailable) {
            try await SessionLifecycle(client: stubbedClient()).rotate(current)
        }
        #expect(StubRelay.received.count == 1,
                "a consuming rotation was sent \(StubRelay.received.count) times")
    }

    @Test("rotation preserves the account binding and extends server expiry")
    func rotationProducesAnAccountBoundReplacement() async throws {
        let freshToken = String(repeating: "J", count: 42) + "A"
        let expiry = ISO8601DateFormatter().string(
            from: Date().addingTimeInterval(30 * 24 * 60 * 60))
        StubRelay.reset([.init(status: 200, json: """
        {"token":"\(freshToken)","expires_at":"\(expiry)"}
        """)])
        let current = activeCredential(expiresInDays: 6)

        let replacement = try await SessionLifecycle(client: stubbedClient()).rotate(current)
        #expect(replacement.aci == current.aci)
        #expect(replacement.phase == .active)
        #expect(replacement.bearerToken == freshToken)
        #expect(replacement.expiresAt > current.expiresAt)
    }

    private func activeCredential(expiresInDays days: Double) -> SessionCredential {
        let issuedAt = Date().addingTimeInterval(-24 * 60 * 60)
        return SessionCredential(
            token: Data((String(repeating: "I", count: 42) + "A").utf8), aci: UUID(),
            issuedAt: issuedAt,
            expiresAt: Date().addingTimeInterval(days * 24 * 60 * 60),
            origin: .serverIssued, phase: .active)
    }
}
