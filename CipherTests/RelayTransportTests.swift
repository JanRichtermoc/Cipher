//
//  RelayTransportTests.swift
//  CipherTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import CipherCrypto
import Foundation
import Testing

@testable import Cipher

/// A relay that answers however the test needs it to, including badly.
///
/// `URLProtocol` rather than a fake client, for the reason `StubRelay` gives: the properties
/// under test here belong to ``RelayClient`` and ``BoundedResponseLoader``, and a fake would
/// let the test assert its own stub.
final class TransportStub: URLProtocol, @unchecked Sendable {

    enum Reply: Sendable {
        case http(status: Int, body: Data, headers: [String: String])
        /// A transport-level failure, so the classification path can be driven directly.
        case failure(URLError.Code)
        /// A 302 offered to the delegate before the response is delivered.
        case redirect(to: String)
    }

    /// Handed out in order; the last one repeats once exhausted.
    nonisolated(unsafe) static var replies: [Reply] = []
    /// Every request that actually reached the wire, so "did it retry?" and "was the token
    /// re-sent?" are observable rather than assumed.
    nonisolated(unsafe) static var received: [URLRequest] = []

    static func reset(_ replies: [Reply]) {
        self.replies = replies
        self.received = []
    }

    static func json(_ status: Int, _ text: String, headers: [String: String] = [:]) -> Reply {
        .http(status: status, body: Data(text.utf8), headers: headers)
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.received.append(request)
        let reply = Self.replies.count > 1
            ? Self.replies.removeFirst()
            : (Self.replies.first ?? .http(status: 500, body: Data(), headers: [:]))

        switch reply {
        case .failure(let code):
            client?.urlProtocol(self, didFailWithError: URLError(code))

        case .redirect(let target):
            let response = HTTPURLResponse(url: request.url!, statusCode: 302,
                                           httpVersion: "HTTP/1.1",
                                           headerFields: ["Location": target])!
            var next = URLRequest(url: URL(string: target)!)
            next.httpMethod = request.httpMethod
            next.allHTTPHeaderFields = request.allHTTPHeaderFields
            client?.urlProtocol(self, wasRedirectedTo: next, redirectResponse: response)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocolDidFinishLoading(self)

        case .http(let status, let body, let headers):
            let response = HTTPURLResponse(url: request.url!, statusCode: status,
                                           httpVersion: "HTTP/1.1", headerFields: headers)!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            if !body.isEmpty { client?.urlProtocol(self, didLoad: body) }
            client?.urlProtocolDidFinishLoading(self)
        }
    }

    override func stopLoading() {}
}

/// AUDIT 5.26. Pinning decides *who* may answer; nothing here decided *what* they may say.
///
/// Each suite below is one boundary from that finding, and each carries the positive control
/// its negative test needs — a check that has never been made to fail is not a check
/// (**R2**), and one that fires on a correct relay gets deleted.
@Suite("Relay transport bounds", .serialized)
@MainActor
struct RelayTransportTests {

    // MARK: - Harness

    private func stubbedClient(callDeadline: TimeInterval = RelayClient.resourceTimeout,
                               jitterSeconds: Double = 0) -> RelayClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [TransportStub.self]
        return RelayClient(session: URLSession(configuration: configuration),
                           callDeadline: callDeadline,
                           jitter: { _ in jitterSeconds })
    }

    private func idempotentRequest(
        responseByteCeiling: Int = RelayClient.defaultResponseCeiling
    ) -> RelayRequest {
        RelayRequest(method: "GET", path: "/v1/messages", body: nil, contentType: nil,
                     bearerToken: "token", isIdempotent: true,
                     responseByteCeiling: responseByteCeiling)
    }

    /// Polls until `condition` holds, so a timing test waits for an observable fact rather
    /// than for a duration someone guessed.
    private func waitUntil(_ condition: @Sendable () -> Bool,
                           timeout: TimeInterval = 5) async -> Bool {
        let deadline = ContinuousClock.now.advanced(by: .seconds(timeout))
        while ContinuousClock.now < deadline {
            if condition() { return true }
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
        return condition()
    }

    private func withEngine<T>(_ body: (CryptoEngine) async throws -> T) async throws -> T {
        let container = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("transport-\(UUID().uuidString)", isDirectory: true)
        let engine = try await CryptoEngine.open(container: container)
        do {
            let result = try await body(engine)
            try? await engine.destroyAllState()
            try? FileManager.default.removeItem(at: container)
            return result
        } catch {
            try? await engine.destroyAllState()
            try? FileManager.default.removeItem(at: container)
            throw error
        }
    }

    // MARK: - The body is bounded where the bytes arrive

    @Test("a body over the ceiling is refused rather than buffered")
    func oversizedResponseIsRefused() async throws {
        let ceiling = 4096
        TransportStub.reset([.http(status: 200,
                                   body: Data(repeating: 0x41, count: ceiling + 1),
                                   headers: [:])])

        await #expect(throws: RelayClient.TransportError.responseTooLarge) {
            try await stubbedClient().send(idempotentRequest(responseByteCeiling: ceiling))
        }
        // Not retried: a relay that answers with too much answers with too much again, and
        // each attempt costs this device the same memory.
        #expect(TransportStub.received.count == 1)
    }

    @Test("a body exactly at the ceiling is accepted")
    func bodyAtTheCeilingIsAccepted() async throws {
        let ceiling = 4096
        TransportStub.reset([.http(status: 200,
                                   body: Data(repeating: 0x41, count: ceiling),
                                   headers: [:])])

        let response = try await stubbedClient()
            .send(idempotentRequest(responseByteCeiling: ceiling))
        #expect(response.status == 200)
        #expect(response.body.count == ceiling)
    }

    @Test("a declared Content-Length over the ceiling is refused before the body is read")
    func declaredContentLengthOverTheCeilingIsRefusedBeforeTheBody() async throws {
        // The body itself is far *under* the ceiling, so only the declared length can be what
        // refuses this — which is what makes the early-out observable rather than inferred.
        TransportStub.reset([.http(status: 200,
                                   body: Data(repeating: 0x41, count: 100),
                                   headers: ["Content-Length": "99999999"])])

        await #expect(throws: RelayClient.TransportError.responseTooLarge) {
            try await stubbedClient().send(idempotentRequest(responseByteCeiling: 1000))
        }
    }

    @Test("the fetch ceiling is derived from the relay's own batch and envelope limits")
    func fetchCeilingIsDerivedFromTheRelaysOwnLimits() {
        // One full batch of maximum-size envelopes must fit, or a legitimate fetch would be
        // refused — the failure mode a picked constant produces.
        let base64Envelope = 4 * ((RelayMailbox.maxEnvelopeBytes + 2) / 3)
        let fullBatch = RelayMailbox.maxFetchBatch * base64Envelope
        #expect(RelayClient.fetchResponseCeiling > fullBatch)

        // And it must still be a bound: comfortably under the memory a fetch may cost.
        #expect(RelayClient.fetchResponseCeiling < 12 * 1024 * 1024)

        // The ordinary ceiling is not the fetch one; every other endpoint answers small.
        #expect(RelayClient.defaultResponseCeiling < RelayClient.fetchResponseCeiling)
    }

    // MARK: - Redirects, and where pinning must stay

    @Test("the loader refuses to follow a redirect")
    func theLoaderRefusesToFollowARedirect() throws {
        let loader = BoundedResponseLoader(byteCeiling: 1024)
        let session = URLSession(configuration: .ephemeral)
        let task = session.dataTask(with: URLRequest(url: RelayEndpoint.baseURL))
        let response = try #require(HTTPURLResponse(
            url: RelayEndpoint.baseURL, statusCode: 302, httpVersion: "HTTP/1.1",
            headerFields: ["Location": "https://evil.example/v1/messages"]))

        var handed: URLRequest? = URLRequest(url: URL(string: "https://evil.example")!)
        loader.urlSession(session, task: task,
                          willPerformHTTPRedirection: response,
                          newRequest: URLRequest(url: URL(string: "https://evil.example")!)) {
            handed = $0
        }
        task.cancel()

        // Following it would re-send the bearer token to whatever host the relay named.
        #expect(handed == nil)
    }

    @Test("a redirect is not followed and the bearer token is not re-sent")
    func aRedirectIsNotFollowedAndTheTokenIsNotResent() async throws {
        TransportStub.reset([.redirect(to: "https://evil.example/v1/messages")])

        let response = try await stubbedClient().send(idempotentRequest())

        // The 3xx is handed back as an unrecognised status; every caller maps it to a
        // malformed response.
        #expect(response.status == 302)
        #expect(TransportStub.received.count == 1)
        let host = TransportStub.received.first?.url?.host
        #expect(host == RelayEndpoint.host)
    }

    @Test("the loader never handles an authentication challenge, so pinning keeps its one home")
    func theLoaderNeverHandlesAnAuthenticationChallenge() {
        let loader = BoundedResponseLoader(byteCeiling: 1024)

        // Every selector here is derived by the compiler from the protocol itself rather than
        // spelled as a string. A typed string is the classic vacuous negative: the ObjC names
        // are `didReceiveData:` and `didReceiveResponse:` where Swift says `didReceive:`, so a
        // hand-written `!responds(to:)` can pass because the selector does not exist at all.
        let sessionChallenge = #selector(URLSessionDelegate.urlSession(_:didReceive:completionHandler:))
        let taskChallenge = #selector(URLSessionTaskDelegate.urlSession(_:task:didReceive:completionHandler:))
        let redirect = #selector(URLSessionTaskDelegate.urlSession(_:task:willPerformHTTPRedirection:newRequest:completionHandler:))
        let receivedData = #selector(URLSessionDataDelegate.urlSession(_:dataTask:didReceive:) as (URLSessionDataDelegate) -> ((URLSession, URLSessionDataTask, Data) -> Void)?)
        let receivedResponse = #selector(URLSessionDataDelegate.urlSession(_:dataTask:didReceive:completionHandler:))

        // The negative: a task delegate implementing either challenge method would take that
        // dispatch away from `PinningSessionDelegate`, and the symptom would be a client that
        // still works — with no pinning.
        #expect(!loader.responds(to: sessionChallenge))
        #expect(!loader.responds(to: taskChallenge))

        // The positive controls. The first proves `sessionChallenge` names something that can
        // be responded to at all, so the assertion above is about the loader rather than about
        // a selector nothing implements; the rest are the methods URLSession must reach for
        // the ceiling and the redirect refusal to be applied to a live task.
        #expect(PinningSessionDelegate().responds(to: sessionChallenge))
        #expect(loader.responds(to: redirect))
        #expect(loader.responds(to: receivedData))
        #expect(loader.responds(to: receivedResponse))
    }

    // MARK: - Cancellation is not an attack

    @Test("cancelling during backoff is reported as cancellation, not as a TLS failure")
    func cancellationIsNotReportedAsATLSFailure() async throws {
        // 503 keeps the idempotent request retrying, so there is a backoff to cancel inside.
        TransportStub.reset([TransportStub.json(503, "{}")])
        let client = stubbedClient(jitterSeconds: 1.0)

        let task = Task { try await client.send(idempotentRequest()) }
        #expect(await waitUntil { TransportStub.received.count >= 1 })
        task.cancel()

        await #expect(throws: CancellationError.self) { try await task.value }
    }

    @Test("a refused pin is still reported as a secure-connection failure")
    func aRefusedPinIsStillReportedAsASecureConnectionFailure() async throws {
        // The pinner cancels the challenge, which arrives as `URLError.cancelled` — the same
        // code our own cancellation produces. This is the conflation the fix must not break.
        TransportStub.reset([.failure(.cancelled)])

        await #expect(throws: RelayClient.TransportError.secureConnectionFailed) {
            try await stubbedClient().send(idempotentRequest())
        }
    }

    @Test("cancellation survives the mailbox's error mapping")
    func cancellationSurvivesTheMailboxErrorMapping() async throws {
        TransportStub.reset([TransportStub.json(503, "{}")])
        let mailbox = RelayMailbox(client: stubbedClient(jitterSeconds: 1.0))

        let task = Task { try await mailbox.fetch(token: "token") }
        #expect(await waitUntil { TransportStub.received.count >= 1 })
        task.cancel()

        // Not `.unreachable`: the relay was reachable and the user simply left.
        await #expect(throws: CancellationError.self) { try await task.value }
    }

    // MARK: - One deadline for the whole call

    @Test("the whole call is bounded by one deadline across attempts")
    func theWholeCallIsBoundedByOneDeadline() async throws {
        TransportStub.reset([TransportStub.json(503, "{}")])
        let client = stubbedClient(callDeadline: 0.3, jitterSeconds: 0.2)

        await #expect(throws: RelayClient.TransportError.exhaustedRetries(lastStatus: 503)) {
            try await client.send(idempotentRequest())
        }
        // Fewer than `maxAttempts`: the budget ran out first, which is the property.
        #expect(TransportStub.received.count < RelayClient.maxAttempts)
    }

    @Test("with budget to spare, every attempt is made")
    func withoutTheDeadlineEveryAttemptIsMade() async throws {
        TransportStub.reset([TransportStub.json(503, "{}")])
        let client = stubbedClient(callDeadline: 60, jitterSeconds: 0)

        await #expect(throws: RelayClient.TransportError.exhaustedRetries(lastStatus: 503)) {
            try await client.send(idempotentRequest())
        }
        // The positive control for the test above: without the deadline cutting it short the
        // same stub produces the full three attempts, so that test is measuring the deadline
        // and not some other refusal.
        #expect(TransportStub.received.count == RelayClient.maxAttempts)
    }

    @Test("an attempt's timeout is clamped to what is left of the deadline")
    func anAttemptTimeoutIsClampedToWhatIsLeftOfTheDeadline() async throws {
        TransportStub.reset([TransportStub.json(200, "{}")])
        let client = stubbedClient(callDeadline: 0.5, jitterSeconds: 0)

        _ = try await client.send(idempotentRequest())

        let sent = try #require(TransportStub.received.first)
        // Otherwise a call could start a 30-second request one second before its own ceiling,
        // and `resourceTimeout` would name a bound the code does not have.
        #expect(sent.timeoutInterval <= 0.5)
        #expect(sent.timeoutInterval < RelayClient.requestTimeout)
    }

    // MARK: - Retry-After

    @Test("Retry-After is found whatever the relay capitalised it as")
    func retryAfterIsFoundWhateverTheRelayCapitalisedIt() {
        // Asserted on `Response` directly and deliberately not end to end: `HTTPURLResponse`
        // canonicalises header names, so a stub-driven test would pass against the
        // case-sensitive lookup too and prove nothing (**R2**). The lowercased store plus this
        // accessor is the control; the platform's canonicalisation is not something this code
        // gets to depend on.
        let response = RelayClient.Response(
            status: 429, body: Data(), headers: ["retry-after": "30"])

        #expect(response.header("Retry-After") == "30")
        #expect(response.header("RETRY-AFTER") == "30")
        #expect(response.header("retry-after") == "30")
        #expect(response.header("X-Absent") == nil)
    }

    // MARK: - The base must be a bare origin, and the request must stay on it

    @Test("a base URL carrying credentials is refused")
    func aBaseURLCarryingCredentialsIsRefused() throws {
        // URLSession turns these into an `Authorization: Basic` header, which displaces the
        // bearer token — the request would go out unauthenticated.
        let base = try #require(URL(string: "https://user:pass@relay.mgchatman.app"))
        #expect(throws: RelayRequest.BuildError.malformedBaseURL) {
            try RelayRequest.requireBareOrigin(base)
        }
    }

    @Test("a base URL carrying a port is refused")
    func aBaseURLCarryingAPortIsRefused() throws {
        // The pin is keyed by host, so `host:8443` stays pinned while reaching another service.
        let base = try #require(URL(string: "https://relay.mgchatman.app:8443"))
        #expect(throws: RelayRequest.BuildError.malformedBaseURL) {
            try RelayRequest.requireBareOrigin(base)
        }
    }

    @Test("a base URL carrying a path, query or fragment is refused")
    func aBaseURLCarryingAPathQueryOrFragmentIsRefused() throws {
        for raw in ["https://relay.mgchatman.app/v2",
                    "https://relay.mgchatman.app/?k=v",
                    "https://relay.mgchatman.app/#f",
                    "http://relay.mgchatman.app"] {
            let base = try #require(URL(string: raw))
            #expect(throws: RelayRequest.BuildError.malformedBaseURL) {
                try RelayRequest.requireBareOrigin(base)
            }
        }
    }

    @Test("a bare https origin is accepted")
    func aBareHTTPSOriginIsAccepted() throws {
        // The positive control: the checks above must not be refusing everything, and the
        // shipping constant must satisfy them.
        try RelayRequest.requireBareOrigin(RelayEndpoint.baseURL)
        try RelayRequest.requireBareOrigin(
            try #require(URL(string: "https://relay.mgchatman.app/")))

        let request = try RelayRequest(method: "GET", path: "/v1/messages", isIdempotent: true)
            .urlRequest(relativeTo: RelayEndpoint.baseURL)
        #expect(request.url?.absoluteString == "https://relay.mgchatman.app/v1/messages")
    }

    @Test("a non-bare base URL is refused when a request is composed against it")
    func aNonBareBaseIsRefusedWhenTheRequestIsComposed() throws {
        // The three tests above exercise `requireBareOrigin` directly, which says nothing
        // about whether anything calls it — deleting the call site left every one of them
        // green. This one goes through the composition path, so the wiring is the property.
        for raw in ["https://user:pass@relay.mgchatman.app",
                    "https://relay.mgchatman.app:8443",
                    "https://relay.mgchatman.app/v2"] {
            let base = try #require(URL(string: raw))
            #expect(throws: RelayRequest.BuildError.malformedBaseURL) {
                try RelayRequest(method: "GET", path: "/v1/messages", isIdempotent: true)
                    .urlRequest(relativeTo: base)
            }
        }
    }

    @Test("a relative or traversing request path is refused")
    func aRelativeOrTraversingPathIsRefused() throws {
        for path in ["v1/messages", "/v1/../../admin", "../v1/messages", ""] {
            #expect(throws: RelayRequest.BuildError.insecureOrMalformedURL) {
                try RelayRequest(method: "GET", path: path, isIdempotent: true)
                    .urlRequest(relativeTo: RelayEndpoint.baseURL)
            }
        }
    }

    @Test("a request path that resolves to another origin is refused")
    func aPathThatResolvesToAnotherOriginIsRefused() throws {
        // `URL(string:relativeTo:)` resolves each of these off the pinned host, where these
        // pins say nothing.
        for path in ["//evil.example/v1", "https://evil.example/v1"] {
            #expect(throws: RelayRequest.BuildError.insecureOrMalformedURL) {
                try RelayRequest(method: "GET", path: path, isIdempotent: true)
                    .urlRequest(relativeTo: RelayEndpoint.baseURL)
            }
        }
    }

    // MARK: - A fetch batch has a shape

    private func envelopeJSON(_ entries: [(String, Data)], more: Bool = false) -> String {
        let messages = entries.map {
            "{\"id\":\"\($0.0)\",\"envelope\":\"\($0.1.base64EncodedString())\"}"
        }
        return "{\"messages\":[\(messages.joined(separator: ","))],\"more\":\(more)}"
    }

    private func validEnvelope() -> Data {
        Data(repeating: 0x42, count: RelayMailbox.minEnvelopeBytes)
    }

    @Test("a batch larger than the relay's own cap is refused")
    func aBatchLargerThanTheRelaysCapIsRefused() async throws {
        let entries = (0...RelayMailbox.maxFetchBatch).map {
            (UUID(uuidString: String(format: "00000000-0000-4000-8000-%012d", $0))!.uuidString.lowercased(),
             validEnvelope())
        }
        TransportStub.reset([TransportStub.json(200, envelopeJSON(entries))])

        await #expect(throws: RelayMailbox.Failure.malformedResponse) {
            try await RelayMailbox(client: stubbedClient()).fetch(token: "token")
        }
    }

    @Test("a repeated message id in one batch is refused")
    func aRepeatedMessageIdInOneBatchIsRefused() async throws {
        // Acknowledgement addresses an id. Two entries under one id means acknowledging one
        // silently discards the other, and the relay has already deleted it.
        let id = UUID().uuidString.lowercased()
        TransportStub.reset([TransportStub.json(
            200, envelopeJSON([(id, validEnvelope()), (id, validEnvelope())]))])

        await #expect(throws: RelayMailbox.Failure.malformedResponse) {
            try await RelayMailbox(client: stubbedClient()).fetch(token: "token")
        }
    }

    @Test("an envelope outside the relay's stored size range is refused")
    func anEnvelopeOutsideTheStoredSizeRangeIsRefused() async throws {
        for count in [RelayMailbox.minEnvelopeBytes - 1, RelayMailbox.maxEnvelopeBytes + 1] {
            let entry = (UUID().uuidString.lowercased(), Data(repeating: 0x42, count: count))
            TransportStub.reset([TransportStub.json(200, envelopeJSON([entry]))])

            await #expect(throws: RelayMailbox.Failure.malformedResponse) {
                try await RelayMailbox(client: stubbedClient()).fetch(
                    token: "token")
            }
        }
    }

    @Test("a well-formed batch is accepted")
    func aWellFormedBatchIsAccepted() async throws {
        // The positive control for the three refusals above: a batch at the relay's own limits
        // must still arrive, or the bound is refusing correct traffic.
        let entries = (0..<RelayMailbox.maxFetchBatch).map {
            (UUID(uuidString: String(format: "00000000-0000-4000-8000-%012d", $0))!.uuidString.lowercased(),
             Data(repeating: 0x42, count: RelayMailbox.maxEnvelopeBytes))
        }
        TransportStub.reset([TransportStub.json(200, envelopeJSON(entries, more: true))])

        let batch = try await RelayMailbox(client: stubbedClient()).fetch(token: "token")
        #expect(batch.messages.count == RelayMailbox.maxFetchBatch)
        #expect(batch.more)
    }

    // MARK: - An acknowledgement has a shape

    @Test("an acknowledgement over the relay's cap never leaves the device")
    func anOversizedAcknowledgementNeverLeavesTheDevice() async throws {
        TransportStub.reset([TransportStub.json(200, #"{"acknowledged":0}"#)])
        let ids = (0...RelayMailbox.maxAcknowledgeBatch).map { _ in UUID() }

        await #expect(throws: RelayMailbox.Failure.rejected) {
            try await RelayMailbox(client: stubbedClient())
                .acknowledge(ids: ids, token: "token")
        }
        #expect(TransportStub.received.isEmpty)
    }

    @Test("an acknowledged count above what was asked is refused")
    func anAcknowledgedCountAboveWhatWasAskedIsRefused() async throws {
        TransportStub.reset([TransportStub.json(200, #"{"acknowledged":5}"#)])

        await #expect(throws: RelayMailbox.Failure.malformedResponse) {
            try await RelayMailbox(client: stubbedClient())
                .acknowledge(ids: [UUID(), UUID()], token: "token")
        }
    }

    @Test("an acknowledged count within what was asked is accepted")
    func anAcknowledgedCountWithinWhatWasAskedIsAccepted() async throws {
        // Fewer than asked is normal — a repeat, or a TTL sweep that got there first.
        TransportStub.reset([TransportStub.json(200, #"{"acknowledged":1}"#)])

        let acknowledged = try await RelayMailbox(client: stubbedClient())
            .acknowledge(ids: [UUID(), UUID()], token: "token")
        #expect(acknowledged == 1)
    }

    // MARK: - A publication reports a pool

    @Test("a publication reporting an empty pool after an upload is refused")
    func aPublicationReportingAnEmptyPoolIsRefused() async throws {
        try await withEngine { engine in
            let keys = try await engine.generatePublishedKeys(oneTimeCount: 4)
            TransportStub.reset([TransportStub.json(
                200, #"{"one_time_prekeys":0,"kyber_prekeys":4}"#)])

            await #expect(throws: RelayKeyDirectory.Failure.malformedResponse) {
                try await RelayKeyDirectory(client: stubbedClient())
                    .publish(keys, token: "token")
            }
        }
    }

    @Test("a publication reporting a plausible pool is accepted")
    func aPublicationReportingAPlausiblePoolIsAccepted() async throws {
        // The positive control. Deliberately *fewer* than were uploaded: the relay counts
        // after the publish transaction commits, so a peer dispensing one in between is
        // legitimate and a stricter gate would fail a correct publication (**R2**).
        try await withEngine { engine in
            let keys = try await engine.generatePublishedKeys(oneTimeCount: 4)
            TransportStub.reset([TransportStub.json(
                200, #"{"one_time_prekeys":1,"kyber_prekeys":1}"#)])

            let counts = try await RelayKeyDirectory(client: stubbedClient())
                .publish(keys, token: "token")
            #expect(TransportStub.received.count == 1)
            // The counts are returned rather than dropped: they are the only view this device
            // has of the *relay-side* pool, which is the one a drain empties, and P6.S01's
            // replenishment threshold is read from them.
            #expect(counts == RelayKeyDirectory.PoolCounts(oneTimePreKeys: 1, kyberPreKeys: 1))
        }
    }

    // MARK: - An invite code is checked before it is spent

    @Test("an invite code is normalised the way the relay normalises it")
    func anInviteCodeIsNormalisedTheWayTheRelayNormalisesIt() {
        let canonical = "ABCDEFGHJKMNPQRSTVWXYZ0123"

        #expect(InviteCode(canonical)?.canonical == canonical)
        // Separators are how the code is shown and read aloud.
        #expect(InviteCode("abcde-fghjk-mnpqr-stvwx-yz012-3")?.canonical == canonical)
        #expect(InviteCode("  ABCDE FGHJK MNPQR STVWX YZ012 3 ")?.canonical == canonical)

        // Crockford's transcription rules, accepted on input only: I and L are a written 1,
        // O is a written 0. A mirror that only checked membership of the alphabet would
        // refuse each of these — and refuse a code the relay would have taken.
        #expect(InviteCode("I2345678901234567890123456")?.canonical == "12345678901234567890123456")
        #expect(InviteCode("l2345678901234567890123456")?.canonical == "12345678901234567890123456")
        #expect(InviteCode("O2345678901234567890123456")?.canonical == "02345678901234567890123456")
    }

    @Test("a code of the wrong length or with an excluded symbol is refused")
    func anInviteCodeWithAnExcludedSymbolIsRefused() {
        // U is excluded from Crockford base32 and, unlike I/L/O, is not remapped.
        #expect(InviteCode("U2345678901234567890123456") == nil)
        #expect(InviteCode("ABCDEFGHJKMNPQRSTVWXYZ012") == nil)   // one short
        #expect(InviteCode("ABCDEFGHJKMNPQRSTVWXYZ01234") == nil) // one long
        #expect(InviteCode("") == nil)
        #expect(InviteCode("   ") == nil)
        #expect(InviteCode("ABCDE_FGHJK_MNPQR_STVWX_YZ012_3") == nil)
    }

    @Test("a malformed invite code never spends a redemption attempt")
    func aMalformedInviteCodeNeverSpendsARedemptionAttempt() async throws {
        try await withEngine { engine in
            TransportStub.reset([TransportStub.json(201, "{}")])

            await #expect(throws: InviteRedemption.Failure.refused) {
                try await InviteRedemption(client: stubbedClient())
                    .redeem(code: "NOT-A-CODE", using: engine)
            }
            // `POST /v1/invite/redeem` is 5/hour/IP and is the only flow an unauthenticated
            // install has: four typos would otherwise cost an hour of onboarding.
            #expect(TransportStub.received.isEmpty)
        }
    }
}
