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

/// AUDIT 5.26 — what the pinned client does with a hostile *answer*, as opposed to a hostile
/// certificate.
///
/// Pinning decides who may speak. Everything here is about what they are then allowed to say:
/// how many bytes, where the request may be sent, how long the call may take, and which
/// response shapes are arithmetic this relay can actually do. Each check has a positive
/// control in the same suite, because "refused" and "broken" produce the same green.
///
/// The stub is a `URLProtocol` of its own rather than `StubRelay` or `RoutedStubRelay`: those
/// carry static state, Swift Testing runs suites in parallel, and a shared static reply queue
/// between two suites is a flake nobody would attribute to the right cause.
final class TransportStub: URLProtocol, @unchecked Sendable {

    struct Reply: Sendable {
        let status: Int
        let body: Data
        let headers: [String: String]

        init(status: Int = 200, json: String = "{}", headers: [String: String] = [:]) {
            self.status = status
            self.body = Data(json.utf8)
            self.headers = headers
        }

        init(status: Int = 200, body: Data, headers: [String: String] = [:]) {
            self.status = status
            self.body = body
            self.headers = headers
        }
    }

    /// Replies are handed out in order; the last one repeats once exhausted.
    nonisolated(unsafe) private static var replies: [Reply] = []
    nonisolated(unsafe) private static var received: [URL] = []
    private static let lock = NSLock()

    static func reset(_ replies: [Reply]) {
        lock.withLock {
            self.replies = replies
            self.received = []
        }
    }

    static var requestedURLs: [URL] { lock.withLock { received } }
    static var requestCount: Int { requestedURLs.count }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let reply = Self.lock.withLock { () -> Reply in
            if let url = request.url { Self.received.append(url) }
            return Self.replies.count > 1
                ? Self.replies.removeFirst()
                : (Self.replies.first ?? Reply(status: 500))
        }

        let response = HTTPURLResponse(url: request.url!,
                                       statusCode: reply.status,
                                       httpVersion: "HTTP/1.1",
                                       headerFields: reply.headers)!

        // A `URLProtocol` must *signal* a redirect; returning a 3xx as an ordinary response is
        // just a 3xx, and `URLSession` never asks its delegate about it. The first version of
        // this stub did exactly that, which made the redirect test pass against a client that
        // followed redirects — caught only because that test has a positive control.
        if (300...399).contains(reply.status),
           let location = reply.headers.first(where: { $0.key.lowercased() == "location" })?.value,
           let target = URL(string: location, relativeTo: request.url)?.absoluteURL {
            var redirected = request
            redirected.url = target
            client?.urlProtocol(self, wasRedirectedTo: redirected, redirectResponse: response)
            // And then deliver it as an ordinary response, because a declined redirect has to
            // complete somehow. `URLSession`'s documented behaviour when a delegate passes nil
            // is to hand back the redirect response itself; a real server does that by having
            // already sent it. A stub that only signalled the redirect would leave the task
            // hanging until the request timeout, which reads as a network fault rather than
            // as a refusal. If the redirect *is* followed, a new protocol instance serves it
            // and these bytes are discarded.
        }

        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: reply.body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

@Suite("Relay transport bounds", .serialized)
struct RelayTransportTests {

    private static func configuration() -> URLSessionConfiguration {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [TransportStub.self]
        return configuration
    }

    private static func client(
        resourceTimeout: TimeInterval = RelayClient.resourceTimeout,
        jitter: @escaping @Sendable (ClosedRange<Double>) -> Double = { _ in 0 }
    ) -> RelayClient {
        RelayClient(session: URLSession(configuration: configuration()),
                    resourceTimeout: resourceTimeout,
                    jitter: jitter)
    }

    private static func request(
        path: String = "/v1/messages",
        isIdempotent: Bool = true,
        maxResponseBytes: Int = RelayClient.defaultMaxResponseBytes
    ) -> RelayRequest {
        RelayRequest(method: "GET", path: path, body: nil, contentType: nil,
                     bearerToken: "t", isIdempotent: isIdempotent,
                     maxResponseBytes: maxResponseBytes)
    }

    // MARK: - The origin every request is resolved against

    @Test("the shipping base URL is a bare origin — the positive control for every check below")
    func theShippingBaseURLIsABareOrigin() throws {
        // Without this, a guard that refused *everything* would make the whole origin section
        // green while breaking every real request.
        #expect(RelayEndpoint.isBareOrigin(RelayEndpoint.baseURL))

        let built = try Self.request(path: "/v1/messages")
            .urlRequest(relativeTo: RelayEndpoint.baseURL)
        #expect(built.url?.absoluteString == "https://\(RelayEndpoint.host)/v1/messages")
    }

    @Test("a base URL carrying credentials is refused")
    func credentialsInTheBaseAreRefused() {
        // URLSession turns these into an `Authorization: Basic` header — a secret on the wire
        // that also displaces the bearer token the request authenticates with.
        let base = URL(string: "https://user:secret@\(RelayEndpoint.host)")!
        #expect(!RelayEndpoint.isBareOrigin(base))
        #expect(throws: RelayRequest.BuildError.insecureOrMalformedURL) {
            _ = try Self.request().urlRequest(relativeTo: base)
        }
    }

    @Test("a base URL carrying a port is refused")
    func aPortInTheBaseIsRefused() {
        // The pin is keyed by host, so this stays pinned while reaching a different service.
        let base = URL(string: "https://\(RelayEndpoint.host):8443")!
        #expect(!RelayEndpoint.isBareOrigin(base))
        #expect(throws: RelayRequest.BuildError.insecureOrMalformedURL) {
            _ = try Self.request().urlRequest(relativeTo: base)
        }
    }

    @Test("a base URL carrying a path, query or fragment is refused")
    func aNonBarePathQueryOrFragmentIsRefused() {
        for raw in ["https://\(RelayEndpoint.host)/api",
                    "https://\(RelayEndpoint.host)?k=v",
                    "https://\(RelayEndpoint.host)#f",
                    "http://\(RelayEndpoint.host)"] {
            let base = URL(string: raw)!
            #expect(!RelayEndpoint.isBareOrigin(base), "\(raw) was accepted as an origin")
            #expect(throws: RelayRequest.BuildError.insecureOrMalformedURL) {
                _ = try Self.request().urlRequest(relativeTo: base)
            }
        }
    }

    @Test("a path that leaves the pinned origin is refused")
    func aPathLeavingTheOriginIsRefused() {
        for path in ["//evil.example/v1/messages",          // protocol-relative
                     "http://\(RelayEndpoint.host)/v1",     // scheme downgrade
                     "https://evil.example/v1",             // another host entirely
                     "https://u:p@\(RelayEndpoint.host)/v1", // credentials via the path
                     "https://\(RelayEndpoint.host):8443/v1", // a port via the path
                     "/v1/../../v1/messages",               // traversal
                     "v1/messages"] {                       // relative to the base's directory
            #expect(throws: RelayRequest.BuildError.insecureOrMalformedURL) {
                _ = try Self.request(path: path).urlRequest(relativeTo: RelayEndpoint.baseURL)
            }
        }
    }

    // MARK: - The body ceiling

    @Test("a response over the ceiling is refused rather than buffered")
    func anOversizedResponseIsRefused() async throws {
        // Both halves of the ceiling. A declared `Content-Length` is refused before any body
        // arrives; a response that declares nothing — which is what a chunked reply does, and
        // what a flood would be — is refused by counting what actually arrives. Testing only
        // the first would leave the case that matters unexercised.
        for headers in [["Content-Length": "4096"], [:]] {
            TransportStub.reset([
                .init(body: Data(repeating: 0x41, count: 4096), headers: headers),
            ])

            await #expect(throws: RelayClient.TransportError.responseTooLarge) {
                try await Self.client().send(Self.request(maxResponseBytes: 1024))
            }
        }
    }

    @Test("a response at the ceiling is accepted — the positive control")
    func aResponseAtTheCeilingIsAccepted() async throws {
        // Off-by-one in the other direction would refuse every real fetch, and a refusal that
        // refuses everything passes the test above.
        TransportStub.reset([.init(body: Data(repeating: 0x41, count: 1024))])

        let response = try await Self.client().send(Self.request(maxResponseBytes: 1024))
        #expect(response.status == 200)
        #expect(response.body.count == 1024)
    }

    @Test("an oversized response is not retried")
    func anOversizedResponseIsNotRetried() async throws {
        // It is not transient: the same relay answers the same way, and three attempts at
        // buffering a flood is three floods.
        TransportStub.reset([.init(body: Data(repeating: 0x41, count: 4096))])

        _ = try? await Self.client().send(Self.request(maxResponseBytes: 1024))
        #expect(TransportStub.requestCount == 1)
    }

    // MARK: - Redirects

    @Test("a redirect is not followed")
    func aRedirectIsNotFollowed() async throws {
        TransportStub.reset([
            .init(status: 302, headers: ["Location": "https://evil.example/v1/messages"]),
            .init(status: 200, json: #"{"messages":[],"more":false}"#),
        ])

        let response = try await Self.client().send(Self.request())

        #expect(response.status == 302, "the 3xx must be handed back, not followed")
        #expect(TransportStub.requestCount == 1)
        #expect(TransportStub.requestedURLs.allSatisfy { $0.host == RelayEndpoint.host })
    }

    @Test("the same redirect IS followed by default handling — the positive control")
    func theStubRedirectIsFollowedWithoutTheRefusal() async throws {
        // Without this the test above would also pass against a stub that never produced a
        // followable redirect at all, which is the R2 shape: a check that cannot fail.
        TransportStub.reset([
            .init(status: 302, headers: ["Location": "https://\(RelayEndpoint.host)/v1/other"]),
            .init(status: 200, json: #"{"ok":true}"#),
        ])

        let session = URLSession(configuration: Self.configuration())
        let (_, response) = try await session.data(
            from: URL(string: "https://\(RelayEndpoint.host)/v1/messages")!)

        #expect((response as? HTTPURLResponse)?.statusCode == 200)
        #expect(TransportStub.requestCount == 2, "the stub did not produce a real redirect")
    }

    // MARK: - Retry-After, whatever the relay capitalises it as

    @Test("Retry-After is honoured however the relay capitalised it")
    func retryAfterIsHonouredWhateverTheCase() async throws {
        // `HTTPURLResponse` reports field names as the server spelled them, so the client
        // stores them lowercased and looks them up lowercased. Both spellings are tested
        // because only one of them can catch a half-fix: with the names left as sent, a lookup
        // that lowercases the query finds `retry-after` and misses `Retry-After`.
        for name in ["Retry-After", "retry-after", "RETRY-AFTER"] {
            TransportStub.reset([
                .init(status: 429, headers: [name: "0.6"]),
                .init(status: 200),
            ])

            let started = ContinuousClock.now
            _ = try await Self.client().send(Self.request())
            let elapsed = started.duration(to: .now)

            #expect(elapsed > .milliseconds(400), "\(name) was ignored")
        }
    }

    @Test("no retry-after means no extra wait — the positive control")
    func withoutARetryAfterThereIsNoWait() async throws {
        // Proves the timing above measures the header and not the retry loop itself.
        TransportStub.reset([.init(status: 429), .init(status: 200)])

        let started = ContinuousClock.now
        _ = try await Self.client().send(Self.request())
        let elapsed = started.duration(to: .now)

        #expect(elapsed < .milliseconds(400))
    }

    // MARK: - The whole-call deadline

    @Test("the whole call, not just one attempt, is bounded")
    func theWholeCallIsBounded() async throws {
        // `timeoutIntervalForResource` bounds one URLSessionTask; this client makes up to
        // three, with a backoff between each.
        TransportStub.reset([.init(status: 503)])

        await #expect(throws: RelayClient.TransportError.deadlineExceeded) {
            try await Self.client(resourceTimeout: 0.25, jitter: { _ in 0.2 })
                .send(Self.request())
        }
    }

    @Test("with budget to spare the same call exhausts its retries — the positive control")
    func withBudgetTheCallExhaustsRetriesInstead() async throws {
        // Without this, a deadline that fired immediately would pass the test above while
        // making every request fail.
        TransportStub.reset([.init(status: 503)])

        await #expect(throws: RelayClient.TransportError.exhaustedRetries(lastStatus: 503)) {
            try await Self.client().send(Self.request())
        }
        #expect(TransportStub.requestCount == RelayClient.maxAttempts)
    }

    // MARK: - Cancellation is not a pin failure

    @Test("a call cancelled during backoff reports cancellation, not a TLS failure")
    func cancellationDuringBackoffIsNotReportedAsTLS() async throws {
        // The bug: the backoff swallowed cancellation with `try?`, the request then failed as
        // `URLError.cancelled`, and `classify` maps that to `secureConnectionFailed` because
        // that is also how a refused pin arrives. A user leaving a screen was told the
        // connection had been attacked.
        TransportStub.reset([.init(status: 503)])
        let client = Self.client(jitter: { _ in 5 })

        let task = Task { try await client.send(Self.request()) }
        try await Task.sleep(nanoseconds: 200_000_000)
        task.cancel()

        await #expect(throws: CancellationError.self) { try await task.value }
    }

    // MARK: - Fetch: what a batch may contain

    private static func mailbox() -> RelayMailbox { RelayMailbox(client: client()) }

    private static func fetchBody(_ entries: [(id: String, envelope: Data)]) -> String {
        let messages = entries.map {
            #"{"id":"\#($0.id)","envelope":"\#($0.envelope.base64EncodedString())"}"#
        }
        return #"{"messages":[\#(messages.joined(separator: ","))],"more":false}"#
    }

    private static func envelope(_ count: Int) -> Data { Data(repeating: 0x7A, count: count) }

    @Test("a well-formed batch is accepted — the positive control for the four checks below")
    func aWellFormedBatchIsAccepted() async throws {
        let entries = (0..<3).map {
            (id: UUID().uuidString.lowercased(),
             envelope: Self.envelope(RelayMailbox.minEnvelopeBytes + $0))
        }
        TransportStub.reset([.init(json: Self.fetchBody(entries))])

        let batch = try await Self.mailbox().fetch(token: "t")
        #expect(batch.messages.count == 3)
        #expect(!batch.more)
    }

    @Test("a batch longer than the relay's own cap is refused")
    func anOverlongBatchIsRefused() async throws {
        let entries = (0...RelayMailbox.maxFetchBatch).map { _ in
            (id: UUID().uuidString.lowercased(), envelope: Self.envelope(64))
        }
        TransportStub.reset([.init(json: Self.fetchBody(entries))])

        await #expect(throws: RelayMailbox.Failure.malformedResponse) {
            try await Self.mailbox().fetch(token: "t")
        }
    }

    @Test("a repeated message id in one batch is refused")
    func duplicateIdsAreRefused() async throws {
        let id = UUID().uuidString.lowercased()
        TransportStub.reset([.init(json: Self.fetchBody([
            (id: id, envelope: Self.envelope(64)),
            (id: id, envelope: Self.envelope(65)),
        ]))])

        await #expect(throws: RelayMailbox.Failure.malformedResponse) {
            try await Self.mailbox().fetch(token: "t")
        }
    }

    @Test("an envelope outside the relay's own size bounds is refused")
    func anEnvelopeOutsideTheStoreBoundsIsRefused() async throws {
        for count in [RelayMailbox.minEnvelopeBytes - 1, RelayMailbox.maxEnvelopeBytes + 1] {
            TransportStub.reset([.init(json: Self.fetchBody([
                (id: UUID().uuidString.lowercased(), envelope: Self.envelope(count)),
            ]))])

            await #expect(throws: RelayMailbox.Failure.malformedResponse) {
                try await Self.mailbox().fetch(token: "t")
            }
        }
    }

    @Test("a fetch response beyond a full batch of full envelopes is refused unread")
    func aFloodedFetchResponseIsRefused() async throws {
        // Asserted at the transport layer on purpose. `RelayMailbox` maps `responseTooLarge`
        // onto `malformedResponse`, and JSON that is 10 MiB of spaces fails to decode as
        // `malformedResponse` too — so a mailbox-level assertion here would pass just as
        // happily against no ceiling at all. The ceiling is derived from the relay's own batch
        // and envelope limits, so nothing legitimate reaches it.
        TransportStub.reset([
            .init(body: Data(repeating: 0x20, count: RelayMailbox.maxFetchResponseBytes + 1)),
        ])

        await #expect(throws: RelayClient.TransportError.responseTooLarge) {
            try await Self.client().send(
                Self.request(maxResponseBytes: RelayMailbox.maxFetchResponseBytes))
        }
    }

    @Test("an oversized answer is reported as a malformed response, not as an outage")
    func anOversizedAnswerIsNotReportedAsUnreachable() async throws {
        // The relay answered. Telling the user to check their connection would send them to
        // look at the one thing that is working.
        TransportStub.reset([
            .init(body: Data(repeating: 0x20, count: RelayMailbox.maxFetchResponseBytes + 1)),
        ])

        await #expect(throws: RelayMailbox.Failure.malformedResponse) {
            try await Self.mailbox().fetch(token: "t")
        }
    }

    // MARK: - Header names

    @Test("a header is found whatever case the caller asks for")
    func theHeaderLookupIsCaseInsensitive() {
        // Half of the property: names are stored lowercased, so the *query* must be too.
        // HTTP field names are case-insensitive (RFC 9110 §5.1) and nothing stops a relay
        // from picking a spelling.
        let response = RelayClient.Response(
            status: 429, body: Data(), headers: ["retry-after": "7"])

        #expect(response.header("Retry-After") == "7")
        #expect(response.header("RETRY-AFTER") == "7")
        #expect(response.header("retry-after") == "7")
        #expect(response.header("absent") == nil)
    }

    // MARK: - Acknowledgement counts

    @Test("an acknowledgement count above what was asked is refused")
    func anImpossibleAcknowledgementCountIsRefused() async throws {
        TransportStub.reset([.init(json: #"{"acknowledged":5}"#)])

        await #expect(throws: RelayMailbox.Failure.malformedResponse) {
            _ = try await Self.mailbox().acknowledge(ids: [UUID()], token: "t")
        }
    }

    @Test("a plausible acknowledgement count is accepted — the positive control")
    func aPlausibleAcknowledgementCountIsAccepted() async throws {
        TransportStub.reset([.init(json: #"{"acknowledged":1}"#)])

        let count = try await Self.mailbox().acknowledge(ids: [UUID(), UUID()], token: "t")
        #expect(count == 1, "fewer than asked for is normal — a repeat, or a TTL sweep")
    }

    @Test("an oversized acknowledgement batch never reaches the relay")
    func anOversizedAcknowledgementIsRefusedLocally() async throws {
        TransportStub.reset([.init(json: #"{"acknowledged":0}"#)])
        let ids = (0...RelayMailbox.maxAcknowledgeBatch).map { _ in UUID() }

        await #expect(throws: RelayMailbox.Failure.rejected) {
            _ = try await Self.mailbox().acknowledge(ids: ids, token: "t")
        }
        #expect(TransportStub.requestCount == 0,
                "a request certain to be refused still spends a rate-limit token")
    }

    // MARK: - Publication results

    private static func publishedKeys() async throws -> PublishedKeys {
        let container = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("relay-transport-\(UUID().uuidString)", isDirectory: true)
        let engine = try await CryptoEngine.open(container: container)
        return try await engine.generatePublishedKeys(oneTimeCount: 2)
    }

    @Test("a publication reporting an empty pool is refused")
    func anEmptyPoolAfterPublishingIsRefused() async throws {
        // The failure this prevents: the app records that it has published and stops
        // publishing (6/day), while every peer's bundle fetch 404s. Nothing else in the
        // response says whether the upload landed.
        TransportStub.reset([.init(json: #"{"one_time_prekeys":0,"kyber_prekeys":0}"#)])

        await #expect(throws: RelayKeyDirectory.Failure.malformedResponse) {
            try await RelayKeyDirectory(client: Self.client())
                .publish(try await Self.publishedKeys(), token: "t")
        }
    }

    @Test("a publication reporting a pool is accepted — the positive control")
    func aReportedPoolIsAccepted() async throws {
        // Deliberately *fewer* than were uploaded: the relay counts after the publish
        // transaction commits, so a peer dispensing one in between is legitimate and must not
        // fail the publication (AUDIT R2 — a gate that cries wolf gets deleted).
        TransportStub.reset([.init(json: #"{"one_time_prekeys":1,"kyber_prekeys":1}"#)])

        try await RelayKeyDirectory(client: Self.client())
            .publish(try await Self.publishedKeys(), token: "t")
    }

    @Test("a publication result that is not a count is refused")
    func anAbsurdPoolCountIsRefused() async throws {
        for json in [#"{"one_time_prekeys":-1,"kyber_prekeys":1}"#,
                     #"{"one_time_prekeys":1,"kyber_prekeys":9999999}"#,
                     #"{}"#] {
            TransportStub.reset([.init(json: json)])

            await #expect(throws: RelayKeyDirectory.Failure.malformedResponse) {
                try await RelayKeyDirectory(client: Self.client())
                    .publish(try await Self.publishedKeys(), token: "t")
            }
        }
    }

    // MARK: - Invite codes

    @Test("a code that cannot be valid never spends a rate-limit token")
    func anImpossibleCodeIsRefusedLocally() async throws {
        // `POST /v1/invite/redeem` is 5/hour/IP and is the relay's only per-IP control
        // (AUDIT 5.15). Four typos would lock the user out of the one flow they have.
        TransportStub.reset([.init(status: 201)])

        for code in ["", "   ", "GOOD-CODE", "ABCDE", String(repeating: "A", count: 27),
                     "ABCDEFGHJKMNPQRSTVWXYZ234!"] {
            await #expect(throws: InviteRedemption.Failure.refused) {
                try await InviteRedemption(client: Self.client())
                    .redeem(code: code, using: try await Self.engine())
            }
        }
        #expect(TransportStub.requestCount == 0)
    }

    @Test("the client canonicalises a code exactly the way the relay parses one")
    func canonicalisationMatchesTheRelay() {
        let canonical = "ABCDEFGHJKMNPQRSTVWXYZ2345"
        #expect(InviteCode.canonical(canonical) == canonical)

        // Grouping, spaces, surrounding whitespace and lowercase all normalise away, exactly
        // as `invite.Parse` normalises them.
        #expect(InviteCode.canonical("  abcde-fghjk mnpqr stvwx yz2345  ") == canonical)

        // Crockford's transcription rules: I and L are 1, O is 0. A client that normalised
        // less than the relay would refuse codes the relay accepts.
        #expect(InviteCode.canonical("ILO23456789ABCDEFGHJKMNPQR") == "11023456789ABCDEFGHJKMNPQR")
        #expect(InviteCode.canonical("ilo23456789abcdefghjkmnpqr") == "11023456789ABCDEFGHJKMNPQR")

        // U is not in the alphabet at all, and neither is anything outside it.
        #expect(InviteCode.canonical("U1234567890ABCDEFGHJKMNPQR") == nil)
        #expect(InviteCode.canonical(String(repeating: "A", count: 25)) == nil)
    }

    @Test("a well-formed code reaches the relay in canonical form — the positive control")
    func aWellFormedCodeReachesTheRelay() async throws {
        // Without this, refusing every code would pass the two tests above.
        TransportStub.reset([.init(status: 401)])

        await #expect(throws: InviteRedemption.Failure.refused) {
            try await InviteRedemption(client: Self.client())
                .redeem(code: "abcde-fghjk-mnpqr-stvwx-yz234-5", using: try await Self.engine())
        }
        #expect(TransportStub.requestCount == 1, "a valid-looking code must be presented")
        #expect(TransportStub.requestedURLs.first?.path == "/v1/invite/redeem")
    }

    private static func engine() async throws -> CryptoEngine {
        let container = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("relay-invite-\(UUID().uuidString)", isDirectory: true)
        return try await CryptoEngine.open(container: container)
    }
}
