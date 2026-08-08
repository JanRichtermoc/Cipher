//
//  MessagingTestSupport.swift
//  CipherTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//
//  Test doubles for the messaging path. Nothing here may be reachable from the app target — the
//  same rule `Scripts/verify-app-target-manifest.sh` enforces for the shipping bundle.
//

import CipherCrypto
import Foundation
import Security
import XCTest

@testable import Cipher

/// A stubbed relay that answers per route, so one test can drive a fetch, an acknowledgement and
/// a send in the order the repository actually performs them.
///
/// `URLProtocol` rather than a fake client, for the reason `StubRelay` gives: several of these
/// tests are about what `RelayClient` does — retry, or refuse to — and a protocol-witness fake
/// would let the test assert its own stub instead of the code that ships.
final class RoutedStubRelay: URLProtocol, @unchecked Sendable {

    struct Reply: Sendable {
        let status: Int
        let body: Data

        init(status: Int, json: String = "{}") {
            self.status = status
            self.body = Data(json.utf8)
        }

        /// A raw body, for the one route whose answer is not JSON: a blob download returns
        /// `application/octet-stream` ciphertext (P6.S04).
        init(status: Int, bytes: Data) {
            self.status = status
            self.body = bytes
        }
    }

    /// Keyed by `"METHOD /path"`. A key ending in `/` prefix-matches, so `GET /v1/keys/` covers
    /// `/v1/keys/<uuid>`; anything else must match exactly. Each route's replies are consumed in
    /// order and the last one repeats.
    ///
    /// **Longest key wins.** A plain prefix match makes `POST /v1/messages/ack` also match
    /// `POST /v1/messages`, so an acknowledgement would be answered by the send route — which is
    /// how three tests here first "failed" against correct production code, and exactly the shape
    /// of a test harness that reports the wrong culprit.
    nonisolated(unsafe) private static var routes: [String: [Reply]] = [:]
    nonisolated(unsafe) private(set) static var received: [(route: String, body: Data)] = []
    nonisolated(unsafe) private static var blockedRoute: String?
    nonisolated(unsafe) private static var blocksRemaining = 0
    private static let routeStarted = DispatchSemaphore(value: 0)
    private static let routeRelease = DispatchSemaphore(value: 0)
    private static let stateLock = NSLock()

    static func reset(_ routes: [String: [Reply]]) {
        stateLock.withLock {
            self.routes = routes
            self.received = []
            self.blockedRoute = nil
            self.blocksRemaining = 0
        }
    }

    /// Replaces one route without clearing what has been recorded, so a test can change the
    /// relay's behaviour mid-run and still count everything that happened.
    static func setRoute(_ route: String, _ replies: [Reply]) {
        stateLock.withLock { routes[route] = replies }
    }

    static func requests(_ route: String) -> [Data] {
        stateLock.withLock { received.filter { matches($0.route, route) }.map(\.body) }
    }

    static func count(_ route: String) -> Int { requests(route).count }

    /// Blocks the next matching request after recording and choosing its reply. This makes an
    /// actor-reentrancy race deterministic: another repository call either reaches the relay
    /// while the first is suspended, or its operation gate keeps it out.
    static func blockNextRequest(_ route: String) {
        stateLock.withLock {
            blockedRoute = route
            blocksRemaining = 1
        }
    }

    /// Waits for the blocked route to be reached.
    ///
    /// The ceiling is generous on purpose, and raising it weakens nothing: the semaphore is
    /// signalled the instant the request arrives, so a healthy run never spends any of it.
    /// It bounds only how long a *broken* run waits before failing.
    ///
    /// Two seconds was not enough. The first `receive()` in a fresh process opens the crypto
    /// engine, reads the Keychain, opens SQLite and performs its first libsignal call before it
    /// ever reaches the relay, and `testACancelledRepositoryWaiterNeverRunsAfterTheGateOpens`
    /// sorts first among these tests, so it pays that cold start. On a loaded CI runner — where
    /// the surrounding suites ran three to four times slower than on a developer machine — that
    /// exceeded two seconds and failed the *precondition*, not the property under test.
    static func waitForBlockedRequest(timeout: TimeInterval = observationCeiling) -> Bool {
        routeStarted.wait(timeout: .now() + timeout) == .success
    }

    static func releaseBlockedRequest() { routeRelease.signal() }

    // --- Timing budgets, and the order between them -----------------------------
    //
    // Every wait a test performs must be shorter than `blockEscapeHatch`, because when the
    // hatch fires the blocked response is delivered, the app's gate releases, and the queued
    // call proceeds — so a wait that outlives it stops observing "the second call is held
    // out" and starts observing "the block expired". That is not a slower test; it is a
    // different test, silently.
    //
    // It was 5 seconds against sleeps of 50–100 ms, so the ordering held by a wide margin and
    // by accident. Raising the waits to survive a slow CI runner inverted it, and the failure
    // was visible only because a negative test showed the relay receiving a second request it
    // should never have seen. The relationship is named here so the next change to either
    // number has to consider the other.

    /// Deadlock escape hatch. Never a timing participant: no test should ever reach it.
    static let blockEscapeHatch: TimeInterval = 60

    /// Ceiling for waiting on an observable condition. Well under ``blockEscapeHatch``.
    static let observationCeiling: TimeInterval = 20

    /// Polls until `condition` holds, or the ceiling expires.
    ///
    /// The replacement for `try await Task.sleep(for: .milliseconds(50))` followed by an
    /// assertion. A fixed sleep encodes a guess about machine speed in two directions at once:
    /// too short and the test fails on a slow machine, too short *in the other sense* and the
    /// assertion is true because the thing being waited for has not happened yet — which is a
    /// pass for the wrong reason, and the failure mode a gate must not have (AUDIT **R2**).
    static func waitUntil(
        timeout: TimeInterval = observationCeiling,
        _ condition: @Sendable () -> Bool
    ) async -> Bool {
        let deadline = ContinuousClock.now.advanced(by: .seconds(timeout))
        while ContinuousClock.now < deadline {
            if condition() { return true }
            try? await Task.sleep(for: .milliseconds(5))
        }
        return condition()
    }

    private static func matches(_ route: String, _ pattern: String) -> Bool {
        pattern.hasSuffix("/") ? route.hasPrefix(pattern) : route == pattern
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let method = request.httpMethod ?? "GET"
        let path = request.url?.path ?? ""
        let route = "\(method) \(path)"

        // `httpBody` is nil for a body set on an upload task; these requests all set it
        // directly, and `bodyStreamData` covers the case where URLSession converted it.
        let body = request.httpBody ?? Self.bodyStreamData(request) ?? Data()
        let (reply, shouldBlock): (Reply, Bool) = Self.stateLock.withLock {
            Self.received.append((route, body))
            let match = Self.routes
                .filter { Self.matches(route, $0.key) }
                .max { $0.key.count < $1.key.count }
            var replies = match?.value ?? [Reply(status: 404)]
            let reply = replies.count > 1
                ? replies.removeFirst() : (replies.first ?? Reply(status: 404))
            if let key = match?.key { Self.routes[key] = replies }

            let shouldBlock = Self.blockedRoute == route && Self.blocksRemaining > 0
            if shouldBlock { Self.blocksRemaining -= 1 }
            return (reply, shouldBlock)
        }
        let responseURL = request.url!
        let deliver: @Sendable () -> Void = { [self] in
            let response = HTTPURLResponse(
                url: responseURL, statusCode: reply.status, httpVersion: "HTTP/1.1",
                headerFields: [:])!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: reply.body)
            client?.urlProtocolDidFinishLoading(self)
        }
        if shouldBlock {
            Self.routeStarted.signal()
            // Do not block URLSession's protocol scheduling thread: doing so serialises every
            // request in the session and makes the concurrency test green without the app's
            // gate. Only response delivery waits; another request can start meanwhile.
            DispatchQueue.global().async {
                _ = Self.routeRelease.wait(timeout: .now() + Self.blockEscapeHatch)
                deliver()
            }
        } else {
            deliver()
        }
    }

    override func stopLoading() {}

    private static func bodyStreamData(_ request: URLRequest) -> Data? {
        guard let stream = request.httpBodyStream else { return nil }
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while stream.hasBytesAvailable {
            let read = stream.read(&buffer, maxLength: buffer.count)
            if read <= 0 { break }
            data.append(contentsOf: buffer[0..<read])
        }
        return data
    }

    /// A client whose transport is this stub, with no jitter so a retry does not sleep.
    static func client() -> RelayClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [RoutedStubRelay.self]
        return RelayClient(
            session: URLSession(configuration: configuration), jitter: { _ in 0 })
    }
}

/// A Keychain-backed session store under a test-only service name, so a test can arrange the
/// "signed in" state without touching the real one and without a fake `SessionStore` — the
/// repository reads the credential through the same code the app does.
enum TestSession {

    static let service = "cz.janrichtermoc.Cipher.tests.session"

    static func store() -> SessionStore { SessionStore(service: service) }

    /// Stores a credential whose token is the given bearer string.
    static func signIn(
        token: String = String(repeating: "A", count: 43),
        aci: UUID,
        phase: SessionCredential.Phase = .active
    ) throws {
        let issuedAt = Date()
        try store().store(
            SessionCredential(token: Data(token.utf8), aci: aci, issuedAt: issuedAt,
                              expiresAt: issuedAt.addingTimeInterval(30 * 24 * 60 * 60),
                              origin: .serverIssued, phase: phase))
    }

    static func signOut() {
        try? store().clear()
    }
}

/// Two real engines over temporary containers: the device under test, and a peer that produces
/// genuine ciphertext for it.
///
/// The peer is a second `CryptoEngine` rather than a hand-built fixture because the point of a
/// receive test is that a real envelope, produced by a real ratchet, decrypts and is filed. A
/// fake envelope would only test the plumbing around a value the test made up.
struct MessagingFixture {

    let localAci = UUID()
    let peerAci = UUID()
    let engine: CryptoEngine
    let peerEngine: CryptoEngine
    private let containers: [URL]

    init() async throws {
        let localRoot = Self.container()
        let peerRoot = Self.container()
        containers = [localRoot, peerRoot]

        engine = try await CryptoEngine.open(container: localRoot)
        peerEngine = try await CryptoEngine.open(container: peerRoot)

        try await engine.adoptLocalAddress(PeerAddress(aci: localAci))
        try await peerEngine.adoptLocalAddress(PeerAddress(aci: peerAci))
    }

    func tearDown() async {
        // Close SQLite before removing its container. Unlinking a live WAL/SHM vnode is an API
        // violation and can make a following test exercise an invalidated descriptor.
        try? await engine.destroyAllState()
        try? await peerEngine.destroyAllState()
        for url in containers { try? FileManager.default.removeItem(at: url) }
    }

    private static func container() -> URL {
        URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("messaging-\(UUID().uuidString)", isDirectory: true)
    }

    /// An envelope the peer really encrypted for the device under test, establishing the session.
    ///
    /// The device publishes prekeys, the peer starts a session from that publication, and the
    /// result is a `PreKeySignalMessage` — exactly what a first inbound message is.
    func envelopeFromPeer(_ text: String) async throws -> Data {
        try await envelopeFromPeer(content: .text(text))
    }

    /// The same, for a payload that is not plain text — an expiring message (P6.S03), and
    /// whatever comes after it. One bundle-assembly path rather than two, so a test about
    /// content cannot accidentally diverge on how the session was established.
    func envelopeFromPeer(content: MessagePayload.Content) async throws -> Data {
        let published = try await engine.generatePublishedKeys(oneTimeCount: 1)
        let bundle = PeerKeyBundle(
            registrationId: try await engine.localRegistrationId,
            identityKey: try await engine.localIdentityKey,
            preKeyId: published.oneTimePreKeys[0].keyId,
            preKey: published.oneTimePreKeys[0].publicKey,
            signedPreKeyId: published.signedPreKey.keyId,
            signedPreKey: published.signedPreKey.publicKey,
            signedPreKeySignature: published.signedPreKey.signature,
            kyberPreKeyId: published.kyberPreKeys[0].keyId,
            kyberPreKey: published.kyberPreKeys[0].publicKey,
            kyberPreKeySignature: published.kyberPreKeys[0].signature)

        try await peerEngine.startSession(with: PeerAddress(aci: localAci), bundle: bundle)
        let payload = try MessagePayload(content: content).encode()
        return try await peerEngine.encrypt(payload, to: PeerAddress(aci: localAci))
    }

    /// The JSON the relay would answer a fetch with.
    static func fetchBody(_ envelopes: [(id: UUID, bytes: Data)], more: Bool = false) -> String {
        let messages = envelopes.map {
            "{\"id\":\"\($0.id.uuidString.lowercased())\",\"envelope\":\"\($0.bytes.base64EncodedString())\"}"
        }
        return "{\"messages\":[\(messages.joined(separator: ","))],\"more\":\(more)}"
    }
}
