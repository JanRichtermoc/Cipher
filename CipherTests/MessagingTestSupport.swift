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

    static func reset(_ routes: [String: [Reply]]) {
        self.routes = routes
        self.received = []
    }

    /// Replaces one route without clearing what has been recorded, so a test can change the
    /// relay's behaviour mid-run and still count everything that happened.
    static func setRoute(_ route: String, _ replies: [Reply]) {
        routes[route] = replies
    }

    static func requests(_ route: String) -> [Data] {
        received.filter { matches($0.route, route) }.map(\.body)
    }

    static func count(_ route: String) -> Int { requests(route).count }

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
        Self.received.append((route, body))

        let match = Self.routes
            .filter { Self.matches(route, $0.key) }
            .max { $0.key.count < $1.key.count }
        var replies = match?.value ?? [Reply(status: 404)]
        let reply = replies.count > 1 ? replies.removeFirst() : (replies.first ?? Reply(status: 404))
        if let key = match?.key { Self.routes[key] = replies }

        let response = HTTPURLResponse(
            url: request.url!, statusCode: reply.status, httpVersion: "HTTP/1.1",
            headerFields: [:])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: reply.body)
        client?.urlProtocolDidFinishLoading(self)
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
    static func signIn(token: String = "test-bearer-token") throws {
        try store().store(
            SessionCredential(token: Data(token.utf8), issuedAt: Date(), origin: .serverIssued))
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
    /// Exposed so a test can inject a filesystem fault into the record container — see
    /// `testAMessageThatCannotBeStoredIsNotAcknowledged`.
    let localContainer: URL
    private let containers: [URL]

    init() async throws {
        let localRoot = Self.container()
        let peerRoot = Self.container()
        localContainer = localRoot
        containers = [localRoot, peerRoot]

        engine = try await CryptoEngine.open(container: localRoot)
        peerEngine = try await CryptoEngine.open(container: peerRoot)

        try await engine.adoptLocalAddress(PeerAddress(aci: localAci))
        try await peerEngine.adoptLocalAddress(PeerAddress(aci: peerAci))
    }

    func tearDown() {
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
        let payload = try MessagePayload(content: .text(text)).encode()
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
