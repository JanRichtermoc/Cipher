//
//  MessageRepositoryTests.swift
//  CipherTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//
//  P5.S10, C-02. What is being guarded is not "a message can be sent" — it is the ordering that
//  makes the send survivable and the acknowledgement honest:
//
//    * nothing leaves this device that `CryptoEngine.encrypt` did not produce;
//    * a message is durable before it is transmitted;
//    * the relay is told to forget a message only once this device can prove it has it.
//
//  Each of those is negative-tested: the failure path is driven, not just the happy one.
//

import CipherCrypto
import Foundation
import XCTest

@testable import Cipher

final class MessageRepositoryTests: XCTestCase {

    private var fixture: MessagingFixture!

    override func setUp() async throws {
        try await super.setUp()
        fixture = try await MessagingFixture()
        try TestSession.signIn()
    }

    override func tearDown() async throws {
        TestSession.signOut()
        fixture.tearDown()
        fixture = nil
        try await super.tearDown()
    }

    private func makeRepository() -> MessageRepository {
        let client = RoutedStubRelay.client()
        return MessageRepository(
            engine: fixture.engine,
            directory: RelayKeyDirectory(client: client),
            mailbox: RelayMailbox(client: client),
            sessions: TestSession.store())
    }

    /// A relay that accepts a publication, dispenses the peer's bundle, accepts sends, and has
    /// nothing waiting. Individual tests override the routes they care about.
    private func defaultRoutes(
        fetch: String = #"{"messages":[],"more":false}"#
    ) async throws -> [String: [RoutedStubRelay.Reply]] {
        [
            "PUT /v1/keys": [.init(status: 200, json: #"{"one_time_prekeys":1,"kyber_prekeys":1}"#)],
            "GET /v1/keys/": [.init(status: 200, json: try await peerBundleJSON())],
            "POST /v1/messages/ack": [.init(status: 200, json: #"{"acknowledged":1}"#)],
            "POST /v1/messages": [.init(status: 202)],
            "GET /v1/messages": [.init(status: 200, json: fetch)],
        ]
    }

    /// The peer's real published bundle, in the relay's wire shape. Real, not synthetic: the
    /// device has to be able to establish a session that the peer can then actually decrypt with.
    private func peerBundleJSON() async throws -> String {
        let published = try await fixture.peerEngine.generatePublishedKeys(oneTimeCount: 1)
        let identity = try await fixture.peerEngine.localIdentityKey
        let registration = try await fixture.peerEngine.localRegistrationId
        return """
        {"registration_id":\(registration),\
        "identity_key":"\(identity.base64EncodedString())",\
        "prekey_id":\(published.oneTimePreKeys[0].keyId),\
        "prekey":"\(published.oneTimePreKeys[0].publicKey.base64EncodedString())",\
        "signed_prekey_id":\(published.signedPreKey.keyId),\
        "signed_prekey":"\(published.signedPreKey.publicKey.base64EncodedString())",\
        "signed_prekey_signature":"\(published.signedPreKey.signature.base64EncodedString())",\
        "kyber_prekey_id":\(published.kyberPreKeys[0].keyId),\
        "kyber_prekey":"\(published.kyberPreKeys[0].publicKey.base64EncodedString())",\
        "kyber_prekey_signature":"\(published.kyberPreKeys[0].signature.base64EncodedString())"}
        """
    }

    private func envelopeSent() throws -> Envelope {
        let bodies = RoutedStubRelay.requests("POST /v1/messages")
            .filter { !$0.isEmpty }
        let body = try XCTUnwrap(bodies.first)
        struct Sent: Decodable {
            let recipient: String
            let envelope: String
        }
        let decoded = try JSONDecoder().decode(Sent.self, from: body)
        return try Envelope.decode(try XCTUnwrap(Data(base64Encoded: decoded.envelope)))
    }

    // MARK: - Sending

    func testASentMessageIsCiphertextTheRelayCannotRead() async throws {
        RoutedStubRelay.reset(try await defaultRoutes())
        let repository = makeRepository()

        let stored = try await repository.send(text: "meet at six", to: fixture.peerAci)
        XCTAssertEqual(stored.state, .sent)

        // The bytes on the wire are an `Envelope` this device produced, and the plaintext is not
        // in them anywhere. This is the assertion C-02 was about: the previous path appended a
        // struct to an array and called it sending.
        let envelope = try envelopeSent()
        XCTAssertEqual(envelope.sender.uuid, fixture.localAci)
        XCTAssertEqual(envelope.type, .preKey, "a first message must establish the session")
        XCTAssertNil(envelope.ciphertext.range(of: Data("meet at six".utf8)))

        // And the peer can actually read it — the ciphertext is a real ratchet message, not a
        // well-formed envelope around nonsense.
        let received = try await fixture.peerEngine.decrypt(envelope.encode())
        let payload = try MessagePayload.decode(received.plaintext)
        XCTAssertEqual(payload, MessagePayload(content: .text("meet at six")))
        XCTAssertEqual(received.sender.serviceId.uuid, fixture.localAci)
    }

    func testTheMessageIsDurableBeforeItIsTransmitted() async throws {
        // The relay refuses the send. The message must still be on disk, marked failed: a
        // messenger that loses what you typed because the network was down is worse than one
        // that shows it as unsent.
        var routes = try await defaultRoutes()
        routes["POST /v1/messages"] = [.init(status: 500)]
        RoutedStubRelay.reset(routes)
        let repository = makeRepository()

        do {
            _ = try await repository.send(text: "keep me", to: fixture.peerAci)
            XCTFail("a 500 must surface")
        } catch let failure as MessageRepository.Failure {
            XCTAssertEqual(failure, .relayRefused)
        }

        let stored = try await repository.messages(with: fixture.peerAci)
        XCTAssertEqual(stored.map(\.text), ["keep me"])
        XCTAssertEqual(stored.first?.state, .failed)
    }

    func testSendingToABlockedPeerIsRefusedAndNothingLeavesTheDevice() async throws {
        RoutedStubRelay.reset(try await defaultRoutes())
        let repository = makeRepository()
        try await repository.startConversation(with: fixture.peerAci, nickname: nil)
        try await repository.setBlocked(true, for: fixture.peerAci)

        do {
            _ = try await repository.send(text: "hello", to: fixture.peerAci)
            XCTFail("a blocked conversation must refuse")
        } catch let failure as MessageRepository.Failure {
            XCTAssertEqual(failure, .blocked)
        }
        XCTAssertEqual(RoutedStubRelay.count("POST /v1/messages"), 0)
    }

    func testSendingWithoutACredentialNeverTouchesTheNetwork() async throws {
        TestSession.signOut()
        RoutedStubRelay.reset(try await defaultRoutes())
        let repository = makeRepository()

        do {
            _ = try await repository.send(text: "hello", to: fixture.peerAci)
            XCTFail("a signed-out device must not send")
        } catch let failure as MessageRepository.Failure {
            XCTAssertEqual(failure, .notAuthenticated)
        }
        XCTAssertEqual(RoutedStubRelay.received.count, 0)
    }

    func testAPeerWithNoPublishedKeysIsReportedAsUnavailable() async throws {
        var routes = try await defaultRoutes()
        routes["GET /v1/keys/"] = [.init(status: 404)]
        RoutedStubRelay.reset(routes)
        let repository = makeRepository()

        do {
            _ = try await repository.send(text: "hello", to: fixture.peerAci)
            XCTFail("no bundle means no session")
        } catch let failure as MessageRepository.Failure {
            XCTAssertEqual(failure, .peerUnavailable)
        }
        // Nothing was transmitted, and the message is on disk as failed rather than lost.
        XCTAssertEqual(RoutedStubRelay.count("POST /v1/messages"), 0)
        let stored = try await repository.messages(with: fixture.peerAci)
        XCTAssertEqual(stored.first?.state, .failed)
    }

    func testTheBundleIsFetchedOncePerSessionRatherThanPerMessage() async throws {
        RoutedStubRelay.reset(try await defaultRoutes())
        let repository = makeRepository()

        _ = try await repository.send(text: "one", to: fixture.peerAci)
        _ = try await repository.send(text: "two", to: fixture.peerAci)

        // Every fetch consumes one of the peer's one-time prekeys and one of this device's
        // rate-limit tokens (AUDIT 3.1). Refetching per message would help an attacker drain the
        // pool rather than merely allowing it.
        XCTAssertEqual(RoutedStubRelay.count("GET /v1/keys/"), 1)
        XCTAssertEqual(RoutedStubRelay.count("POST /v1/messages"), 2)
    }

    // MARK: - Receiving

    func testAFetchedMessageIsStoredAndThenAcknowledged() async throws {
        let envelope = try await fixture.envelopeFromPeer("from the peer")
        let id = UUID()
        var routes = try await defaultRoutes()
        routes["GET /v1/messages"] = [
            .init(status: 200, json: MessagingFixture.fetchBody([(id, envelope)])),
            .init(status: 200, json: #"{"messages":[],"more":false}"#),
        ]
        RoutedStubRelay.reset(routes)
        let repository = makeRepository()

        let stored = try await repository.receive()
        XCTAssertEqual(stored, 1)

        let messages = try await repository.messages(with: fixture.peerAci)
        XCTAssertEqual(messages.map(\.text), ["from the peer"])
        XCTAssertEqual(messages.first?.direction, .incoming)
        XCTAssertTrue(messages.first?.establishedSession == true)
        // Attribution comes from the session that decrypted, and the identity key it was bound to
        // is what a safety number would be computed from.
        let peerIdentity = try await fixture.peerEngine.localIdentityKey
        XCTAssertEqual(messages.first?.senderIdentityKey, peerIdentity)

        // Acknowledged — and with the id the relay gave, so the relay can actually delete it.
        let ack = try XCTUnwrap(RoutedStubRelay.requests("POST /v1/messages/ack").first)
        XCTAssertTrue(String(decoding: ack, as: UTF8.self).contains(id.uuidString.lowercased()))
    }

    func testAnUndecryptableEnvelopeIsDroppedAndAcknowledged() async throws {
        // A message that cannot decrypt now can never decrypt: the ratchet state that would make
        // it work does not exist. Leaving it unacknowledged would retain ciphertext on a host
        // assumed seizable for the full TTL and fail again on every launch.
        let junk = try Envelope(
            type: .whisper, sender: ServiceIdentifier(kind: .aci, uuid: fixture.peerAci),
            timestamp: 1, ciphertext: Data(repeating: 0xAB, count: 64)).encode()
        let id = UUID()
        var routes = try await defaultRoutes()
        routes["GET /v1/messages"] = [
            .init(status: 200, json: MessagingFixture.fetchBody([(id, junk)])),
            .init(status: 200, json: #"{"messages":[],"more":false}"#),
        ]
        RoutedStubRelay.reset(routes)
        let repository = makeRepository()

        let stored = try await repository.receive()
        XCTAssertEqual(stored, 0, "nothing was stored")
        let messages = try await repository.messages(with: fixture.peerAci)
        XCTAssertTrue(messages.isEmpty)

        let ack = try XCTUnwrap(RoutedStubRelay.requests("POST /v1/messages/ack").first)
        XCTAssertTrue(
            String(decoding: ack, as: UTF8.self).contains(id.uuidString.lowercased()),
            "a permanently undecryptable message must still be acknowledged")
    }

    func testAMessageFromABlockedPeerIsDecryptedDroppedAndAcknowledged() async throws {
        let envelope = try await fixture.envelopeFromPeer("blocked text")
        let id = UUID()
        var routes = try await defaultRoutes()
        routes["GET /v1/messages"] = [
            .init(status: 200, json: MessagingFixture.fetchBody([(id, envelope)])),
            .init(status: 200, json: #"{"messages":[],"more":false}"#),
        ]
        RoutedStubRelay.reset(routes)
        let repository = makeRepository()
        try await repository.startConversation(with: fixture.peerAci, nickname: nil)
        try await repository.setBlocked(true, for: fixture.peerAci)

        let stored = try await repository.receive()
        XCTAssertEqual(stored, 0)
        let messages = try await repository.messages(with: fixture.peerAci)
        XCTAssertTrue(messages.isEmpty)
        XCTAssertFalse(RoutedStubRelay.requests("POST /v1/messages/ack").isEmpty)
    }

    func testAMessageThatCannotBeStoredIsNotAcknowledged() async throws {
        // The single most important branch in the receive path. Acknowledging deletes the relay's
        // copy and an envelope decrypts exactly once, so acknowledging something this device
        // failed to store loses the message permanently — there is nothing to ask for again.
        //
        // The failure is injected from outside rather than through a hook in the shipping code:
        // the sealed database is made unwritable, so the session and prekey writes that
        // `decrypt` performs still succeed (they are files in sibling directories) and only the
        // archive write fails. That is exactly the shape of a full disk.
        //
        // It used to take write permission from the `app-data` directory, which was where
        // message records lived until P5.S11 moved them into `records.sqlite3`. The test kept
        // passing for a while afterwards for the wrong reason and then failed outright, which
        // is the better of the two outcomes: an injection that no longer injects anything is a
        // test that proves nothing while still reporting success.
        let envelope = try await fixture.envelopeFromPeer("must not be acknowledged")
        var routes = try await defaultRoutes()
        routes["GET /v1/messages"] = [
            .init(status: 200, json: MessagingFixture.fetchBody([(UUID(), envelope)])),
        ]
        RoutedStubRelay.reset(routes)
        let repository = makeRepository()

        // Force the database into existence, then take write permission away from it and from
        // the directory it would create its siblings in.
        try await repository.startConversation(with: UUID(), nickname: nil)

        let container = fixture.localContainer
        let databaseFiles = ["records.sqlite3", "records.sqlite3-wal", "records.sqlite3-shm"]
            .map { container.appendingPathComponent($0) }
        XCTAssertTrue(
            FileManager.default.fileExists(atPath: databaseFiles[0].path),
            "the sealed database should exist by now — otherwise this test proves nothing")

        for url in databaseFiles where FileManager.default.fileExists(atPath: url.path) {
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o400], ofItemAtPath: url.path)
        }
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o500], ofItemAtPath: container.path)
        defer {
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o700], ofItemAtPath: container.path)
            for url in databaseFiles where FileManager.default.fileExists(atPath: url.path) {
                try? FileManager.default.setAttributes(
                    [.posixPermissions: 0o600], ofItemAtPath: url.path)
            }
        }

        do {
            _ = try await repository.receive()
            XCTFail("a storage failure must surface rather than being acknowledged away")
        } catch let failure as MessageRepository.Failure {
            XCTAssertEqual(failure, .storageUnavailable)
        }

        // Nothing was acknowledged: the message is still on the relay, which is the only place it
        // still exists.
        XCTAssertEqual(
            RoutedStubRelay.count("POST /v1/messages/ack"), 0,
            "a message that failed to store must never be acknowledged")
    }

    func testAFailedAcknowledgementIsReportedRatherThanIgnored() async throws {
        let envelope = try await fixture.envelopeFromPeer("stored anyway")
        var routes = try await defaultRoutes()
        routes["GET /v1/messages"] = [
            .init(status: 200, json: MessagingFixture.fetchBody([(UUID(), envelope)])),
        ]
        routes["POST /v1/messages/ack"] = [.init(status: 500)]
        RoutedStubRelay.reset(routes)
        let repository = makeRepository()

        do {
            _ = try await repository.receive()
            XCTFail("a failed acknowledgement must surface")
        } catch let failure as MessageRepository.Failure {
            // Acknowledgement *is* retried — it is idempotent on the server, and a lost
            // acknowledgement leaves ciphertext on a box assumed seizable. So a relay that keeps
            // failing surfaces as exhausted retries, which must read as "the relay is broken"
            // rather than "check your connection".
            XCTAssertEqual(failure, .relayUnavailable)
            XCTAssertGreaterThan(RoutedStubRelay.count("POST /v1/messages/ack"), 1)
        }
        // The message is still durable: the relay will offer it again, and the duplicate is
        // dropped by the ratchet rather than shown twice.
        let stored = try await repository.messages(with: fixture.peerAci)
        XCTAssertEqual(stored.map(\.text), ["stored anyway"])
    }

    func testAFetchStopsWhenTheRelayReportsNothingMore() async throws {
        RoutedStubRelay.reset(try await defaultRoutes())
        let repository = makeRepository()

        let stored = try await repository.receive()
        XCTAssertEqual(stored, 0)
        XCTAssertEqual(RoutedStubRelay.count("GET /v1/messages"), 1)
        // Nothing to acknowledge means no request at all, rather than an empty one.
        XCTAssertEqual(RoutedStubRelay.count("POST /v1/messages/ack"), 0)
    }

    func testAPagedFetchDrainsTheQueue() async throws {
        let first = try await fixture.envelopeFromPeer("page one")
        // A second envelope on the same session, so both decrypt.
        let second = try await fixture.peerEngine.encrypt(
            try MessagePayload(content: .text("page two")).encode(),
            to: PeerAddress(aci: fixture.localAci))

        var routes = try await defaultRoutes()
        routes["GET /v1/messages"] = [
            .init(status: 200, json: MessagingFixture.fetchBody([(UUID(), first)], more: true)),
            .init(status: 200, json: MessagingFixture.fetchBody([(UUID(), second)], more: false)),
        ]
        RoutedStubRelay.reset(routes)
        let repository = makeRepository()

        let stored = try await repository.receive()
        XCTAssertEqual(stored, 2)
        XCTAssertEqual(RoutedStubRelay.count("GET /v1/messages"), 2)
        let messages = try await repository.messages(with: fixture.peerAci)
        XCTAssertEqual(messages.map(\.text), ["page one", "page two"])
    }

    // MARK: - Registration

    func testRegistrationAdoptsTheAddressAndPublishesExactlyOnce() async throws {
        RoutedStubRelay.reset(try await defaultRoutes())
        let repository = makeRepository()

        try await repository.register(aci: fixture.localAci)
        try await repository.register(aci: fixture.localAci)
        try await repository.resumeRegistration()

        // Publication is 6 per day per account (`BACKEND.md` §5) and generating the pool is a
        // hundred keypairs. Republishing on every launch would spend both for nothing.
        XCTAssertEqual(RoutedStubRelay.count("PUT /v1/keys"), 1)
        let adopted = await repository.localAci()
        XCTAssertEqual(adopted, fixture.localAci)
    }

    func testAFailedPublicationIsRetriedOnTheNextLaunch() async throws {
        var routes = try await defaultRoutes()
        // A relay that keeps failing. A single 500 followed by a 200 would not test anything:
        // publication is idempotent, so `RelayClient` retries it and the *first* call would
        // succeed on its second attempt.
        routes["PUT /v1/keys"] = [.init(status: 500)]
        RoutedStubRelay.reset(routes)
        let repository = makeRepository()

        // The flag must not be set by a publication the relay never accepted: an account whose
        // keys never published is one no peer can start a session with, and nothing else would
        // ever notice.
        do {
            try await repository.register(aci: fixture.localAci)
            XCTFail("a relay that never accepts the publication must surface")
        } catch let failure as MessageRepository.Failure {
            XCTAssertEqual(failure, .relayUnavailable)
        }

        RoutedStubRelay.setRoute(
            "PUT /v1/keys", [.init(status: 200, json: #"{"one_time_prekeys":1,"kyber_prekeys":1}"#)])
        try await repository.resumeRegistration()

        // And once it has been accepted, it stops: the flag is set only after the relay has the
        // keys, and only then does the retry loop end.
        let attempts = RoutedStubRelay.count("PUT /v1/keys")
        try await repository.resumeRegistration()
        try await repository.resumeRegistration()
        XCTAssertEqual(RoutedStubRelay.count("PUT /v1/keys"), attempts)
    }

    func testAMismatchedAccountIsRefusedRatherThanReadopted() async throws {
        RoutedStubRelay.reset(try await defaultRoutes())
        let repository = makeRepository()
        try await repository.register(aci: fixture.localAci)

        do {
            try await repository.register(aci: UUID())
            XCTFail("a second address must not be adopted")
        } catch let failure as MessageRepository.Failure {
            // Adopting it would orphan every existing session, and the failure would look like a
            // network problem a launch later.
            XCTAssertEqual(failure, .accountMismatch)
        }
    }

    func testThePublishedBodyCarriesTheKyberMaterialTheRelayRequires() async throws {
        RoutedStubRelay.reset(try await defaultRoutes())
        let repository = makeRepository()
        try await repository.register(aci: fixture.localAci)

        let body = try XCTUnwrap(RoutedStubRelay.requests("PUT /v1/keys").first)
        let json = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: body) as? [String: Any])
        // PQXDH is a locked decision and the relay refuses an upload with no last-resort key. A
        // field-name drift here is a 400 in production and a silent downgrade in a worse design.
        XCTAssertNotNil(json["signed_prekey"])
        XCTAssertNotNil(json["kyber_last_resort"])
        let expected = await CryptoEngine.defaultOneTimePreKeyCount
        XCTAssertEqual((json["kyber_prekeys"] as? [Any])?.count, expected)
        XCTAssertEqual((json["one_time_prekeys"] as? [Any])?.count, expected)
    }
}
