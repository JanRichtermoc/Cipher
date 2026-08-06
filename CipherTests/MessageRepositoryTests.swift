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
        try TestSession.signIn(aci: fixture.localAci)
    }

    override func tearDown() async throws {
        TestSession.signOut()
        await fixture.tearDown()
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

    func testCredentialForAnotherAccountCannotUsePriorCryptoState() async throws {
        // Vary only the credential ACI. The engine remains bound to the fixture
        // account and the token remains otherwise valid, so this fails only if
        // the account-binding guard actually runs.
        try TestSession.signIn(aci: UUID())
        RoutedStubRelay.reset(try await defaultRoutes())
        let repository = makeRepository()

        do {
            _ = try await repository.send(text: "must stay local", to: fixture.peerAci)
            XCTFail("a credential from another account used the prior account's ratchets")
        } catch let failure as MessageRepository.Failure {
            XCTAssertEqual(failure, .accountMismatch)
        }
        XCTAssertEqual(RoutedStubRelay.count("GET /v1/keys/"), 0)
        XCTAssertEqual(RoutedStubRelay.count("POST /v1/messages"), 0)
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

    /// AUDIT 4.14. A first message from a new peer, arriving at the conversation cap, is
    /// **dropped and acknowledged** — and that is deliberate, not an oversight.
    ///
    /// The ratchet advanced and committed inside the decrypt transaction, so this envelope can
    /// never be decrypted again. Withholding the acknowledgement would therefore not preserve
    /// it; it would leave the relay serving the same undecryptable bytes on every cycle, and
    /// `receiveExclusively` stops taking messages behind a storage failure — so a device at its
    /// conversation cap would stop receiving from *everyone*. Bounding one peer's first message
    /// is the smaller loss, and the cap never evicts an existing conversation to reach it.
    func testAMessageRefusedByTheConversationCapIsStillAcknowledged() async throws {
        let envelope = try await fixture.envelopeFromPeer("from an unknown peer")
        let id = UUID()
        var routes = try await defaultRoutes()
        routes["GET /v1/messages"] = [
            .init(status: 200, json: MessagingFixture.fetchBody([(id, envelope)])),
            .init(status: 200, json: #"{"messages":[],"more":false}"#),
        ]
        RoutedStubRelay.reset(routes)

        // Exactly one conversation slot, already spent on somebody else.
        let archive = ConversationArchive(
            engine: fixture.engine,
            quota: ConversationArchive.StorageQuota(
                maxConversations: 1,
                maxMessagesPerConversation: 5_000,
                maxDatabaseBytes: 192 * 1024 * 1024,
                evictionTargetBytes: 160 * 1024 * 1024,
                minRetainedPerConversation: 8,
                maxEvictionRounds: 4_096))
        let occupant = UUID()
        _ = try await archive.ensureConversation(occupant, nowMs: 1)

        let client = RoutedStubRelay.client()
        let repository = MessageRepository(
            engine: fixture.engine, archive: archive,
            directory: RelayKeyDirectory(client: client),
            mailbox: RelayMailbox(client: client),
            sessions: TestSession.store())

        // Not a thrown storage failure: the cycle completes.
        let stored = try await repository.receive()
        XCTAssertEqual(stored, 0)

        let messages = try await repository.messages(with: fixture.peerAci)
        XCTAssertTrue(messages.isEmpty, "nothing was stored for the refused peer")

        // The occupant is untouched — the cap refuses the newcomer, it does not evict anyone.
        let ids = try await archive.conversationIds()
        XCTAssertEqual(ids, [occupant])

        let ack = try XCTUnwrap(RoutedStubRelay.requests("POST /v1/messages/ack").first)
        XCTAssertTrue(String(decoding: ack, as: UTF8.self).contains(id.uuidString.lowercased()))
    }

    /// Being at the conversation cap must not stop the conversations that already exist.
    ///
    /// This is the `existing == nil` half of the check, and it needs a real envelope to prove:
    /// an earlier version of this guard lived in `ConversationQuotaTests` and drove
    /// `archive.append`, which never runs the inbound check at all — so it stayed green with
    /// the check deleted (AUDIT §0 R2). Without the `existing == nil` condition, one flood of
    /// unknown peers would take the device off the air for every correspondent it actually has.
    func testAnEstablishedConversationStillReceivesWhileAtTheConversationCap() async throws {
        let envelope = try await fixture.envelopeFromPeer("still getting through")
        let id = UUID()
        var routes = try await defaultRoutes()
        routes["GET /v1/messages"] = [
            .init(status: 200, json: MessagingFixture.fetchBody([(id, envelope)])),
            .init(status: 200, json: #"{"messages":[],"more":false}"#),
        ]
        RoutedStubRelay.reset(routes)

        // One slot, and the sender already occupies it. The store is full; this peer is known.
        let archive = ConversationArchive(
            engine: fixture.engine,
            quota: ConversationArchive.StorageQuota(
                maxConversations: 1,
                maxMessagesPerConversation: 5_000,
                maxDatabaseBytes: 192 * 1024 * 1024,
                evictionTargetBytes: 160 * 1024 * 1024,
                minRetainedPerConversation: 8,
                maxEvictionRounds: 4_096))
        _ = try await archive.ensureConversation(fixture.peerAci, nowMs: 1)

        let client = RoutedStubRelay.client()
        let repository = MessageRepository(
            engine: fixture.engine, archive: archive,
            directory: RelayKeyDirectory(client: client),
            mailbox: RelayMailbox(client: client),
            sessions: TestSession.store())

        let stored = try await repository.receive()
        XCTAssertEqual(stored, 1, "an established conversation still receives at the cap")

        let messages = try await repository.messages(with: fixture.peerAci)
        XCTAssertEqual(messages.map(\.text), ["still getting through"])
        XCTAssertFalse(RoutedStubRelay.requests("POST /v1/messages/ack").isEmpty)
    }

    func testAReceiveTransactionFailureRollsBackTheRatchetSoRetryStoresAndAcknowledges()
        async throws {
        // The single most important branch in the receive path. Acknowledging deletes the relay's
        // copy and an envelope decrypts exactly once, so acknowledging something this device
        // failed to store loses the message permanently — there is nothing to ask for again.
        //
        // Planting a malformed conversation drives the failure *after* a genuine prekey message
        // decrypts and libsignal has mutated the session/prekey stores. It therefore proves the
        // rollback, unlike a database permission failure that can reject BEGIN before decryption.
        let envelope = try await fixture.envelopeFromPeer("survives the retry")
        let id = UUID()
        var routes = try await defaultRoutes()
        routes["GET /v1/messages"] = [
            .init(status: 200, json: MessagingFixture.fetchBody([(id, envelope)])),
        ]
        RoutedStubRelay.reset(routes)
        let repository = makeRepository()

        try await repository.startConversation(with: fixture.peerAci, nickname: nil)
        let group = fixture.peerAci.uuidString.lowercased()
        try await fixture.engine.storeSealedRow(
            namespace: "conv", group: group, ordinal: 0, value: Data("not json".utf8))

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

        // Repair only the injected archive damage. The exact same envelope must still decrypt:
        // if the first attempt committed libsignal's mutations separately, this retry is a
        // duplicate to the ratchet and is dropped/acknowledged with no stored plaintext.
        try await fixture.engine.removeSealedRow(namespace: "conv", group: group, ordinal: 0)
        RoutedStubRelay.setRoute("GET /v1/messages", [
            .init(status: 200, json: MessagingFixture.fetchBody([(id, envelope)])),
            .init(status: 200, json: #"{"messages":[],"more":false}"#),
        ])

        let retriedCount = try await repository.receive()
        XCTAssertEqual(retriedCount, 1)
        let retriedMessages = try await repository.messages(with: fixture.peerAci).map(\.text)
        XCTAssertEqual(retriedMessages, ["survives the retry"])
        let ack = try XCTUnwrap(RoutedStubRelay.requests("POST /v1/messages/ack").first)
        XCTAssertTrue(String(decoding: ack, as: UTF8.self).contains(id.uuidString.lowercased()))
    }

    func testConcurrentReceivesAreSerializedBeforeEitherFetches() async throws {
        let envelope = try await fixture.envelopeFromPeer("once")
        var routes = try await defaultRoutes()
        routes["GET /v1/messages"] = [
            .init(status: 200, json: MessagingFixture.fetchBody([(UUID(), envelope)])),
            .init(status: 200, json: #"{"messages":[],"more":false}"#),
        ]
        RoutedStubRelay.reset(routes)
        RoutedStubRelay.blockNextRequest("GET /v1/messages")
        let repository = makeRepository()

        let first = Task { try await repository.receive() }
        let firstDidBlock = await Task.detached {
            RoutedStubRelay.waitForBlockedRequest()
        }.value
        XCTAssertTrue(
            firstDidBlock,
            "the first receive never reached the deliberate suspension point")
        let second = Task { try await repository.receive() }
        // Wait for the second call to actually queue behind the first, rather than sleeping
        // and hoping it has. A sleep that ends too early makes the assertion below true
        // because nothing has started yet — a pass that proves nothing (AUDIT R2).
        let secondQueued = await RoutedStubRelay.waitUntil {
            repository.queuedOperationWaiters == 1
        }
        XCTAssertTrue(secondQueued, "the second receive never queued behind the first")

        XCTAssertEqual(
            RoutedStubRelay.count("GET /v1/messages"), 1,
            "a second receive reached the relay while the first was suspended")
        RoutedStubRelay.releaseBlockedRequest()

        let results = try await [first.value, second.value].sorted()
        XCTAssertEqual(results, [0, 1])
        let messages = try await repository.messages(with: fixture.peerAci).map(\.text)
        XCTAssertEqual(messages, ["once"])
    }

    func testACancelledRepositoryWaiterNeverRunsAfterTheGateOpens() async throws {
        RoutedStubRelay.reset(try await defaultRoutes())
        RoutedStubRelay.blockNextRequest("GET /v1/messages")
        let repository = makeRepository()

        let holder = Task { try await repository.receive() }
        let holderDidBlock = await Task.detached {
            RoutedStubRelay.waitForBlockedRequest()
        }.value
        XCTAssertTrue(holderDidBlock)
        let waiter = Task { try await repository.receive() }
        // The point of this test is cancelling a waiter that is *queued*. Cancelling one that
        // has not reached the gate yet exercises a different path and would pass regardless,
        // so the queued state is waited for rather than assumed.
        let waiterQueued = await RoutedStubRelay.waitUntil {
            repository.queuedOperationWaiters == 1
        }
        XCTAssertTrue(waiterQueued, "the waiter never queued, so its cancellation proves nothing")
        XCTAssertEqual(RoutedStubRelay.count("GET /v1/messages"), 1)
        waiter.cancel()
        RoutedStubRelay.releaseBlockedRequest()

        let holderResult = try await holder.value
        XCTAssertEqual(holderResult, 0)
        do {
            _ = try await waiter.value
            XCTFail("a cancelled waiter must not execute after acquiring the gate")
        } catch is CancellationError {
            // Expected.
        }
        XCTAssertEqual(RoutedStubRelay.count("GET /v1/messages"), 1)
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
        try TestSession.signIn(aci: fixture.localAci, phase: .registering)
        RoutedStubRelay.reset(try await defaultRoutes())
        let repository = makeRepository()

        try await repository.register()
        try await repository.register()
        try await repository.resumeRegistration()

        // Publication is 6 per day per account (`BACKEND.md` §5) and generating the pool is a
        // hundred keypairs. Republishing on every launch would spend both for nothing.
        XCTAssertEqual(RoutedStubRelay.count("PUT /v1/keys"), 1)
        let adopted = await repository.localAci()
        XCTAssertEqual(adopted, fixture.localAci)
    }

    func testAFailedPublicationIsRetriedOnTheNextLaunch() async throws {
        try TestSession.signIn(aci: fixture.localAci, phase: .registering)
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
            try await repository.register()
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
        try TestSession.signIn(aci: UUID(), phase: .registering)
        RoutedStubRelay.reset(try await defaultRoutes())
        let repository = makeRepository()

        do {
            try await repository.register()
            XCTFail("a second address must not be adopted")
        } catch let failure as MessageRepository.Failure {
            // Adopting it would orphan every existing session, and the failure would look like a
            // network problem a launch later.
            XCTAssertEqual(failure, .accountMismatch)
        }
    }

    func testThePublishedBodyCarriesTheKyberMaterialTheRelayRequires() async throws {
        try TestSession.signIn(aci: fixture.localAci, phase: .registering)
        RoutedStubRelay.reset(try await defaultRoutes())
        let repository = makeRepository()
        try await repository.register()

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

    // MARK: - The publication the relay actually has to accept (AUDIT 5.32)

    /// The bounds `server/internal/api/keys.go` enforces on a publication, mirrored here because
    /// no Swift test can import Go. `docs/BACKEND.md` §2.4–§2.6 owns them.
    ///
    /// **Structural bounds only, deliberately.** The relay's ceiling on the whole body is *not*
    /// repeated here: `api.MaxPublishBytes` is computed from these same constants, and
    /// `TestABodyAtTheValidatorsMaximumIsReadable` proves on that side that any body satisfying
    /// them can be read. Keeping one byte count in two languages is how the relay ended up
    /// refusing publications it had itself declared legal.
    private enum RelayPublishBounds {
        static let maxKeysPerPool = 200
        static let curveKeyBytes = 32...64
        static let kyberKeyBytes = 32...4096
        static let signatureBytes = 32...128
        static let maxKeyId: UInt64 = 0xFF_FFFF
    }

    /// Every way the relay would refuse `body`, as readable text. Empty means it is accepted.
    ///
    /// Written as a checker rather than a wall of assertions so it can be pointed at a body the
    /// relay *must* refuse — a check that has never reported a violation is not a check.
    private func relayRefusals(for body: Data) throws -> [String] {
        let json = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: body) as? [String: Any],
            "the publication body is not a JSON object")
        var refusals: [String] = []

        func checkKey(
            _ key: [String: Any]?, named name: String,
            keyBytes: ClosedRange<Int>, signed: Bool
        ) {
            guard let key else {
                refusals.append("\(name): absent, which the relay refuses")
                return
            }
            if let id = (key["key_id"] as? NSNumber)?.uint64Value {
                if id > RelayPublishBounds.maxKeyId {
                    refusals.append("\(name): key id \(id) is above the protocol ceiling")
                }
            } else {
                refusals.append("\(name): no numeric key_id")
            }

            if let encoded = key["public_key"] as? String,
               let decoded = Data(base64Encoded: encoded) {
                if !keyBytes.contains(decoded.count) {
                    refusals.append("\(name): public key is \(decoded.count) bytes, outside \(keyBytes)")
                }
            } else {
                refusals.append("\(name): public_key is missing or not base64")
            }

            guard signed else { return }
            if let encoded = key["signature"] as? String,
               let decoded = Data(base64Encoded: encoded) {
                if !RelayPublishBounds.signatureBytes.contains(decoded.count) {
                    refusals.append(
                        "\(name): signature is \(decoded.count) bytes, outside "
                            + "\(RelayPublishBounds.signatureBytes)")
                }
            } else {
                refusals.append("\(name): signature is missing or not base64")
            }
        }

        checkKey(
            json["signed_prekey"] as? [String: Any], named: "signed_prekey",
            keyBytes: RelayPublishBounds.curveKeyBytes, signed: true)
        checkKey(
            json["kyber_last_resort"] as? [String: Any], named: "kyber_last_resort",
            keyBytes: RelayPublishBounds.kyberKeyBytes, signed: true)

        let kyber = json["kyber_prekeys"] as? [[String: Any]] ?? []
        let curve = json["one_time_prekeys"] as? [[String: Any]] ?? []
        for (pool, name) in [(kyber, "kyber_prekeys"), (curve, "one_time_prekeys")]
        where pool.count > RelayPublishBounds.maxKeysPerPool {
            refusals.append(
                "\(name): \(pool.count) keys, above the \(RelayPublishBounds.maxKeysPerPool) "
                    + "the relay accepts in one upload")
        }
        for (index, key) in kyber.enumerated() {
            checkKey(
                key, named: "kyber_prekeys[\(index)]",
                keyBytes: RelayPublishBounds.kyberKeyBytes, signed: true)
        }
        for (index, key) in curve.enumerated() {
            checkKey(
                key, named: "one_time_prekeys[\(index)]",
                keyBytes: RelayPublishBounds.curveKeyBytes, signed: false)
        }

        return refusals
    }

    func testThePublishedBodyStaysInsideEveryBoundTheRelayEnforces() async throws {
        // AUDIT 5.32, from this side. The relay refused the shipped client's publication for a
        // month of work because nothing ever compared what the client *produces* with what the
        // relay *accepts* — the relay's own fixtures modelled a four-key pool, and this side
        // never checked the payload against a bound at all.
        //
        // This is the real body: a genuine `register()` at the shipped pool size, captured from
        // the transport, not a re-encoding of it by the test.
        try TestSession.signIn(aci: fixture.localAci, phase: .registering)
        RoutedStubRelay.reset(try await defaultRoutes())
        let repository = makeRepository()
        try await repository.register()

        let body = try XCTUnwrap(RoutedStubRelay.requests("PUT /v1/keys").first)
        let refusals = try relayRefusals(for: body)
        XCTAssertEqual(
            refusals, [],
            "the shipped client publishes material the relay refuses:\n"
                + refusals.joined(separator: "\n"))
    }

    func testSerializedKeyAndSignatureSizesAreWhatTheRelayBoundsAssume() async throws {
        // The relay's bounds and its body ceiling are both sized from these three numbers, and
        // they come from a `0.x` dependency that promises no stability between releases
        // (AUDIT 1.4). Measured from the payload that ships, so a libsignal bump that changes a
        // serialized length fails here — naming the number — rather than in production as a 413.
        try TestSession.signIn(aci: fixture.localAci, phase: .registering)
        RoutedStubRelay.reset(try await defaultRoutes())
        try await makeRepository().register()

        let body = try XCTUnwrap(RoutedStubRelay.requests("PUT /v1/keys").first)
        let json = try XCTUnwrap(try JSONSerialization.jsonObject(with: body) as? [String: Any])

        func byteCount(_ key: [String: Any]?, _ field: String) throws -> Int {
            let encoded = try XCTUnwrap((key?[field]) as? String)
            return try XCTUnwrap(Data(base64Encoded: encoded)).count
        }

        let curve = try XCTUnwrap((json["one_time_prekeys"] as? [[String: Any]])?.first)
        let kyber = try XCTUnwrap((json["kyber_prekeys"] as? [[String: Any]])?.first)
        let signed = json["signed_prekey"] as? [String: Any]

        XCTAssertEqual(try byteCount(curve, "public_key"), 33, "0x05 type byte + 32 key bytes")
        XCTAssertEqual(
            try byteCount(kyber, "public_key"), 1569,
            "ML-KEM-1024: type byte + 1568 key bytes")
        XCTAssertEqual(try byteCount(signed, "signature"), 64)
    }

    func testTheBoundCheckerReportsAPublicationTheRelayWouldRefuse() async throws {
        // The positive control for the two tests above. A checker that has never returned a
        // violation proves nothing about the body it reads — AUDIT **R2**, and **R5** for the
        // habit of deriving the failing case from the data under test. This case is built by
        // hand, in the two directions that actually matter: a pool above the per-upload cap, and
        // a key id above the protocol ceiling.
        let overCap = (0...RelayPublishBounds.maxKeysPerPool).map { index in
            #"{"key_id":\#(index + 1),"public_key":"\#(Data(repeating: 5, count: 33).base64EncodedString())"}"#
        }.joined(separator: ",")
        let signature = Data(repeating: 0xAA, count: 64).base64EncodedString()
        let kyberKey = Data(repeating: 8, count: 1569).base64EncodedString()
        let body = Data(
            """
            {"signed_prekey":{"key_id":16777216,\
            "public_key":"\(Data(repeating: 5, count: 33).base64EncodedString())",\
            "signature":"\(signature)"},\
            "kyber_last_resort":{"key_id":2,"public_key":"\(kyberKey)","signature":"\(signature)"},\
            "kyber_prekeys":[],"one_time_prekeys":[\(overCap)]}
            """.utf8)

        let refusals = try relayRefusals(for: body)
        XCTAssertTrue(
            refusals.contains { $0.contains("above the 200") },
            "the checker missed a pool above the per-upload cap: \(refusals)")
        XCTAssertTrue(
            refusals.contains { $0.contains("above the protocol ceiling") },
            "the checker missed a key id above 0xFFFFFF: \(refusals)")
    }

    @MainActor
    func testAccountCleanupErasesHistoryAndDropsInMemoryConversations() async throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("account-cleanup-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let store = ConversationStore(openEngine: {
            try await CryptoEngine.open(container: root)
        })
        let engine = try await store.engine()
        let aci = UUID()
        try await engine.adoptLocalAddress(PeerAddress(aci: aci))
        let repository = MessageRepository(engine: engine, sessions: TestSession.store())
        _ = try await repository.startConversation(with: UUID(), nickname: "old account")

        await store.refresh()
        XCTAssertEqual(store.chats.count, 1, "positive control: old history was loaded")

        try await store.destroyAccountState()
        XCTAssertTrue(store.chats.isEmpty)
        XCTAssertTrue(store.contacts.isEmpty)
        XCTAssertNil(store.localAci)

        let reopened = try await store.engine()
        let reopenedAddress = try? await reopened.localAddress
        XCTAssertNil(reopenedAddress, "the replacement engine inherited the prior account")
        let freshRepository = MessageRepository(engine: reopened, sessions: TestSession.store())
        let freshConversations = try await freshRepository.conversations()
        XCTAssertTrue(freshConversations.isEmpty, "sealed history survived account cleanup")
        try await reopened.destroyAllState()
    }

    /// After the record key is deleted, opening surviving ciphertext correctly fails. The
    /// persisted destruction gate must then use the no-open cleanup path rather than trapping
    /// the account forever behind an engine it can no longer construct.
    @MainActor
    func testAccountCleanupFinishesPersistedEraseWhenCiphertextCannotOpen() async throws {
        struct InterruptedErase: Error {}
        let probe = PersistentEraseProbe()
        let store = ConversationStore(
            openEngine: { throw InterruptedErase() },
            destroyPersistedState: { await probe.erase() })

        try await store.destroyAccountState()

        let calls = await probe.callCount()
        XCTAssertEqual(calls, 1)
        XCTAssertTrue(store.chats.isEmpty)
        XCTAssertTrue(store.contacts.isEmpty)
        XCTAssertNil(store.localAci)
    }
}

private actor PersistentEraseProbe {
    private var calls = 0

    func erase() { calls += 1 }
    func callCount() -> Int { calls }
}
