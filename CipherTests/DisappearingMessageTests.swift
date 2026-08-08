//
//  DisappearingMessageTests.swift
//  CipherTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//
//  P6.S03. The step's anti-goal is "hide rather than delete", so every test here asks the
//  archive what it actually holds rather than asking a view what it would draw. The two are the
//  same question only when deletion is real.
//

import CipherCrypto
import Foundation
import XCTest

@testable import Cipher

final class DisappearingMessageTests: XCTestCase {

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

    private func makeRepository(now: @escaping @Sendable () -> Date = { Date() })
        -> MessageRepository {
        let client = RoutedStubRelay.client()
        return MessageRepository(
            engine: fixture.engine,
            directory: RelayKeyDirectory(client: client),
            mailbox: RelayMailbox(client: client),
            sessions: TestSession.store(),
            now: now)
    }

    private func routes() async throws -> [String: [RoutedStubRelay.Reply]] {
        let published = try await fixture.peerEngine.generatePublishedKeys(oneTimeCount: 1)
        let identity = try await fixture.peerEngine.localIdentityKey
        let registration = try await fixture.peerEngine.localRegistrationId
        let bundle = """
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
        return [
            "PUT /v1/keys": [
                .init(status: 200, json: #"{"one_time_prekeys":100,"kyber_prekeys":100}"#),
            ],
            "GET /v1/keys/": [.init(status: 200, json: bundle)],
            "POST /v1/messages/ack": [.init(status: 200, json: #"{"acknowledged":1}"#)],
            "POST /v1/messages": [.init(status: 202)],
            "GET /v1/messages": [.init(status: 200, json: #"{"messages":[],"more":false}"#)],
        ]
    }

    /// The envelope the last send put on the wire, decrypted by the peer engine.
    private func payloadSent() async throws -> MessagePayload {
        struct Sent: Decodable {
            let recipient: String
            let envelope: String
        }
        let body = try XCTUnwrap(
            RoutedStubRelay.requests("POST /v1/messages").filter { !$0.isEmpty }.last)
        let decoded = try JSONDecoder().decode(Sent.self, from: body)
        let envelope = try XCTUnwrap(Data(base64Encoded: decoded.envelope))
        let received = try await fixture.peerEngine.decrypt(envelope)
        return try MessagePayload.decode(received.plaintext)
    }

    // MARK: - The timer reaches the wire

    func testAConversationTimerIsCarriedOnEveryMessageItSends() async throws {
        RoutedStubRelay.reset(try await routes())
        let repository = makeRepository()
        try await repository.startConversation(with: fixture.peerAci, nickname: nil)
        try await repository.setDisappearing(seconds: 3600, for: fixture.peerAci)

        _ = try await repository.send(text: "gone in an hour", to: fixture.peerAci)

        // The peer's copy has to expire too, and the only way this device can make that happen
        // is to say so inside the ciphertext. A local-only timer would delete one copy and
        // leave the other, which is the feature not working rather than the feature being
        // partial.
        let payload = try await payloadSent()
        XCTAssertEqual(
            payload, MessagePayload(content: .expiringText("gone in an hour", ttlSeconds: 3600)))
    }

    func testAConversationWithNoTimerStillSendsPlainText() async throws {
        // The positive control for the type discriminator. If every message became
        // `.expiringText`, a build predating this one would refuse all of them.
        RoutedStubRelay.reset(try await routes())
        let repository = makeRepository()
        _ = try await repository.send(text: "no timer", to: fixture.peerAci)

        let payload = try await payloadSent()
        XCTAssertEqual(payload, MessagePayload(content: .text("no timer")))
    }

    func testTurningTheTimerOffStopsMarkingLaterMessages() async throws {
        RoutedStubRelay.reset(try await routes())
        let repository = makeRepository()
        try await repository.startConversation(with: fixture.peerAci, nickname: nil)
        try await repository.setDisappearing(seconds: 30, for: fixture.peerAci)
        _ = try await repository.send(text: "timed", to: fixture.peerAci)

        try await repository.setDisappearing(seconds: nil, for: fixture.peerAci)
        _ = try await repository.send(text: "untimed", to: fixture.peerAci)

        let payload = try await payloadSent()
        XCTAssertEqual(payload, MessagePayload(content: .text("untimed")))
        // And the message sent while it was on keeps its own fate: the timer is on the message,
        // so turning it off later cannot reach back and rescue what was already sent.
        let stored = try await repository.messages(with: fixture.peerAci)
        XCTAssertEqual(stored.count, 2)
        XCTAssertNotNil(stored.first?.expiresAtMs)
        XCTAssertNil(stored.last?.expiresAtMs)
    }

    // MARK: - Deletion, and that it is deletion

    func testAnExpiredMessageIsGoneFromTheArchiveAfterASweep() async throws {
        RoutedStubRelay.reset(try await routes())
        let repository = makeRepository()
        try await repository.startConversation(with: fixture.peerAci, nickname: nil)
        try await repository.setDisappearing(seconds: 30, for: fixture.peerAci)
        _ = try await repository.send(text: "thirty seconds", to: fixture.peerAci)
        _ = try await repository.setDisappearing(seconds: nil, for: fixture.peerAci)
        _ = try await repository.send(text: "kept", to: fixture.peerAci)

        let before = try await repository.messages(with: fixture.peerAci)
        XCTAssertEqual(before.count, 2)

        // A second repository whose clock is past the timer. Nothing was counting down; the
        // message carries the instant it is due and the sweep compares.
        let later = Date().addingTimeInterval(31)
        let swept = makeRepository(now: { later })
        let deleted = try await swept.sweepExpiredMessages()
        XCTAssertEqual(deleted, 1)

        let remaining = try await swept.messages(with: fixture.peerAci)
        XCTAssertEqual(remaining.map(\.text), ["kept"])
    }

    func testASweepBeforeTheTimerEndsDeletesNothing() async throws {
        // The positive control. A sweep that deleted eagerly would pass the test above while
        // destroying messages that were still supposed to exist.
        RoutedStubRelay.reset(try await routes())
        let repository = makeRepository()
        try await repository.startConversation(with: fixture.peerAci, nickname: nil)
        try await repository.setDisappearing(seconds: 3600, for: fixture.peerAci)
        _ = try await repository.send(text: "still here", to: fixture.peerAci)

        let soon = Date().addingTimeInterval(60)
        let swept = makeRepository(now: { soon })
        let deleted = try await swept.sweepExpiredMessages()
        XCTAssertEqual(deleted, 0)
        let remaining = try await swept.messages(with: fixture.peerAci)
        XCTAssertEqual(remaining.map(\.text), ["still here"])
    }

    func testExpirySurvivesARestartAndIsEnforcedOnTheWayBackUp() async throws {
        // The step's own `Done when`: relaunch after expiry finds no row. Nothing here is
        // running while the app is not, so the expiry has to be a stored fact rather than a
        // scheduled callback — which is exactly what a second archive over the same container
        // proves.
        RoutedStubRelay.reset(try await routes())
        let repository = makeRepository()
        try await repository.startConversation(with: fixture.peerAci, nickname: nil)
        try await repository.setDisappearing(seconds: 30, for: fixture.peerAci)
        _ = try await repository.send(text: "survives nothing", to: fixture.peerAci)

        // A fresh archive over the same engine and container: the relaunch. It holds no memory
        // of the send and no timer of its own.
        let reopened = ConversationArchive(engine: fixture.engine)
        let nowMs = UInt64(Date().addingTimeInterval(31).timeIntervalSince1970 * 1000)
        let deleted = try await reopened.deleteExpiredMessages(now: nowMs)
        XCTAssertEqual(deleted, 1)
        let remaining = try await reopened.messages(fixture.peerAci)
        XCTAssertTrue(remaining.isEmpty)
    }

    func testAnUntimedMessageIsNeverSweptHoweverLongItSits() async throws {
        RoutedStubRelay.reset(try await routes())
        let repository = makeRepository()
        _ = try await repository.send(text: "permanent", to: fixture.peerAci)

        let muchLater = Date().addingTimeInterval(400 * 24 * 60 * 60)
        let swept = makeRepository(now: { muchLater })
        let deleted = try await swept.sweepExpiredMessages()
        XCTAssertEqual(deleted, 0)
        let remaining = try await swept.messages(with: fixture.peerAci)
        XCTAssertEqual(remaining.map(\.text), ["permanent"])
    }

    // MARK: - The receiving side

    func testAPeersTimerIsHonouredOnTheReceivingDevice() async throws {
        // The half that makes this a feature rather than a local convenience: a message *from*
        // a peer carrying a timer must expire here too, on a device that never chose it.
        let envelope = try await fixture.envelopeFromPeer(
            content: .expiringText("read fast", ttlSeconds: 30))

        var routes = try await self.routes()
        routes["GET /v1/messages"] = [
            .init(status: 200, json: MessagingFixture.fetchBody([(UUID(), envelope)], more: false)),
        ]
        RoutedStubRelay.reset(routes)

        let repository = makeRepository()
        let received = try await repository.receive()
        XCTAssertEqual(received, 1)
        let stored = try await repository.messages(with: fixture.peerAci)
        XCTAssertEqual(stored.map(\.text), ["read fast"])
        XCTAssertNotNil(
            stored.first?.expiresAtMs,
            "a timer the peer set must be recorded, or their message never disappears here")

        let later = Date().addingTimeInterval(31)
        let swept = makeRepository(now: { later })
        let deleted = try await swept.sweepExpiredMessages()
        XCTAssertEqual(deleted, 1)
        let remaining = try await swept.messages(with: fixture.peerAci)
        XCTAssertTrue(remaining.isEmpty)
    }

    // MARK: - Bounds

    func testATimerBeyondTheWireCeilingCannotBeStored() async throws {
        // A value that could be stored but not sent would make every later send fail with a
        // payload error the user cannot act on.
        RoutedStubRelay.reset(try await routes())
        let repository = makeRepository()
        try await repository.startConversation(with: fixture.peerAci, nickname: nil)
        try await repository.setDisappearing(seconds: 10 * 365 * 24 * 60 * 60, for: fixture.peerAci)

        _ = try await repository.send(text: "clamped", to: fixture.peerAci)
        guard case .expiringText(_, let ttlSeconds) = try await payloadSent().content else {
            return XCTFail("a conversation with a timer must send an expiring payload")
        }
        XCTAssertEqual(ttlSeconds, MessagePayload.maxExpirySeconds)
    }
}
