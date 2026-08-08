//
//  AttachmentTests.swift
//  CipherTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//
//  P6.S04. Two properties, and both are asserted against what actually left the device or what
//  is actually on disk rather than against the shape of the code:
//
//    * the relay only ever receives opaque blobs — the step's anti-goal is "upload then
//      encrypt", so the gate below is applied to the bytes of the real upload and is also shown
//      to fail when the defect is reintroduced;
//    * the encrypted media cache is wiped when a message is deleted or disappears, which is
//      also what makes P6.S03's media clause testable for the first time.
//

import CipherCrypto
import Foundation
import XCTest

@testable import Cipher

final class AttachmentTests: XCTestCase {

    private var fixture: MessagingFixture!

    /// Recognisable, so "does the upload contain the plaintext?" is a question with a real
    /// answer rather than a coincidence of random bytes.
    private let photoBytes = Data("PLAINTEXT-PHOTO-BYTES-THAT-MUST-NEVER-BE-UPLOADED".utf8)

    private let blobId = UUID(uuidString: "9f14a2b6-1111-4222-8333-444455556666")!

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

    // MARK: - Harness

    private func makeRepository(now: @escaping @Sendable () -> Date = { Date() })
        -> MessageRepository {
        let client = RoutedStubRelay.client()
        return MessageRepository(
            engine: fixture.engine,
            directory: RelayKeyDirectory(client: client),
            mailbox: RelayMailbox(client: client),
            blobs: RelayBlobStore(client: client),
            sessions: TestSession.store(),
            now: now)
    }

    private func routes(
        blobDownload: RoutedStubRelay.Reply? = nil
    ) async throws -> [String: [RoutedStubRelay.Reply]] {
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

        var routes: [String: [RoutedStubRelay.Reply]] = [
            "PUT /v1/keys": [
                .init(status: 200, json: #"{"one_time_prekeys":100,"kyber_prekeys":100}"#),
            ],
            "GET /v1/keys/": [.init(status: 200, json: bundle)],
            "POST /v1/messages/ack": [.init(status: 200, json: #"{"acknowledged":1}"#)],
            "POST /v1/messages": [.init(status: 202)],
            "GET /v1/messages": [.init(status: 200, json: #"{"messages":[],"more":false}"#)],
            "DELETE /v1/blobs/": [.init(status: 204)],
        ]
        if let blobDownload {
            routes["GET /v1/blobs/"] = [blobDownload]
        }
        return routes
    }

    /// The relay's answer to an upload of `byteCount` ciphertext bytes, which it echoes back.
    private func uploadReply(byteCount: Int) -> RoutedStubRelay.Reply {
        .init(
            status: 201,
            json: """
            {"id":"\(blobId.uuidString.lowercased())","size":\(byteCount),\
            "expires_at":"2026-12-31T00:00:00Z"}
            """)
    }

    /// The bytes the last upload put on the wire.
    private func uploadedBody() throws -> Data {
        try XCTUnwrap(RoutedStubRelay.requests("POST /v1/blobs").filter { !$0.isEmpty }.last)
    }

    /// The payload the last send put inside the envelope, as the peer would read it.
    private func payloadSent() async throws -> MessagePayload {
        struct Sent: Decodable {
            let envelope: String
        }
        let body = try XCTUnwrap(
            RoutedStubRelay.requests("POST /v1/messages").filter { !$0.isEmpty }.last)
        let decoded = try JSONDecoder().decode(Sent.self, from: body)
        let envelope = try XCTUnwrap(Data(base64Encoded: decoded.envelope))
        return try MessagePayload.decode(
            try await fixture.peerEngine.decrypt(envelope).plaintext)
    }

    // MARK: - The relay only ever receives an opaque blob

    /// The gate, written as a function so it can be shown to fail.
    ///
    /// Three separate ways an upload could be the plaintext: it could *be* it, it could contain
    /// it, or it could be the right size to be it. A checker that only compared equality would
    /// pass against a body with one byte prepended.
    private static func isOpaqueUpload(_ body: Data, hiding plaintext: Data) -> Bool {
        body != plaintext
            && body.range(of: plaintext) == nil
            && body.count == AttachmentCipher.ciphertextSize(forPlaintext: plaintext.count)
    }

    func testTheRelayReceivesCiphertextAndNeverThePlaintext() async throws {
        var routes = try await routes()
        routes["POST /v1/blobs"] = [
            uploadReply(byteCount: AttachmentCipher.ciphertextSize(
                forPlaintext: photoBytes.count)),
        ]
        RoutedStubRelay.reset(routes)

        let repository = makeRepository()
        _ = try await repository.sendAttachment(bytes: photoBytes, to: fixture.peerAci)

        let uploaded = try uploadedBody()
        XCTAssertTrue(
            Self.isOpaqueUpload(uploaded, hiding: photoBytes),
            "the bytes handed to the relay were not opaque")

        // The negative control. Reintroduce the defect the step names — upload the plaintext —
        // and the same checker must refuse it. Without this, a checker that always returned
        // true would report a clean tree it never read (AUDIT R2).
        XCTAssertFalse(
            Self.isOpaqueUpload(photoBytes, hiding: photoBytes),
            "the gate accepted a plaintext upload, so it proves nothing about the real one")
    }

    func testTheKeyTravelsInsideTheCiphertextAndOpensTheUploadedBlob() async throws {
        var routes = try await routes()
        routes["POST /v1/blobs"] = [
            uploadReply(byteCount: AttachmentCipher.ciphertextSize(
                forPlaintext: photoBytes.count)),
        ]
        RoutedStubRelay.reset(routes)

        let repository = makeRepository()
        _ = try await repository.sendAttachment(bytes: photoBytes, to: fixture.peerAci)

        // Read the way the recipient reads it: out of the end-to-end ciphertext, which is the
        // only place the key exists on the wire.
        guard case .attachment(let pointer) = try await payloadSent().content else {
            return XCTFail("the message did not carry an attachment pointer")
        }
        XCTAssertEqual(pointer.blobId, blobId)
        XCTAssertEqual(pointer.byteCount, photoBytes.count)

        let opened = try AttachmentCipher.open(
            ciphertext: try uploadedBody(), key: pointer.key, digest: pointer.digest,
            plaintextByteCount: pointer.byteCount)
        XCTAssertEqual(opened, photoBytes)
    }

    func testAFailedUploadSendsNothingAndStoresNothing() async throws {
        var routes = try await routes()
        routes["POST /v1/blobs"] = [.init(status: 429)]
        RoutedStubRelay.reset(routes)

        let repository = makeRepository()
        do {
            _ = try await repository.sendAttachment(bytes: photoBytes, to: fixture.peerAci)
            XCTFail("a refused upload must not produce a message")
        } catch let failure as MessageRepository.Failure {
            XCTAssertEqual(failure, .rateLimited)
        }

        // A stored message would be a bubble pointing at a blob that does not exist, on a
        // device that has no copy of the bytes either.
        let stored = try await repository.messages(with: fixture.peerAci)
        let cached = try await fixture.engine.cachedAttachmentIds()
        XCTAssertTrue(stored.isEmpty)
        XCTAssertTrue(cached.isEmpty)
        XCTAssertEqual(RoutedStubRelay.count("POST /v1/messages"), 0)
    }

    func testASendRefusedAtSessionSetupUploadsNothing() async throws {
        // The session is established *before* the blob is sealed and uploaded, which is the
        // opposite order to a text send and is the point. A refusal that is known before any
        // bytes are encrypted — no published bundle here, and a changed identity key the user
        // has not accepted, which `startSession` raises the same way — must not have already
        // put a week of unopenable ciphertext on the relay and charged the account's daily
        // quota for it.
        var routes = try await routes()
        routes["GET /v1/keys/"] = [.init(status: 404)]
        routes["POST /v1/blobs"] = [
            uploadReply(byteCount: AttachmentCipher.ciphertextSize(
                forPlaintext: photoBytes.count)),
        ]
        RoutedStubRelay.reset(routes)

        let repository = makeRepository()
        do {
            _ = try await repository.sendAttachment(bytes: photoBytes, to: fixture.peerAci)
            XCTFail("a peer with no bundle cannot be sent to")
        } catch let failure as MessageRepository.Failure {
            XCTAssertEqual(failure, .peerUnavailable)
        }

        XCTAssertEqual(
            RoutedStubRelay.count("POST /v1/blobs"), 0,
            "a refused send left an attachment on the relay")
        let stored = try await repository.messages(with: fixture.peerAci)
        XCTAssertTrue(stored.isEmpty)
    }

    // MARK: - The cache is wiped on disappear

    func testAnExpiredAttachmentTakesItsCachedBlobWithIt() async throws {
        var routes = try await routes()
        routes["POST /v1/blobs"] = [
            uploadReply(byteCount: AttachmentCipher.ciphertextSize(
                forPlaintext: photoBytes.count)),
        ]
        RoutedStubRelay.reset(routes)

        let sentAt = Date(timeIntervalSince1970: 1_000_000)
        let sender = makeRepository(now: { sentAt })
        try await sender.startConversation(with: fixture.peerAci, nickname: nil)
        try await sender.setDisappearing(seconds: 30, for: fixture.peerAci)
        _ = try await sender.sendAttachment(bytes: photoBytes, to: fixture.peerAci)

        // Before: the row exists and its ciphertext is cached.
        let beforeCount = try await sender.messages(with: fixture.peerAci).count
        let beforeCache = try await fixture.engine.cachedAttachmentIds()
        XCTAssertEqual(beforeCount, 1)
        XCTAssertEqual(beforeCache, [blobId])

        let later = makeRepository(now: { sentAt.addingTimeInterval(31) })
        let swept = try await later.sweepExpiredMessages()
        XCTAssertEqual(swept, 1)

        // Deleted, not hidden — and the media half of it, which is what P6.S03 could only
        // state because there were no attachments to delete.
        let remaining = try await later.messages(with: fixture.peerAci)
        let afterCache = try await fixture.engine.cachedAttachmentIds()
        XCTAssertTrue(remaining.isEmpty)
        XCTAssertTrue(
            afterCache.isEmpty,
            "the message disappeared but its decryptable blob stayed on disk")
    }

    func testDeletingAnAttachmentMessageWipesItsCachedBlob() async throws {
        var routes = try await routes()
        routes["POST /v1/blobs"] = [
            uploadReply(byteCount: AttachmentCipher.ciphertextSize(
                forPlaintext: photoBytes.count)),
        ]
        RoutedStubRelay.reset(routes)

        let repository = makeRepository()
        let sent = try await repository.sendAttachment(bytes: photoBytes, to: fixture.peerAci)
        let cachedBefore = try await fixture.engine.cachedAttachmentIds()
        XCTAssertEqual(cachedBefore, [blobId])

        try await repository.deleteMessage(ordinal: sent.ordinal, in: fixture.peerAci)
        let wiped = try await repository.wipeOrphanedAttachments()
        let cachedAfter = try await fixture.engine.cachedAttachmentIds()
        XCTAssertEqual(wiped, 1)
        XCTAssertTrue(cachedAfter.isEmpty)
    }

    func testTheWipeKeepsBlobsAMessageStillPointsAt() async throws {
        // The positive control for the sweep. A wipe that removed everything would pass the two
        // tests above while destroying every attachment on the device.
        var routes = try await routes()
        routes["POST /v1/blobs"] = [
            uploadReply(byteCount: AttachmentCipher.ciphertextSize(
                forPlaintext: photoBytes.count)),
        ]
        RoutedStubRelay.reset(routes)

        let repository = makeRepository()
        _ = try await repository.sendAttachment(bytes: photoBytes, to: fixture.peerAci)

        let wiped = try await repository.wipeOrphanedAttachments()
        let cached = try await fixture.engine.cachedAttachmentIds()
        XCTAssertEqual(wiped, 0)
        XCTAssertEqual(cached, [blobId])
    }

    func testAClearedConversationLeavesNoAttachmentBehind() async throws {
        var routes = try await routes()
        routes["POST /v1/blobs"] = [
            uploadReply(byteCount: AttachmentCipher.ciphertextSize(
                forPlaintext: photoBytes.count)),
        ]
        RoutedStubRelay.reset(routes)

        let repository = makeRepository()
        _ = try await repository.sendAttachment(bytes: photoBytes, to: fixture.peerAci)

        // `clearMessages` removes rows in bulk without decoding them, so it cannot name the
        // blobs it just orphaned. Deriving the live set from what remains is what covers it.
        try await repository.clearMessages(in: fixture.peerAci)
        let wiped = try await repository.wipeOrphanedAttachments()
        let cached = try await fixture.engine.cachedAttachmentIds()
        XCTAssertEqual(wiped, 1)
        XCTAssertTrue(cached.isEmpty)
    }

    // MARK: - Receiving

    func testAReceivedAttachmentIsFetchedVerifiedCachedAndShreddedOnTheRelay() async throws {
        let sealed = try AttachmentCipher.seal(photoBytes)
        let envelope = try await fixture.envelopeFromPeer(
            content: .attachment(MessagePayload.Attachment(
                blobId: blobId, key: sealed.key, digest: sealed.digest,
                byteCount: sealed.plaintextByteCount, ttlSeconds: nil)))

        var routes = try await routes(
            blobDownload: .init(status: 200, bytes: sealed.ciphertext))
        routes["GET /v1/messages"] = [
            .init(status: 200, json: MessagingFixture.fetchBody([(UUID(), envelope)])),
            .init(status: 200, json: #"{"messages":[],"more":false}"#),
        ]
        RoutedStubRelay.reset(routes)

        let repository = makeRepository()
        let received = try await repository.receive()
        XCTAssertEqual(received, 1)

        // Nothing is fetched by receiving: a device that pulled every attachment on delivery
        // would tell the relay which account wanted which blob, the moment it arrived.
        let cacheOnReceive = try await fixture.engine.cachedAttachmentIds()
        XCTAssertEqual(RoutedStubRelay.count("GET /v1/blobs/"), 0)
        XCTAssertTrue(cacheOnReceive.isEmpty)

        let stored = try await repository.messages(with: fixture.peerAci)
        XCTAssertEqual(stored.count, 1)
        let ordinal = try XCTUnwrap(stored.first).ordinal
        let opened = try await repository.attachmentBytes(
            ordinal: ordinal, in: fixture.peerAci)
        XCTAssertEqual(opened, photoBytes)

        let cacheOnOpen = try await fixture.engine.cachedAttachmentIds()
        XCTAssertEqual(RoutedStubRelay.count("GET /v1/blobs/"), 1)
        XCTAssertEqual(cacheOnOpen, [blobId])
        // The recipient holds a verified copy, so the relay's retention has no purpose left.
        XCTAssertEqual(RoutedStubRelay.count("DELETE /v1/blobs/"), 1)

        // And a second open is served from disk rather than from the relay.
        _ = try await repository.attachmentBytes(ordinal: ordinal, in: fixture.peerAci)
        XCTAssertEqual(RoutedStubRelay.count("GET /v1/blobs/"), 1)
    }

    func testABlobThatIsNotTheOneTheMessageNamedIsRefusedAndNeverCached() async throws {
        let sealed = try AttachmentCipher.seal(photoBytes)
        // A different, perfectly valid blob of exactly the same length: the substitution a
        // hostile relay is actually able to make.
        let substitute = try AttachmentCipher.seal(photoBytes)

        let envelope = try await fixture.envelopeFromPeer(
            content: .attachment(MessagePayload.Attachment(
                blobId: blobId, key: sealed.key, digest: sealed.digest,
                byteCount: sealed.plaintextByteCount, ttlSeconds: nil)))

        var routes = try await routes(
            blobDownload: .init(status: 200, bytes: substitute.ciphertext))
        routes["GET /v1/messages"] = [
            .init(status: 200, json: MessagingFixture.fetchBody([(UUID(), envelope)])),
            .init(status: 200, json: #"{"messages":[],"more":false}"#),
        ]
        RoutedStubRelay.reset(routes)

        let repository = makeRepository()
        let received = try await repository.receive()
        XCTAssertEqual(received, 1)
        let stored = try await repository.messages(with: fixture.peerAci)
        let ordinal = try XCTUnwrap(stored.first).ordinal

        do {
            _ = try await repository.attachmentBytes(ordinal: ordinal, in: fixture.peerAci)
            XCTFail("a substituted blob must not be returned")
        } catch let failure as MessageRepository.Failure {
            XCTAssertEqual(failure, .attachmentUnavailable)
        }

        // Refused before the disk, so a relay cannot make this device store bytes it rejected —
        // and the relay's copy is not deleted, because nothing verified was received.
        let cached = try await fixture.engine.cachedAttachmentIds()
        XCTAssertTrue(cached.isEmpty)
        XCTAssertEqual(RoutedStubRelay.count("DELETE /v1/blobs/"), 0)
    }

    func testAnAttachmentWhoseBlobIsGoneReportsItRatherThanHanging() async throws {
        let sealed = try AttachmentCipher.seal(photoBytes)
        let envelope = try await fixture.envelopeFromPeer(
            content: .attachment(MessagePayload.Attachment(
                blobId: blobId, key: sealed.key, digest: sealed.digest,
                byteCount: sealed.plaintextByteCount, ttlSeconds: nil)))

        var routes = try await routes(blobDownload: .init(status: 404))
        routes["GET /v1/messages"] = [
            .init(status: 200, json: MessagingFixture.fetchBody([(UUID(), envelope)])),
            .init(status: 200, json: #"{"messages":[],"more":false}"#),
        ]
        RoutedStubRelay.reset(routes)

        let repository = makeRepository()
        let received = try await repository.receive()
        XCTAssertEqual(received, 1)
        let stored = try await repository.messages(with: fixture.peerAci)
        let ordinal = try XCTUnwrap(stored.first).ordinal

        do {
            _ = try await repository.attachmentBytes(ordinal: ordinal, in: fixture.peerAci)
            XCTFail("a missing blob must be reported")
        } catch let failure as MessageRepository.Failure {
            // Same case as a failed integrity check on purpose: which of its answers this
            // device rejected is not something the relay may learn from the behaviour.
            XCTAssertEqual(failure, .attachmentUnavailable)
        }
    }

    // MARK: - Storage

    func testACachedBlobSurvivesNothingAnAccountEraseLeavesBehind() async throws {
        // The cache lives inside the crypto container precisely so this holds without a second
        // erase path that could be forgotten.
        try await fixture.engine.storeAttachment(
            id: blobId, ciphertext: Data(repeating: 9, count: 64))
        let cached = try await fixture.engine.cachedAttachmentIds()
        XCTAssertEqual(cached, [blobId])

        try await fixture.engine.destroyAllState()

        // Every operation refuses afterwards, and the bytes are gone with the container.
        do {
            _ = try await fixture.engine.cachedAttachmentIds()
            XCTFail("a destroyed engine must not answer for its attachment cache")
        } catch {
            XCTAssertEqual(error as? CryptoEngineError, .destroyed)
        }
    }
}
