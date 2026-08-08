//
//  SealedSenderTests.swift
//  CipherCryptoTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//
//  P7.S01 — sealed sender (AUDIT 3.4).
//
//  Two things are being tested here and they pull in opposite directions.
//
//  The first is the property the phase exists for: a relayed frame no longer names its
//  sender, so a seized relay database holds no record of who sent what. That is asserted
//  against the bytes of a real send, with a positive control proving the search can find a
//  sender when one is there.
//
//  The second is that sealing did not become a way *past* the wire boundary. Every refusal
//  the addressed path makes — sender-key payloads (§0.2.2), PlaintextContent (§0.2.4), a
//  second device (§0.2.5), a phone number (§0.2.7) — has to be made again on the inside of
//  the container, because sealing hides the payload from every other check. Each of those
//  refusals gets a test that builds exactly the thing being refused.
//
//  The certificates below are minted by the tests themselves, with keys generated on the
//  spot. That is not a shortcut: it is the honest shape of the scheme. Cipher's relay cannot
//  issue certificates (see `CryptoEngine.selfIssuedSenderCertificate`), so the sending
//  account issues its own, and anyone can issue one naming anyone. Nothing here treats a
//  certificate as evidence, and `testARelabelledCertificateCannotMisattribute` is the
//  demonstration that the code does not either.
//

import Foundation
import LibSignalClient
import XCTest

@testable import CipherCrypto

final class SealedSenderTests: XCTestCase {

    // MARK: - Fixture

    @CryptoActor
    private struct Pair {
        let engine: CryptoEngine
        let local: PeerAddress
        let remote: PeerAddress
        let peer: PeerFixture

        init(root: URL, secrets: SecretStorage = InMemorySecretStorage()) throws {
            engine = try CryptoEngine(root: root, secrets: secrets, now: { 1_700_000_000_000 })
            local = PeerAddress(aci: UUID())
            remote = PeerAddress(aci: UUID())
            peer = try PeerFixture(address: try remote.makeProtocolAddress())
            try engine.adoptLocalAddress(local)
        }

        /// Establishes the session in both directions: the engine starts one from the peer's
        /// bundle, and the peer learns the engine's identity by opening the first message.
        /// Sealing to a recipient needs their identity key, so a peer that has never heard
        /// from us cannot seal to us — which is true of the real thing as well.
        @discardableResult
        func connect() throws -> String {
            try engine.startSession(with: remote, bundle: try peer.makeCipherBundle())
            return try openAtPeer(try engine.encrypt(Data("establish".utf8), to: remote)).text
        }

        /// Opens a frame the engine produced, the way the peer's own client would: the
        /// sender's address comes out of the certificate, because the frame names nobody.
        func openAtPeer(_ envelopeBytes: Data) throws
            -> (text: String, certificate: SenderCertificate) {
            try open(envelopeBytes, at: peer)
        }

        /// The same, at any fixture. Opening is also how a peer *learns* the engine's identity
        /// key, which is what sealing back to it later requires.
        func open(_ envelopeBytes: Data, at fixture: PeerFixture) throws
            -> (text: String, certificate: SenderCertificate) {
            let envelope = try Envelope.decode(envelopeBytes)
            let content = try UnidentifiedSenderMessageContent(
                message: envelope.ciphertext, identityStore: fixture.store,
                context: NullContext())
            let certificate = content.senderCertificate
            let text = try fixture.decrypt(
                content.contents, type: content.messageType,
                from: try ProtocolAddress(
                    name: certificate.senderUuid, deviceId: certificate.deviceId))
            return (text, certificate)
        }

        /// Builds a sealed frame from the peer, with every part of the container overridable
        /// so a test can construct precisely the thing being refused.
        func sealFromPeer(
            _ text: String,
            certificate: SenderCertificate? = nil,
            groupId: Data = Data(),
            type: CiphertextMessage.MessageType? = nil,
            contents: Data? = nil
        ) throws -> Data {
            let message = try peer.encrypt(text, to: try local.makeProtocolAddress())
            let content = try UnidentifiedSenderMessageContent(
                contents ?? message.bytes,
                type: type ?? message.type,
                from: try certificate ?? SealedSenderTests.mintCertificate(
                    uuidString: remote.serviceId.canonicalString,
                    key: peer.identity.identityKey.publicKey),
                contentHint: .default,
                groupId: groupId)
            let sealed = try sealedSenderEncrypt(
                content, for: try local.makeProtocolAddress(),
                identityStore: peer.store, context: NullContext())
            return try Envelope(
                type: .sealed, sender: nil, timestamp: 1_700_000_000_002, ciphertext: sealed
            ).encode()
        }
    }

    /// Mints a certificate with a freshly generated authority, exactly as the app does.
    ///
    /// Anyone can call this with any account's identifier. That is the point: the certificate
    /// is a container field, not a credential, and a test that had to obtain one from
    /// somewhere trusted would be describing a scheme Cipher does not have.
    @CryptoActor
    private static func mintCertificate(
        uuidString: String, deviceId: UInt32 = PeerAddress.primaryDevice,
        e164: String? = nil, key: PublicKey
    ) throws -> SenderCertificate {
        let trustRoot = PrivateKey.generate()
        let serverKey = PrivateKey.generate()
        return try SenderCertificate(
            sender: try SealedSenderAddress(
                e164: e164, uuidString: uuidString, deviceId: deviceId),
            publicKey: key,
            expiration: UInt64.max,
            signerCertificate: try ServerCertificate(
                keyId: 1, publicKey: serverKey.publicKey, trustRoot: trustRoot),
            signerKey: serverKey)
    }

    // MARK: - The relayed frame names nobody

    /// AUDIT 3.4, against the bytes that would actually be stored.
    ///
    /// The check is not "the parsed field is nil" — that would pass on a frame that still
    /// carried the identifier somewhere else. It searches the whole frame for the sender's
    /// wire encoding *and* for the raw UUID, and the positive control proves that search
    /// finds a sender when one is present. Without the control this test would keep passing
    /// if the search were ever silently unable to match anything (AUDIT R2).
    func testTheRelayedFrameNamesNobody() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let pair = try Pair(root: root)
            try pair.connect()

            let bytes = try pair.engine.encrypt(Data("who sent this".utf8), to: pair.remote)
            let envelope = try Envelope.decode(bytes)

            XCTAssertEqual(envelope.type, .sealed)
            XCTAssertNil(envelope.sender)
            XCTAssertEqual(Data(bytes[2..<19]), Data(repeating: 0, count: 17),
                           "the sender slot is zero, not merely unparsed")

            let wireForm = pair.local.serviceId.fixedWidthBinary
            let rawUuid = withUnsafeBytes(of: pair.local.serviceId.uuid.uuid) { Data($0) }

            // Positive control: the same two searches against an addressed frame, which is
            // what every envelope looked like before this step.
            let addressed = try Envelope(
                type: .whisper, sender: pair.local.serviceId, timestamp: 1,
                ciphertext: Data([0x01])).encode()
            XCTAssertNotNil(addressed.range(of: wireForm),
                            "the search cannot find a sender that is there; what follows is void")
            XCTAssertNotNil(addressed.range(of: rawUuid),
                            "the search cannot find a UUID that is there; what follows is void")

            XCTAssertNil(bytes.range(of: wireForm),
                         "the sender's wire encoding survives in the relayed frame")
            XCTAssertNil(bytes.range(of: rawUuid),
                         "the sender's UUID survives in the relayed frame")

            // And the recipient — who has the key — still learns exactly who it was.
            let opened = try pair.openAtPeer(bytes)
            XCTAssertEqual(opened.text, "who sent this")
            XCTAssertEqual(opened.certificate.senderUuid, pair.local.serviceId.canonicalString)
        }.value
    }

    /// The certificate binds this installation's own identity key, carries no phone number,
    /// and names the only device wire v1 has.
    func testTheSelfIssuedCertificateSaysOnlyWhatCipherHas() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let pair = try Pair(root: root)
            try pair.connect()

            let opened = try pair.openAtPeer(
                try pair.engine.encrypt(Data("hello".utf8), to: pair.remote))
            let certificate = opened.certificate

            XCTAssertEqual(certificate.senderUuid, pair.local.serviceId.canonicalString)
            XCTAssertNil(certificate.senderE164, "Cipher has no phone number to put here (§0.2.7)")
            XCTAssertEqual(certificate.deviceId, PeerAddress.primaryDevice, "§0.2.5")
            XCTAssertEqual(certificate.publicKey.serialize(), try pair.engine.localIdentityKey,
                           "the certificate must name the key the session will authenticate")
        }.value
    }

    /// Minted once and reused, including across a restart: it is derived from facts that do
    /// not move, so re-minting per message would be work that changes nothing.
    func testTheCertificateIsMintedOnceAndSurvivesARestart() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }
        let secrets = InMemorySecretStorage()

        let carried = try await Task { @CryptoActor () -> (PeerFixture, PeerAddress, Data) in
            let pair = try Pair(root: root, secrets: secrets)
            try pair.connect()

            let first = try pair.openAtPeer(
                try pair.engine.encrypt(Data("one".utf8), to: pair.remote)).certificate
            let second = try pair.openAtPeer(
                try pair.engine.encrypt(Data("two".utf8), to: pair.remote)).certificate
            XCTAssertEqual(first.serialize(), second.serialize())

            return (pair.peer, pair.remote, first.serialize())
        }.value

        try await Task { @CryptoActor in
            let (peer, remote, before) = carried
            let reopened = try CryptoEngine(root: root, secrets: secrets)

            let envelope = try reopened.encrypt(Data("after restart".utf8), to: remote)
            let content = try UnidentifiedSenderMessageContent(
                message: try Envelope.decode(envelope).ciphertext,
                identityStore: peer.store, context: NullContext())

            XCTAssertEqual(content.senderCertificate.serialize(), before,
                           "the certificate is persisted, not re-minted on every launch")
        }.value
    }

    // MARK: - Receiving a sealed message

    func testASealedMessageIsAttributedToTheSessionThatDecryptedIt() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let pair = try Pair(root: root)
            try pair.connect()

            let decrypted = try pair.engine.decrypt(try pair.sealFromPeer("sealed reply"))

            XCTAssertEqual(decrypted.plaintext, Data("sealed reply".utf8))
            XCTAssertEqual(decrypted.sender, pair.remote)
            XCTAssertEqual(decrypted.senderIdentityKey,
                           pair.peer.identity.identityKey.serialize())
            XCTAssertNil(decrypted.claimedSender, "a sealed frame makes no claim to record")
            XCTAssertFalse(decrypted.establishedSession)
        }.value
    }

    /// A sealed **first** message: the inner type is what decides whether a session is being
    /// established, and after sealing that is the only place it can be read from.
    func testASealedFirstMessageEstablishesTheSession() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let pair = try Pair(root: root)

            // The peer starts the session this time, so the first thing the engine ever sees
            // from this account is a sealed PreKeySignalMessage.
            try processPreKeyBundle(
                try EngineFixture.publishBundle(for: pair.engine, address: pair.local),
                for: try pair.local.makeProtocolAddress(),
                ourAddress: try pair.remote.makeProtocolAddress(),
                sessionStore: pair.peer.store, identityStore: pair.peer.store,
                context: NullContext())

            let decrypted = try pair.engine.decrypt(try pair.sealFromPeer("first contact"))

            XCTAssertEqual(decrypted.plaintext, Data("first contact".utf8))
            XCTAssertEqual(decrypted.sender, pair.remote)
            XCTAssertTrue(decrypted.establishedSession,
                          "the inner type must still be visible after unsealing")
        }.value
    }

    /// Addressed frames keep working, so nothing already on the relay is lost when a build
    /// that seals arrives. Removing this branch is a separate decision with its own cost.
    func testAddressedFramesAreStillAccepted() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let pair = try Pair(root: root)
            try pair.connect()

            let message = try pair.peer.encrypt(
                "from an older build", to: try pair.local.makeProtocolAddress())
            let addressed = try Envelope(
                type: try Envelope.payloadType(for: message.type),
                sender: pair.remote.serviceId, timestamp: 1, ciphertext: message.bytes).encode()

            let decrypted = try pair.engine.decrypt(addressed)
            XCTAssertEqual(decrypted.plaintext, Data("from an older build".utf8))
            XCTAssertEqual(decrypted.claimedSender, pair.remote.serviceId,
                           "an addressed frame still reports what it claimed")
        }.value
    }

    // MARK: - The boundary refusals apply inside the container

    /// §0.2.2. A group id is the field a sender-key message would carry, and it travels
    /// inside the sealed container where no other check can see it.
    func testASealedGroupPayloadIsRefused() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let pair = try Pair(root: root)
            try pair.connect()

            let framed = try pair.sealFromPeer("would be a group message", groupId: Data([0x01]))
            XCTAssertThrowsError(try pair.engine.decrypt(framed)) { error in
                XCTAssertEqual(error as? EnvelopeError, .groupMessagingNotSupported)
            }

            // The refusal must not have stepped the ratchet on its way out.
            XCTAssertEqual(
                try pair.engine.decrypt(try pair.sealFromPeer("still works")).plaintext,
                Data("still works".utf8))
        }.value
    }

    /// §0.2.4 and §0.2.2 again, this time through the payload type rather than the group id.
    ///
    /// Every libsignal message type outside the two live ones is swept. Two of them are the
    /// ones that matter — `plaintext` carries `DecryptionErrorMessage`, `senderKey` is a group
    /// message — and the test asserts those two specifically reached *our* refusal, so a
    /// future libsignal that refused to build the container itself could not quietly turn this
    /// into a test of libsignal's constructor.
    func testASealedPlaintextContentOrSenderKeyPayloadIsRefused() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let pair = try Pair(root: root)
            try pair.connect()

            let live: Set<UInt8> = [
                CiphertextMessage.MessageType.preKey.rawValue,
                CiphertextMessage.MessageType.whisper.rawValue,
            ]
            var refusedByUs: Set<UInt8> = []

            for raw in UInt8(0)...UInt8(16) where !live.contains(raw) {
                let type = CiphertextMessage.MessageType(rawValue: raw)
                // A container libsignal will not even build is refused earlier than here,
                // which is also acceptable — but it is recorded as such rather than counted
                // as a refusal this module made.
                guard let framed = try? pair.sealFromPeer("refused", type: type) else { continue }

                XCTAssertThrowsError(try pair.engine.decrypt(framed),
                                     "inner type \(raw) must not be accepted") { error in
                    guard let envelopeError = error as? EnvelopeError else {
                        return XCTFail("inner type \(raw) failed as \(error), not as a refusal")
                    }
                    refusedByUs.insert(raw)
                    switch raw {
                    case CiphertextMessage.MessageType.senderKey.rawValue:
                        XCTAssertEqual(envelopeError, .groupMessagingNotSupported)
                    case CiphertextMessage.MessageType.plaintext.rawValue:
                        XCTAssertEqual(envelopeError, .unauthenticatedPayloadRefused)
                    default:
                        XCTAssertEqual(envelopeError, .unknownPayloadType(raw))
                    }
                }
            }

            XCTAssertTrue(
                refusedByUs.contains(CiphertextMessage.MessageType.senderKey.rawValue),
                "the sender-key case never reached this module's refusal; §0.2.2 is untested here")
            XCTAssertTrue(
                refusedByUs.contains(CiphertextMessage.MessageType.plaintext.rawValue),
                "the PlaintextContent case never reached this module's refusal; §0.2.4 untested")
        }.value
    }

    /// §0.2.5. libsignal's certificate has a `deviceId`; wire v1 deliberately does not.
    /// Accepting one here would let multi-device arrive through the sealed container without
    /// the `wireVersion` 2 the locked decision requires.
    func testASealedCertificateNamingASecondDeviceIsRefused() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let pair = try Pair(root: root)
            try pair.connect()

            let framed = try pair.sealFromPeer(
                "from device two",
                certificate: try Self.mintCertificate(
                    uuidString: pair.remote.serviceId.canonicalString, deviceId: 2,
                    key: pair.peer.identity.identityKey.publicKey))

            XCTAssertThrowsError(try pair.engine.decrypt(framed)) { error in
                XCTAssertEqual(error as? EnvelopeError, .sealedSenderDeviceRefused(2))
            }
        }.value
    }

    /// §0.2.7. The certificate has an `e164` field. Cipher has never had a value for it, and
    /// a field nobody fills is one an attacker can fill, so it is refused rather than ignored.
    func testASealedCertificateCarryingAPhoneNumberIsRefused() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let pair = try Pair(root: root)
            try pair.connect()

            let framed = try pair.sealFromPeer(
                "with a phone number",
                certificate: try Self.mintCertificate(
                    uuidString: pair.remote.serviceId.canonicalString,
                    e164: "+15551234567",
                    key: pair.peer.identity.identityKey.publicKey))

            XCTAssertThrowsError(try pair.engine.decrypt(framed)) { error in
                XCTAssertEqual(error as? EnvelopeError, .sealedSenderIdentifierRefused)
            }
        }.value
    }

    /// A PNI is representable in the certificate's identifier string and Cipher never issues
    /// one. Refused rather than resolved to the same UUID in the ACI namespace, which would
    /// map two different identities onto one store slot.
    func testASealedCertificateNamingAPniIsRefused() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let pair = try Pair(root: root)
            try pair.connect()

            let framed = try pair.sealFromPeer(
                "from a PNI",
                certificate: try Self.mintCertificate(
                    uuidString: Pni(fromUUID: pair.remote.serviceId.uuid).serviceIdString,
                    key: pair.peer.identity.identityKey.publicKey))

            XCTAssertThrowsError(try pair.engine.decrypt(framed)) { error in
                XCTAssertEqual(error as? EnvelopeError, .sealedSenderIdentifierRefused)
            }
        }.value
    }

    /// The layer underneath: libsignal binds the certificate's **key** to the account that
    /// sealed the container, and refuses one that names a key its sealer does not hold.
    ///
    /// Pinned here even though it is upstream's check, not ours, because the refusal in the
    /// next test is only meaningful while this one holds — together they say "the sealer is
    /// the session owner". If a libsignal release stopped enforcing it, this test is where
    /// that shows up, rather than in a silently weaker guarantee two layers away.
    func testACertificateKeyTheSealerDoesNotHoldIsRefused() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let pair = try Pair(root: root)
            try pair.connect()

            let framed = try pair.sealFromPeer(
                "a key the sealer does not hold",
                certificate: try Self.mintCertificate(
                    uuidString: pair.remote.serviceId.canonicalString,
                    key: PrivateKey.generate().publicKey))

            XCTAssertThrowsError(try pair.engine.decrypt(framed)) { error in
                guard case SignalError.invalidMessage = error else {
                    return XCTFail("expected libsignal to refuse the container, got \(error)")
                }
            }

            // Positive control: the same message with a certificate that agrees is accepted,
            // so the refusal above is about the key and not about the fixture.
            XCTAssertEqual(
                try pair.engine.decrypt(try pair.sealFromPeer("right key")).plaintext,
                Data("right key".utf8))
        }.value
    }

    /// The sealed analogue of `MessagingTests.testRewrittenEnvelopeSenderCannotMisattribute`,
    /// and the reason this module checks the certificate key against the session at all.
    ///
    /// Sealing needs only the recipient's **public** identity key, so anyone holding a
    /// plaintext Signal ciphertext — a relay that captured an addressed frame, say — can wrap
    /// it in a container of their own. libsignal is satisfied, because such a sealer names its
    /// own key in the certificate, as the previous test requires. The label can even be
    /// correct: this one names the account the ciphertext really came from, so the inner
    /// decrypt succeeds and every other check passes.
    ///
    /// What the attacker cannot do is make the certificate's key be that account's key. The
    /// refusal is that disagreement, and it is the difference between "this message is from B"
    /// and "B sent this message": without it, a third party chooses when B's mail is
    /// delivered, and the recipient cannot tell.
    func testAThirdPartyCannotResealAnotherAccountsCiphertext() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let pair = try Pair(root: root)
            try pair.connect()

            // A third account, which learns the engine's identity key by opening a message —
            // that key is all sealing to the engine requires.
            let other = PeerAddress(aci: UUID())
            let otherPeer = try PeerFixture(address: try other.makeProtocolAddress())
            try pair.engine.startSession(with: other, bundle: try otherPeer.makeCipherBundle())
            _ = try pair.open(
                try pair.engine.encrypt(Data("hello".utf8), to: other), at: otherPeer)

            // The real peer's ciphertext, taken as a relay would have it from an addressed
            // frame, re-sealed by `otherPeer` under a certificate that names the peer
            // correctly and carries `otherPeer`'s key — the only key it could carry.
            let captured = try pair.peer.encrypt(
                "genuinely from the peer", to: try pair.local.makeProtocolAddress())
            let content = try UnidentifiedSenderMessageContent(
                captured.bytes, type: captured.type,
                from: try Self.mintCertificate(
                    uuidString: pair.remote.serviceId.canonicalString,
                    key: otherPeer.identity.identityKey.publicKey),
                contentHint: .default, groupId: Data())
            let resealed = try Envelope(
                type: .sealed, sender: nil, timestamp: 1,
                ciphertext: try sealedSenderEncrypt(
                    content, for: try pair.local.makeProtocolAddress(),
                    identityStore: otherPeer.store, context: NullContext())
            ).encode()

            XCTAssertThrowsError(try pair.engine.decrypt(resealed)) { error in
                XCTAssertEqual(error as? EnvelopeError, .sealedSenderKeyMismatch)
            }

            // And the conversation survives the refusal: the peer's own next message still
            // arrives, so this cost the attacker a message rather than the session.
            XCTAssertEqual(
                try pair.engine.decrypt(try pair.sealFromPeer("still the peer")).sender,
                pair.remote)
        }.value
    }
}
