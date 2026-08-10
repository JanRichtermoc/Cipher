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
                    name: certificate.senderUuid, deviceId: certificate.deviceId),
                padded: true)
            return (text, certificate)
        }

        /// Builds a sealed frame from the peer, with every part of the container overridable
        /// so a test can construct precisely the thing being refused.
        ///
        /// The text is padded first (P7.S02), because a sealed frame carries a padded plaintext
        /// and a fixture that skipped that would be modelling a client Cipher does not ship.
        /// `padded: false` builds the frame such a client *would* send, which is refused —
        /// `testASealedFrameWithoutPaddingIsRefused`.
        func sealFromPeer(
            _ text: String,
            certificate: SenderCertificate? = nil,
            groupId: Data = Data(),
            type: CiphertextMessage.MessageType? = nil,
            contents: Data? = nil,
            padded: Bool = true
        ) throws -> Data {
            let body = padded
                ? try MessagePadding.pad(Data(text.utf8))
                : Data(text.utf8)
            let message = try peer.encrypt(body, to: try local.makeProtocolAddress())
            let content = try UnidentifiedSenderMessageContent(
                contents ?? message.bytes,
                type: type ?? message.type,
                from: try certificate ?? SealedFrame.certificate(
                    naming: remote.serviceId.canonicalString,
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

    /// A peer fixture that has fetched the engine's published bundle, which is all it takes to
    /// start a conversation with it: the bundle is public and the relay serves it to anyone.
    ///
    /// `address` is the address the fixture encrypts under. That is a field a client fills in
    /// for itself — nothing ties it to the ACI the relay issued the account — so passing
    /// another account's address here models a client that lies about who it is.
    @CryptoActor
    private static func startSession(towards pair: Pair, as address: ProtocolAddress) throws
        -> PeerFixture {
        let fixture = try PeerFixture(address: address)
        try processPreKeyBundle(
            try EngineFixture.publishBundle(for: pair.engine, address: pair.local),
            for: try pair.local.makeProtocolAddress(),
            ourAddress: fixture.address,
            sessionStore: fixture.store, identityStore: fixture.store,
            context: NullContext())
        return fixture
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

    /// A sealed frame carries a padded plaintext (P7.S02), and one that does not is refused
    /// rather than delivered.
    ///
    /// The two features are coupled on purpose — a frame is padded exactly when it is sealed,
    /// so the receive path needs no heuristic — and this is the edge that coupling creates: a
    /// peer that seals without padding. Refusing costs that message. Accepting would mean
    /// returning the terminator and its zero fill to the caller as content, and those bytes are
    /// valid UTF-8, so nothing further downstream would notice.
    func testASealedFrameWithoutPaddingIsRefused() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let pair = try Pair(root: root)
            try pair.connect()

            XCTAssertThrowsError(
                try pair.engine.decrypt(try pair.sealFromPeer("unpadded", padded: false))
            ) { error in
                XCTAssertEqual(error as? MessagingError, .malformedPadding)
            }

            // Positive control: the same peer, padding as a shipped client does, is accepted.
            XCTAssertEqual(
                try pair.engine.decrypt(try pair.sealFromPeer("padded")).plaintext,
                Data("padded".utf8))
        }.value
    }

    /// An addressed frame on an **established** session keeps working, so a message already on
    /// the relay when a sealing build arrives is not lost.
    ///
    /// This half survives the AUDIT 3.8 retirement below, and the reason is the ratchet: a
    /// `SignalMessage` verifies only under the keys of the session it belongs to, so a rewritten
    /// sender costs the attacker a dropped message rather than a misattributed one
    /// (`MessagingTests.testRewrittenEnvelopeSenderCannotMisattribute`). Nothing about the
    /// weakness that closed the other branch applies here.
    func testAddressedFramesOnAnEstablishedSessionAreStillAccepted() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let pair = try Pair(root: root)
            try pair.connect()

            let message = try pair.peer.encrypt(
                "from an older build", to: try pair.local.makeProtocolAddress())
            XCTAssertEqual(message.type, .whisper,
                           "this test must exercise the branch that survived, not the retired one")

            let addressed = try Envelope(
                type: try Envelope.payloadType(for: message.type),
                sender: pair.remote.serviceId, timestamp: 1, ciphertext: message.bytes).encode()

            let decrypted = try pair.engine.decrypt(addressed)
            XCTAssertEqual(decrypted.plaintext, Data("from an older build".utf8))
            XCTAssertEqual(decrypted.claimedSender, pair.remote.serviceId,
                           "an addressed frame still reports what it claimed")
            XCTAssertFalse(decrypted.establishedSession)
        }.value
    }

    /// AUDIT 3.8: the addressed **first** message is refused.
    ///
    /// The frame this builds is exactly what a pre-P7.S01 client sent to open a conversation,
    /// and it is the one frame whose label nothing could check — the identity key arrives
    /// inside the message, so there is no stored key for a wrong name to disagree with. The
    /// test above is the control that keeps this from being a blanket ban on addressed frames.
    ///
    /// The cost is real and is asserted rather than described: this message is genuine, it
    /// decrypts, and it is refused anyway. What makes that affordable is that no build has
    /// produced one since P7.S01 — `CryptoEngine.encrypt` seals unconditionally — and that the
    /// sealed replacement binds the sender's address into the ciphertext, so the same lie now
    /// costs an attacker a session it must actually hold.
    func testAnAddressedFirstMessageIsRefused() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let pair = try Pair(root: root)
            let peer = try Self.startSession(
                towards: pair, as: try pair.remote.makeProtocolAddress())

            let message = try peer.encrypt(
                "first contact from an older build", to: try pair.local.makeProtocolAddress())
            XCTAssertEqual(message.type, .preKey, "this must be the frame under test")

            let addressed = try Envelope(
                type: try Envelope.payloadType(for: message.type),
                sender: pair.remote.serviceId, timestamp: 1, ciphertext: message.bytes).encode()

            XCTAssertThrowsError(try pair.engine.decrypt(addressed)) { error in
                XCTAssertEqual(error as? EnvelopeError, .addressedFirstMessageRefused)
            }

            // Refused before any session, prekey or ratchet state was touched: the peer is
            // still unknown, so the refusal cost a message rather than leaving half a session
            // behind for the next one to trip over.
            XCTAssertNil(try pair.engine.peerIdentityState(for: pair.remote))
            XCTAssertFalse(try pair.engine.hasSession(with: pair.remote))

            // And the sealed frame the same peer would send today is accepted, which is what
            // makes this a retirement rather than a lockout.
            let sealed = try pair.engine.decrypt(
                try SealedFrame.firstMessage(
                    "first contact", from: peer, naming: pair.remote, to: pair.local))
            XCTAssertEqual(sealed.plaintext, Data("first contact".utf8))
            XCTAssertTrue(sealed.establishedSession)
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
                certificate: try SealedFrame.certificate(
                    naming: pair.remote.serviceId.canonicalString, deviceId: 2,
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
                certificate: try SealedFrame.certificate(
                    naming: pair.remote.serviceId.canonicalString,
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
                certificate: try SealedFrame.certificate(
                    naming: Pni(fromUUID: pair.remote.serviceId.uuid).serviceIdString,
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
                certificate: try SealedFrame.certificate(
                    naming: pair.remote.serviceId.canonicalString,
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
                try MessagePadding.pad(Data("genuinely from the peer".utf8)),
                to: try pair.local.makeProtocolAddress())
            let content = try UnidentifiedSenderMessageContent(
                captured.bytes, type: captured.type,
                from: try SealedFrame.certificate(
                    naming: pair.remote.serviceId.canonicalString,
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

    // MARK: - The residual the certificate cannot cover (AUDIT 3.8)

    /// AUDIT 3.8, as amended 2026-08-09, which until now no test pinned.
    ///
    /// The test above stops a third party re-sealing **someone else's** ciphertext. This one is
    /// what remains once that is closed, and it is a different sentence: an account that seals
    /// its **own** ciphertext chooses the name on it, because the certificate is self-issued
    /// (`CryptoEngine.selfIssuedSenderCertificate`), the key it must carry is the sealer's, and
    /// the address bound into the ciphertext is one the sealer's client fills in for itself.
    /// `signalDecryptPreKey` then saves that key against the name the certificate chose, and the
    /// receive path's `sealedSenderKeyMismatch` check compares the two — which agree, because
    /// they are the same key. So the message is delivered, attributed to a peer who did not send
    /// it, and the named peer's stored identity is overwritten on the way.
    ///
    /// **No code change is available or wanted, and that is why this is a test and not a fix.**
    /// Refusing would contradict locked decision §0.2.1: receiving under a changed identity is
    /// trusted precisely so a substitution cannot silently drop mail. The protection is the
    /// identity-change warning and the safety number behind it, so what this pins is that the
    /// warning actually fires — a verified badge cleared, sending blocked, the key on screen
    /// being the impostor's.
    ///
    /// The impostor lies in **two** places, and it has to: the certificate names the peer, and
    /// the ciphertext underneath it is encrypted under the peer's address as well, because the
    /// pinned libsignal binds both addresses into the message.
    /// `testTheCertificateNameAndTheCiphertextMustAgreeOnTheSender` is that binding on its own.
    /// Neither lie is checked against anything — an account chooses what its own client puts in
    /// both fields — so the binding costs the impostor consistency and nothing else.
    ///
    /// Note what the finding is *not*. A relay cannot do this: it holds no session with the
    /// recipient and cannot produce a `PreKeySignalMessage` that decrypts. It takes an account
    /// inside the circle (`THREAT_MODEL.md` §1.8), which is why this row survived P7.S01.
    func testAnImpostorCanSealAFirstMessageUnderAVerifiedPeersName() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let pair = try Pair(root: root)
            try pair.connect()

            // The state the finding is about: an established session with a peer whose safety
            // number the user has compared out of band. Asserted before the attack rather than
            // after, so "the badge was cleared" cannot pass on a badge that was never set.
            XCTAssertTrue(
                try pair.engine.setPeerVerified(
                    true, identityKey: pair.peer.identity.identityKey.serialize(),
                    for: pair.remote))
            let before = try XCTUnwrap(try pair.engine.peerIdentityState(for: pair.remote))
            XCTAssertEqual(before.identityKey, pair.peer.identity.identityKey.serialize())
            XCTAssertTrue(before.isVerified, "the peer was never verified; what follows is void")
            XCTAssertFalse(before.needsAcknowledgement, "sending is already blocked; likewise")

            // A third account the engine has never heard from, whose client claims to be the
            // peer. It needs nothing private: the engine's published bundle is what any peer
            // fetches to start a conversation, and the address a client encrypts under is a
            // field it fills in for itself — the relay's ACI never enters this ciphertext.
            let impostor = try Self.startSession(
                towards: pair, as: try pair.remote.makeProtocolAddress())

            let framed = try SealedFrame.firstMessage(
                "meet me at the usual place", from: impostor,
                naming: pair.remote, to: pair.local)

            // Delivered, not refused. Recorded as an assertion because a future change that
            // started refusing it would be a change to §0.2.1 and must not pass quietly.
            let decrypted = try pair.engine.decrypt(framed)
            XCTAssertEqual(decrypted.plaintext, Data("meet me at the usual place".utf8))
            XCTAssertEqual(decrypted.sender, pair.remote,
                           "the impostor's message is attributed to the peer it named")
            XCTAssertTrue(decrypted.establishedSession)
            XCTAssertEqual(decrypted.senderIdentityKey, impostor.identity.identityKey.serialize(),
                           "the identity key is the honest half of the attribution")
            XCTAssertNotEqual(decrypted.senderIdentityKey,
                              pair.peer.identity.identityKey.serialize())

            // The protection, which is the part that has to hold.
            let after = try XCTUnwrap(try pair.engine.peerIdentityState(for: pair.remote))
            XCTAssertEqual(after.identityKey, impostor.identity.identityKey.serialize(),
                           "the peer's stored identity was not replaced, so nothing warns the user")
            XCTAssertFalse(after.isVerified,
                           "a verified badge survived a substituted key, asserting the substitution was checked")
            XCTAssertTrue(after.needsAcknowledgement, "the identity change did not block sending")

            XCTAssertThrowsError(
                try pair.engine.encrypt(Data("are you there".utf8), to: pair.remote)
            ) { error in
                XCTAssertEqual(error as? MessagingError, .identityNotAccepted)
            }

            // And what accepting costs, stated rather than left implied: a user who dismisses
            // the warning is now writing to the impostor under their peer's name. This is what
            // the safety-number comparison exists to prevent, and the only thing that does.
            XCTAssertTrue(
                try pair.engine.acceptPeerIdentity(
                    impostor.identity.identityKey.serialize(), for: pair.remote))
            XCTAssertEqual(
                try pair.open(
                    try pair.engine.encrypt(Data("are you there".utf8), to: pair.remote),
                    at: impostor).text,
                "are you there")
        }.value
    }

    /// The control for the test above, and the reason it says anything.
    ///
    /// Same impostor, same first message, same construction — only the name in the certificate
    /// is its own. It lands as an ordinary new contact and the verified peer is untouched, so
    /// what moved that peer's identity was the relabelling and not merely a stranger's first
    /// message arriving. Without this, the test above would keep passing if every inbound
    /// session-establishing message clobbered every stored identity.
    func testAFirstMessageUnderTheSendersOwnNameLeavesAVerifiedPeerAlone() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let pair = try Pair(root: root)
            try pair.connect()

            XCTAssertTrue(
                try pair.engine.setPeerVerified(
                    true, identityKey: pair.peer.identity.identityKey.serialize(),
                    for: pair.remote))

            let strangerAddress = PeerAddress(aci: UUID())
            let stranger = try Self.startSession(
                towards: pair, as: try strangerAddress.makeProtocolAddress())

            let decrypted = try pair.engine.decrypt(
                try SealedFrame.firstMessage(
                    "hello, we have not met", from: stranger,
                    naming: strangerAddress, to: pair.local))

            XCTAssertEqual(decrypted.sender, strangerAddress)
            XCTAssertEqual(decrypted.senderIdentityKey, stranger.identity.identityKey.serialize())

            let peer = try XCTUnwrap(try pair.engine.peerIdentityState(for: pair.remote))
            XCTAssertEqual(peer.identityKey, pair.peer.identity.identityKey.serialize(),
                           "an unrelated first message replaced the peer's identity")
            XCTAssertTrue(peer.isVerified, "an unrelated first message cleared the peer's badge")
            XCTAssertFalse(peer.needsAcknowledgement,
                           "an unrelated first message blocked sending to the peer")
            XCTAssertNoThrow(try pair.engine.encrypt(Data("still fine".utf8), to: pair.remote))
        }.value
    }

    /// The upstream binding that makes the two tests above differ, pinned because nothing in
    /// this module states it and the module's behaviour rests on it.
    ///
    /// The pinned libsignal takes the sender's address at `signalEncrypt` and again at
    /// `signalDecryptPreKey`, and binds both into the message. The receive path reads the
    /// address out of the **certificate** and hands it to the decrypt as the sender, so a
    /// certificate that names anyone other than the account the ciphertext was encrypted under
    /// produces a message that cannot decrypt at all — in either direction of disagreement.
    ///
    /// This is worth a test of its own for two reasons. It is why an impostor must claim a name
    /// in the ciphertext as well as in the certificate, which is the shape AUDIT 3.8 records.
    /// And it is a guarantee from the dependency rather than from this code, so if a libsignal
    /// release stopped binding the address, that shows up here rather than as a quietly wider
    /// residual — the same reason `testACertificateKeyTheSealerDoesNotHoldIsRefused` exists.
    func testTheCertificateNameAndTheCiphertextMustAgreeOnTheSender() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let pair = try Pair(root: root)
            try pair.connect()

            // Two accounts rather than one used twice, and the reason is the replay control:
            // a client keeps sending session-establishing messages until one is answered, so a
            // second first message from the same sender carries the same base key and
            // `markKyberPreKeyUsed` refuses it as a replay — a refusal about something else
            // entirely, which is exactly what a control must not be.
            let relabellerAddress = PeerAddress(aci: UUID())
            let relabeller = try Self.startSession(
                towards: pair, as: try relabellerAddress.makeProtocolAddress())

            // The certificate claims the peer; the ciphertext was encrypted under the sender's
            // own address. The container opens and the certificate is accepted — every check
            // this module makes passes — and the message underneath then fails to decrypt.
            XCTAssertThrowsError(
                try pair.engine.decrypt(
                    try SealedFrame.firstMessage(
                        "relabelled", from: relabeller, naming: pair.remote, to: pair.local))
            ) { error in
                guard case SignalError.invalidMessage = error else {
                    return XCTFail("expected libsignal to refuse the message, got \(error)")
                }
            }

            // Positive control: the same construction, from an account naming the address its
            // ciphertext was encrypted under, is accepted. Without it the refusal above could
            // be any fixture defect at all.
            let honestAddress = PeerAddress(aci: UUID())
            let honest = try Self.startSession(
                towards: pair, as: try honestAddress.makeProtocolAddress())
            let accepted = try pair.engine.decrypt(
                try SealedFrame.firstMessage(
                    "not relabelled", from: honest, naming: honestAddress, to: pair.local))
            XCTAssertEqual(accepted.plaintext, Data("not relabelled".utf8))
            XCTAssertEqual(accepted.sender, honestAddress)
        }.value
    }
}
