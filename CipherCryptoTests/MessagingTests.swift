//
//  MessagingTests.swift
//  CipherCryptoTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//
//  The messaging façade, driven end to end. The far side is always libsignal's own
//  in-memory store, so a passing round trip means the façade agrees with the reference
//  implementation rather than with itself.
//

import Foundation
import LibSignalClient
import XCTest

@testable import CipherCrypto

final class MessagingTests: XCTestCase {

    // MARK: - Fixture

    /// An engine with an adopted address, and a peer it can talk to.
    @CryptoActor
    private struct Pair {
        let engine: CryptoEngine
        let local: PeerAddress
        let remote: PeerAddress
        let peer: PeerFixture

        init(root: URL, secrets: SecretStorage = InMemorySecretStorage(),
             now: @escaping () -> UInt64 = { 1_700_000_000_000 }) throws {
            engine = try CryptoEngine(root: root, secrets: secrets, now: now)
            local = PeerAddress(aci: UUID())
            remote = PeerAddress(aci: UUID())
            peer = try PeerFixture(address: try remote.makeProtocolAddress())
            try engine.adoptLocalAddress(local)
        }

        /// Establishes the session in the outbound direction.
        func connect() throws {
            try engine.startSession(with: remote, bundle: try peer.makeCipherBundle())
        }

        /// Delivers an envelope the engine produced to the peer, as a relay would.
        func deliverToPeer(_ envelopeBytes: Data) throws -> String {
            let envelope = try Envelope.decode(envelopeBytes)
            return try peer.decrypt(
                envelope.ciphertext,
                type: envelope.type == .preKey ? .preKey : .whisper,
                from: try local.makeProtocolAddress())
        }

        /// Wraps a peer's ciphertext in an envelope, as the peer's own client would.
        func envelopeFromPeer(_ text: String, sender: PeerAddress? = nil) throws -> Data {
            let message = try peer.encrypt(text, to: try local.makeProtocolAddress())
            return try Envelope(
                type: try Envelope.payloadType(for: message.type),
                sender: (sender ?? remote).serviceId,
                timestamp: 1_700_000_000_001,
                ciphertext: message.bytes
            ).encode()
        }
    }

    // MARK: - P2.S02 — round trip and persistence

    func testRoundTripThroughTheFacade() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let pair = try Pair(root: root)
            try pair.connect()

            let outbound = try pair.engine.encrypt(Data("hello".utf8), to: pair.remote)
            XCTAssertEqual(try Envelope.decode(outbound).type, .preKey,
                           "the first message must establish the session")
            XCTAssertEqual(try pair.deliverToPeer(outbound), "hello")

            let inbound = try pair.engine.decrypt(try pair.envelopeFromPeer("and back"))
            XCTAssertEqual(inbound.plaintext, Data("and back".utf8))
            XCTAssertEqual(inbound.sender, pair.remote)
            XCTAssertFalse(inbound.establishedSession, "the ratchet had already started")

            // Attribution is the identity that authenticated it, not the envelope field.
            XCTAssertEqual(inbound.senderIdentityKey, pair.peer.identity.identityKey.serialize())
        }.value
    }

    func testTheEnvelopeCarriesTheDeclaredTimestampAndNothingSecret() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let pair = try Pair(root: root, now: { 42_000 })
            try pair.connect()

            let bytes = try pair.engine.encrypt(Data("plaintext marker".utf8), to: pair.remote)
            let envelope = try Envelope.decode(bytes)

            XCTAssertEqual(envelope.timestamp, 42_000)
            XCTAssertEqual(envelope.sender, pair.local.serviceId)
            XCTAssertFalse(bytes.range(of: Data("plaintext marker".utf8)) != nil,
                           "the plaintext must not appear anywhere in the relayed frame")
        }.value
    }

    func testSessionSurvivesAnEngineRestart() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }
        let secrets = InMemorySecretStorage()

        let carried = try await Task { @CryptoActor () -> (PeerFixture, PeerAddress, PeerAddress) in
            let pair = try Pair(root: root, secrets: secrets)
            try pair.connect()
            // Drive one message each way so the ratchet has actually stepped before the
            // restart; a session that only survives at rest is not the interesting case.
            _ = try pair.deliverToPeer(try pair.engine.encrypt(Data("first".utf8), to: pair.remote))
            return (pair.peer, pair.local, pair.remote)
        }.value

        try await Task { @CryptoActor in
            let (peer, local, remote) = carried
            let reopened = try CryptoEngine(root: root, secrets: secrets)

            XCTAssertEqual(try reopened.localAddress, local,
                           "the installation must still be the same one")
            XCTAssertTrue(try reopened.hasSession(with: remote))

            let message = try peer.encrypt("after restart", to: try local.makeProtocolAddress())
            let envelope = try Envelope(
                type: try Envelope.payloadType(for: message.type),
                sender: remote.serviceId, timestamp: 1, ciphertext: message.bytes).encode()

            XCTAssertEqual(try reopened.decrypt(envelope).plaintext, Data("after restart".utf8))
        }.value
    }

    /// Unreadable local protocol state is not evidence that the relay envelope is corrupt.
    /// The app must keep that envelope pending instead of acknowledging away the only copy.
    func testCorruptProtocolStateSurfacesAsStorageUnavailable() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let pair = try Pair(root: root)
            try pair.connect()
            _ = try pair.deliverToPeer(
                try pair.engine.encrypt(Data("establish".utf8), to: pair.remote))
            let envelope = try pair.envelopeFromPeer("must remain pending")

            let address = try pair.remote.makeProtocolAddress()
            let recordKey = "\(address.name).\(address.deviceId)"
            var tagInput = Data(RecordKind.session.rawValue.utf8)
            tagInput.append(0)
            tagInput.append(contentsOf: recordKey.utf8)
            let database = pair.engine.store.appDatabase
            try database.put(
                namespace: "proto-session", groupTag: database.groupTag(tagInput), ordinal: 0,
                value: Data([0xFF]))

            XCTAssertThrowsError(try pair.engine.decrypt(envelope)) { error in
                XCTAssertEqual(error as? MessagingError, .storeUnavailable)
                XCTAssertFalse(error is RecordStoreError)
            }
        }.value
    }

    // MARK: - P2.S03 — attribution follows the session, never the envelope

    /// Locked decision §0.2.3, demonstrated rather than asserted.
    ///
    /// A hostile relay rewrites the envelope's sender to an address the recipient knows.
    /// The ciphertext is untouched and the frame stays well-formed — `Envelope.decode`
    /// accepts it, as `LockedDecisionsTests` already shows. What must not happen is the
    /// message being *delivered* under the substituted name. It cannot: the session the
    /// relay named holds different keys, so the ratchet MAC fails and the message is
    /// dropped. The attacker converts a message into a non-message, never into a lie.
    func testRewrittenEnvelopeSenderCannotMisattribute() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let pair = try Pair(root: root)
            try pair.connect()
            _ = try pair.deliverToPeer(try pair.engine.encrypt(Data("hi".utf8), to: pair.remote))

            // A second peer the engine also has a session with — so the substituted address
            // resolves to a real session rather than to nothing. Attribution by envelope
            // would succeed here; attribution by session must not.
            let other = PeerAddress(aci: UUID())
            let otherPeer = try PeerFixture(address: try other.makeProtocolAddress())
            try pair.engine.startSession(with: other, bundle: try otherPeer.makeCipherBundle())
            _ = try pair.deliverToPeer(try pair.engine.encrypt(Data("hi".utf8), to: pair.remote))

            let honest = try pair.envelopeFromPeer("from the real peer")
            XCTAssertEqual(try pair.engine.decrypt(honest).sender, pair.remote)

            // Same ciphertext, relabelled as the other peer.
            var forged = try pair.envelopeFromPeer("from the real peer")
            forged.replaceSubrange(2..<19, with: other.serviceId.fixedWidthBinary)

            XCTAssertEqual(try Envelope.decode(forged).sender, other.serviceId,
                           "the frame must still parse — the wire cannot detect this")
            XCTAssertThrowsError(try pair.engine.decrypt(forged)) { error in
                XCTAssertFalse(error is MessagingError && (error as? MessagingError) == .noSession,
                               "a real session was named; the failure must be cryptographic")
            }
        }.value
    }

    func testAMessageForAnUnknownSenderIsRefusedRatherThanGuessed() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let pair = try Pair(root: root)
            try pair.connect()
            _ = try pair.deliverToPeer(try pair.engine.encrypt(Data("hi".utf8), to: pair.remote))

            var forged = try pair.envelopeFromPeer("relabelled")
            forged.replaceSubrange(
                2..<19, with: ServiceIdentifier(kind: .aci, uuid: UUID()).fixedWidthBinary)

            XCTAssertThrowsError(try pair.engine.decrypt(forged)) { error in
                XCTAssertEqual(error as? MessagingError, .noSession,
                               "there is no session to try; it must not fall back to another")
            }
        }.value
    }

    // MARK: - P2.S05 — the identity-change policy survives the façade

    func testChangedIdentityBlocksSendingButNotReceivingThroughTheFacade() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let pair = try Pair(root: root)
            try pair.connect()
            _ = try pair.deliverToPeer(try pair.engine.encrypt(Data("trusted".utf8), to: pair.remote))

            // A different installation claiming the same address: a new identity key.
            let impostor = try PeerFixture(address: try pair.remote.makeProtocolAddress())
            _ = try impostor.makeBundle()
            try processPreKeyBundle(
                try Self.bundleForEngine(pair),
                for: try pair.local.makeProtocolAddress(),
                ourAddress: try pair.remote.makeProtocolAddress(),
                sessionStore: impostor.store, identityStore: impostor.store,
                context: NullContext())

            let intrusion = try impostor.encrypt(
                "from a new key", to: try pair.local.makeProtocolAddress())
            let envelope = try Envelope(
                type: try Envelope.payloadType(for: intrusion.type),
                sender: pair.remote.serviceId, timestamp: 1, ciphertext: intrusion.bytes).encode()

            // Receiving is allowed, and the change is recorded.
            let received = try pair.engine.decrypt(envelope)
            XCTAssertEqual(received.plaintext, Data("from a new key".utf8))
            XCTAssertEqual(received.senderIdentityKey, impostor.identity.identityKey.serialize())

            let state = try XCTUnwrap(
                try pair.engine.peerIdentityState(
                    name: pair.remote.serviceId.canonicalString, deviceId: pair.remote.deviceId))
            XCTAssertTrue(state.needsAcknowledgement)

            // Sending is refused until the user has looked at the new safety number.
            XCTAssertThrowsError(
                try pair.engine.encrypt(Data("reply".utf8), to: pair.remote)
            ) { error in
                // P5.S10 maps this to `MessagingError.identityNotAccepted`. It used to be
                // libsignal's own `SignalError.untrustedIdentity`, which meant the only way for
                // the app to distinguish "compare a safety number" from "the network is down"
                // was to `import LibSignalClient` — reopening, through `throws`, the boundary
                // AUDIT 5.12 closed and that `verify-api-boundary.sh` cannot see. See AUDIT 5.19.
                guard case MessagingError.identityNotAccepted = error else {
                    return XCTFail("expected identityNotAccepted, got \(error)")
                }
            }

            // And accepting the exact key unblocks it.
            XCTAssertTrue(
                try pair.engine.acceptPeerIdentity(
                    impostor.identity.identityKey.serialize(),
                    name: pair.remote.serviceId.canonicalString,
                    deviceId: pair.remote.deviceId))
            XCTAssertNoThrow(try pair.engine.encrypt(Data("reply".utf8), to: pair.remote))
        }.value
    }

    /// Publishes a bundle *for the engine*, so a peer can start a session towards it.
    ///
    /// The private halves must actually be stored, not merely advertised: `signalDecryptPreKey`
    /// looks up the signed and kyber prekeys the incoming message names, and a bundle whose
    /// keys were never persisted fails at decrypt with `invalidKeyIdentifier` — which reads
    /// like a protocol bug and is really a fixture that published keys it did not keep.
    @CryptoActor
    private static func bundleForEngine(_ pair: Pair) throws -> PreKeyBundle {
        let context = NullContext()
        let store = pair.engine.store
        let ids = try store.reservePreKeyIds(count: 3)

        let preKey = PrivateKey.generate()
        let signed = PrivateKey.generate()
        let kyber = KEMKeyPair.generate()
        let identity = try store.identityKeyPair(context: context)

        let signedSignature = identity.privateKey.generateSignature(
            message: signed.publicKey.serialize())
        let kyberSignature = identity.privateKey.generateSignature(
            message: kyber.publicKey.serialize())

        let preKeyId = ids.lowerBound
        let signedPreKeyId = ids.lowerBound + 1
        let kyberPreKeyId = ids.lowerBound + 2

        try store.storePreKey(
            PreKeyRecord(id: preKeyId, privateKey: preKey), id: preKeyId, context: context)
        try store.storeSignedPreKey(
            SignedPreKeyRecord(
                id: signedPreKeyId, timestamp: 1000,
                privateKey: signed, signature: signedSignature),
            id: signedPreKeyId, context: context)
        try store.storeKyberPreKey(
            KyberPreKeyRecord(
                id: kyberPreKeyId, timestamp: 1000, keyPair: kyber, signature: kyberSignature),
            id: kyberPreKeyId, context: context)

        return try PreKeyBundle(
            registrationId: try store.localRegistrationId(context: context),
            deviceId: pair.local.deviceId,
            prekeyId: preKeyId, prekey: preKey.publicKey,
            signedPrekeyId: signedPreKeyId, signedPrekey: signed.publicKey,
            signedPrekeySignature: signedSignature,
            identity: identity.identityKey,
            kyberPrekeyId: kyberPreKeyId, kyberPrekey: kyber.publicKey,
            kyberPrekeySignature: kyberSignature)
    }

    // MARK: - P2.S04 — groups stay unreachable through the façade

    /// Locked decision §0.2.2 holds at the API, not only at the wire type.
    ///
    /// `SenderKeyStore` is deliberately unimplemented, so a group message has nowhere to go —
    /// but "nowhere to go" must be a refusal, not a crash or a partial state change. Every
    /// payload discriminator outside the two live ones is rejected by the parser before any
    /// store is touched, which is what keeps an unimplemented feature from becoming a
    /// reachable one.
    func testGroupAndUnknownPayloadTypesAreRefusedByTheFacade() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let pair = try Pair(root: root)
            try pair.connect()
            _ = try pair.deliverToPeer(try pair.engine.encrypt(Data("hi".utf8), to: pair.remote))

            let live = Set(Envelope.PayloadType.allCases.map(\.rawValue))
            XCTAssertEqual(live, [1, 2], "only preKey and whisper may be live")

            // Every other discriminator, including 3 (reserved for the unauthenticated
            // PlaintextContent carrier) and whatever a sender-key message would claim.
            for raw in UInt8(0)...UInt8(16) where !live.contains(raw) {
                var frame = try pair.envelopeFromPeer("would be a group message")
                frame[frame.startIndex + 1] = raw

                XCTAssertThrowsError(try pair.engine.decrypt(frame),
                                     "payload type \(raw) must not be accepted") { error in
                    XCTAssertEqual(error as? EnvelopeError, .unknownPayloadType(raw))
                }
            }

            // And the session is untouched by the attempts: a rejected frame must not have
            // stepped the ratchet or consumed a prekey on the way to being refused.
            let honest = try pair.envelopeFromPeer("still works")
            XCTAssertEqual(try pair.engine.decrypt(honest).plaintext, Data("still works".utf8))
        }.value
    }

    // MARK: - Local address

    /// Changing this device's own address would orphan every session it has. Refused, not
    /// applied — and re-adopting the same one is a no-op so a retried registration is safe.
    func testLocalAddressIsWriteOnce() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let engine = try CryptoEngine(root: root, secrets: InMemorySecretStorage())
            XCTAssertNil(try engine.localAddress)

            let mine = PeerAddress(aci: UUID())
            try engine.adoptLocalAddress(mine)
            XCTAssertEqual(try engine.localAddress, mine)

            XCTAssertNoThrow(try engine.adoptLocalAddress(mine), "re-adopting the same is a no-op")

            XCTAssertThrowsError(try engine.adoptLocalAddress(PeerAddress(aci: UUID()))) { error in
                XCTAssertEqual(error as? MessagingError, .localAddressAlreadySet)
            }
            XCTAssertEqual(try engine.localAddress, mine, "the refusal must change nothing")
        }.value
    }

    func testSendingWithNoLocalAddressIsRefused() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let engine = try CryptoEngine(root: root, secrets: InMemorySecretStorage())
            XCTAssertThrowsError(
                try engine.encrypt(Data("x".utf8), to: PeerAddress(aci: UUID()))
            ) { XCTAssertEqual($0 as? MessagingError, .localAddressNotSet) }
        }.value
    }

    // MARK: - Destruction

    func testEveryMessagingCallRefusesAfterDestruction() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let pair = try Pair(root: root)
            try pair.connect()
            // The peer only has a session once it has decrypted something from us, so an
            // envelope has to be earned before it can be replayed against a dead engine.
            _ = try pair.deliverToPeer(try pair.engine.encrypt(Data("first".utf8), to: pair.remote))
            let envelope = try pair.envelopeFromPeer("before")

            try pair.engine.destroyAllState()

            for call in [
                { _ = try pair.engine.localAddress },
                { try pair.engine.adoptLocalAddress(pair.local) },
                { try pair.engine.startSession(with: pair.remote,
                                               bundle: try pair.peer.makeCipherBundle()) },
                { _ = try pair.engine.hasSession(with: pair.remote) },
                { _ = try pair.engine.encrypt(Data("x".utf8), to: pair.remote) },
                { _ = try pair.engine.decrypt(envelope) },
            ] as [() throws -> Void] {
                XCTAssertThrowsError(try call()) { error in
                    XCTAssertEqual(error as? CryptoEngineError, .destroyed)
                }
            }
        }.value
    }
}
