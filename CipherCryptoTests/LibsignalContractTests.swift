//
//  LibsignalContractTests.swift
//  CipherCryptoTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//
//  These are the M0 smoke-test gates promoted to a permanent test suite.
//
//  Their purpose is not to test libsignal — Signal does that. It is to pin the
//  *behavioural contract* this codebase depends on, so that a future dependency
//  bump that silently changes any of it fails here rather than in production.
//  libsignal is deliberately 0.x and promises no stability between releases.
//

import XCTest
import LibSignalClient
@testable import CipherCrypto

final class LibsignalContractTests: XCTestCase {

    // MARK: - Fixtures

    /// A Bob with a published PQXDH bundle and his private halves persisted.
    private struct Peer {
        let store: InMemorySignalProtocolStore
        let address: ProtocolAddress
        let bundle: PreKeyBundle
        let identity: IdentityKeyPair
    }

    private static let preKeyId: UInt32 = 4570
    private static let signedPreKeyId: UInt32 = 3006
    private static let kyberPreKeyId: UInt32 = 8888

    private func makeBob(context ctx: StoreContext) throws -> Peer {
        let store = InMemorySignalProtocolStore()
        let address = try ProtocolAddress(name: "bob", deviceId: 1)

        let preKey = PrivateKey.generate()
        let signedPreKey = PrivateKey.generate()
        let kyber = KEMKeyPair.generate()
        let identity = try store.identityKeyPair(context: ctx)

        let spkSig = identity.privateKey.generateSignature(
            message: signedPreKey.publicKey.serialize())
        let kyberSig = identity.privateKey.generateSignature(
            message: kyber.publicKey.serialize())

        let bundle = try PreKeyBundle(
            registrationId: try store.localRegistrationId(context: ctx),
            deviceId: 1,
            prekeyId: Self.preKeyId,
            prekey: preKey.publicKey,
            signedPrekeyId: Self.signedPreKeyId,
            signedPrekey: signedPreKey.publicKey,
            signedPrekeySignature: spkSig,
            identity: identity.identityKey,
            kyberPrekeyId: Self.kyberPreKeyId,
            kyberPrekey: kyber.publicKey,
            kyberPrekeySignature: kyberSig)

        try store.storePreKey(
            PreKeyRecord(id: Self.preKeyId, privateKey: preKey),
            id: Self.preKeyId, context: ctx)
        try store.storeSignedPreKey(
            SignedPreKeyRecord(id: Self.signedPreKeyId, timestamp: 42000,
                               privateKey: signedPreKey, signature: spkSig),
            id: Self.signedPreKeyId, context: ctx)
        try store.storeKyberPreKey(
            KyberPreKeyRecord(id: Self.kyberPreKeyId, timestamp: 42000,
                              keyPair: kyber, signature: kyberSig),
            id: Self.kyberPreKeyId, context: ctx)

        return Peer(store: store, address: address, bundle: bundle, identity: identity)
    }

    // MARK: - Linkage

    func testLibsignalIsLinkedAndUsable() throws {
        // Proves the Rust FFI is actually linked, not merely that the Swift wrapper compiled.
        let key = PrivateKey.generate()
        XCTAssertEqual(key.publicKey.serialize().count, 33, "0x05 type byte + 32 key bytes")
        XCTAssertEqual(key.publicKey.keyBytes.count, 32)
    }

    // MARK: - PQXDH is mandatory

    func testPreKeyBundleAlwaysCarriesAKyberPreKey() throws {
        // v0.99.1 removed the classic X3DH bundle initializers entirely. If a future
        // version reintroduces a non-Kyber path, that is a downgrade surface and this
        // test documents the assumption that none exists.
        let ctx = NullContext()
        let bob = try makeBob(context: ctx)
        XCTAssertEqual(bob.bundle.kyberPreKeyId, Self.kyberPreKeyId)
        XCTAssertNotNil(bob.bundle.preKeyId)
    }

    func testEstablishedSessionIsFullyPostQuantum() throws {
        let ctx = NullContext()
        let alice = InMemorySignalProtocolStore()
        let aliceAddress = try ProtocolAddress(name: "alice", deviceId: 1)
        let bob = try makeBob(context: ctx)

        try processPreKeyBundle(bob.bundle, for: bob.address, ourAddress: aliceAddress,
                                sessionStore: alice, identityStore: alice, context: ctx)

        let session = try XCTUnwrap(alice.loadSession(for: bob.address, context: ctx))
        XCTAssertTrue(session.hasCurrentState(requirePqRatio: 1.0),
                      "session must be fully post-quantum")
        XCTAssertEqual(try session.remoteRegistrationId(),
                       try bob.store.localRegistrationId(context: ctx))
    }

    // MARK: - Round trip and the ratchet

    func testRoundTripAndRatchetStep() throws {
        let ctx = NullContext()
        let alice = InMemorySignalProtocolStore()
        let aliceAddress = try ProtocolAddress(name: "alice", deviceId: 1)
        let bob = try makeBob(context: ctx)

        try processPreKeyBundle(bob.bundle, for: bob.address, ourAddress: aliceAddress,
                                sessionStore: alice, identityStore: alice, context: ctx)

        // Alice -> Bob: the first message is a PreKeySignalMessage.
        let outbound = "the ratchet turns"
        let ct = try signalEncrypt(message: Array(outbound.utf8),
                                   for: bob.address, localAddress: aliceAddress,
                                   sessionStore: alice, identityStore: alice, context: ctx)
        XCTAssertEqual(ct.messageType, .preKey)

        let plaintext = try signalDecryptPreKey(
            message: try PreKeySignalMessage(bytes: ct.serialize()),
            from: aliceAddress, localAddress: bob.address,
            sessionStore: bob.store, identityStore: bob.store,
            preKeyStore: bob.store, signedPreKeyStore: bob.store,
            kyberPreKeyStore: bob.store, context: ctx)
        XCTAssertEqual(String(decoding: plaintext, as: UTF8.self), outbound)

        // Bob -> Alice: a Whisper message, proving the ratchet stepped.
        let reply = "and turns back"
        let ct2 = try signalEncrypt(message: Array(reply.utf8),
                                    for: aliceAddress, localAddress: bob.address,
                                    sessionStore: bob.store, identityStore: bob.store,
                                    context: ctx)
        XCTAssertEqual(ct2.messageType, .whisper)

        let plaintext2 = try signalDecrypt(
            message: try SignalMessage(bytes: ct2.serialize()),
            from: bob.address, to: aliceAddress,
            sessionStore: alice, identityStore: alice, context: ctx)
        XCTAssertEqual(String(decoding: plaintext2, as: UTF8.self), reply)
    }

    // MARK: - Store contract

    func testLibraryConsumesOneTimePreKeyItself() throws {
        // The app must never remove consumed one-time prekeys itself: libsignal calls
        // removePreKey on the prekey-decrypt path. This pins that behaviour.
        let ctx = NullContext()
        let alice = InMemorySignalProtocolStore()
        let aliceAddress = try ProtocolAddress(name: "alice", deviceId: 1)
        let bob = try makeBob(context: ctx)

        try processPreKeyBundle(bob.bundle, for: bob.address, ourAddress: aliceAddress,
                                sessionStore: alice, identityStore: alice, context: ctx)
        let ct = try signalEncrypt(message: Array("hello".utf8),
                                   for: bob.address, localAddress: aliceAddress,
                                   sessionStore: alice, identityStore: alice, context: ctx)

        XCTAssertNoThrow(try bob.store.loadPreKey(id: Self.preKeyId, context: ctx),
                         "prekey present before decrypt")

        _ = try signalDecryptPreKey(
            message: try PreKeySignalMessage(bytes: ct.serialize()),
            from: aliceAddress, localAddress: bob.address,
            sessionStore: bob.store, identityStore: bob.store,
            preKeyStore: bob.store, signedPreKeyStore: bob.store,
            kyberPreKeyStore: bob.store, context: ctx)

        XCTAssertThrowsError(try bob.store.loadPreKey(id: Self.preKeyId, context: ctx),
                             "libsignal must have consumed the one-time prekey")
    }

    func testSaveIdentityReturnsReplacedExistingOnlyForADifferentKey() throws {
        // This return value is what drives the "safety number changed" state, so its
        // exact semantics are load-bearing.
        let ctx = NullContext()
        let store = InMemorySignalProtocolStore()
        let peer = try ProtocolAddress(name: "peer", deviceId: 1)

        let first = IdentityKeyPair.generate().identityKey
        let second = IdentityKeyPair.generate().identityKey

        XCTAssertEqual(try store.saveIdentity(first, for: peer, context: ctx), .newOrUnchanged,
                       "no prior key")
        XCTAssertEqual(try store.saveIdentity(first, for: peer, context: ctx), .newOrUnchanged,
                       "same key again is idempotent")
        XCTAssertEqual(try store.saveIdentity(second, for: peer, context: ctx), .replacedExisting,
                       "a different key must report a replacement")
        XCTAssertEqual(try store.saveIdentity(second, for: peer, context: ctx), .newOrUnchanged,
                       "re-saving the replacement is idempotent again")
    }

    // MARK: - Replay

    func testReplayIsRejectedAsDuplicatedMessage() throws {
        let ctx = NullContext()
        let alice = InMemorySignalProtocolStore()
        let aliceAddress = try ProtocolAddress(name: "alice", deviceId: 1)
        let bob = try makeBob(context: ctx)

        try processPreKeyBundle(bob.bundle, for: bob.address, ourAddress: aliceAddress,
                                sessionStore: alice, identityStore: alice, context: ctx)
        let ct = try signalEncrypt(message: Array("once".utf8),
                                   for: bob.address, localAddress: aliceAddress,
                                   sessionStore: alice, identityStore: alice, context: ctx)
        let bytes = ct.serialize()

        _ = try signalDecryptPreKey(
            message: try PreKeySignalMessage(bytes: bytes),
            from: aliceAddress, localAddress: bob.address,
            sessionStore: bob.store, identityStore: bob.store,
            preKeyStore: bob.store, signedPreKeyStore: bob.store,
            kyberPreKeyStore: bob.store, context: ctx)

        // A replay must surface specifically as duplicatedMessage — the app silently
        // drops that case, and must not confuse it with a real decryption failure.
        XCTAssertThrowsError(try signalDecryptPreKey(
            message: try PreKeySignalMessage(bytes: bytes),
            from: aliceAddress, localAddress: bob.address,
            sessionStore: bob.store, identityStore: bob.store,
            preKeyStore: bob.store, signedPreKeyStore: bob.store,
            kyberPreKeyStore: bob.store, context: ctx)
        ) { error in
            guard case SignalError.duplicatedMessage = error else {
                return XCTFail("expected duplicatedMessage, got \(error)")
            }
        }
    }

    // MARK: - Malformed input

    func testMalformedPublicKeyIsRejected() {
        // Invalid-curve protection: deserialization validates the type byte and point.
        XCTAssertThrowsError(try PublicKey(Array(repeating: UInt8(0xAA), count: 33)))
        XCTAssertThrowsError(try PublicKey([UInt8]()))
        XCTAssertThrowsError(try PublicKey(Array(repeating: UInt8(0x05), count: 8)))
    }

    func testMalformedMessagesAreRejected() {
        XCTAssertThrowsError(try SignalMessage(bytes: [UInt8]()))
        XCTAssertThrowsError(try PreKeySignalMessage(bytes: Array(repeating: UInt8(0xFF), count: 64)))
        XCTAssertThrowsError(try SessionRecord(bytes: Array(repeating: UInt8(0x01), count: 16)))
    }

    // MARK: - Safety numbers

    func testSafetyNumbersAgreeAndAreStable() throws {
        let aliceIdentity = IdentityKeyPair.generate()
        let bobIdentity = IdentityKeyPair.generate()

        // Signal's production iteration count. The identifier bytes are a Cipher wire
        // contract, NOT something the library derives from `version` — see PLAN §4.
        let generator = NumericFingerprintGenerator(iterations: 5200)
        let aliceId = Array("alice".utf8)
        let bobId = Array("bob".utf8)

        let fromAlice = try generator.create(version: 2,
                                             localIdentifier: aliceId,
                                             localKey: aliceIdentity.publicKey,
                                             remoteIdentifier: bobId,
                                             remoteKey: bobIdentity.publicKey)
        let fromBob = try generator.create(version: 2,
                                           localIdentifier: bobId,
                                           localKey: bobIdentity.publicKey,
                                           remoteIdentifier: aliceId,
                                           remoteKey: aliceIdentity.publicKey)

        XCTAssertEqual(fromAlice.displayable.formatted, fromBob.displayable.formatted)
        XCTAssertEqual(fromAlice.displayable.formatted.count, 60)
        XCTAssertTrue(try fromAlice.scannable.compare(againstEncoding: fromBob.scannable.encoding))
    }

    func testSafetyNumbersDifferForADifferentPeer() throws {
        let aliceIdentity = IdentityKeyPair.generate()
        let bobIdentity = IdentityKeyPair.generate()
        let malloryIdentity = IdentityKeyPair.generate()

        let generator = NumericFingerprintGenerator(iterations: 5200)
        let aliceId = Array("alice".utf8)

        let withBob = try generator.create(version: 2,
                                           localIdentifier: aliceId,
                                           localKey: aliceIdentity.publicKey,
                                           remoteIdentifier: Array("bob".utf8),
                                           remoteKey: bobIdentity.publicKey)
        let withMallory = try generator.create(version: 2,
                                               localIdentifier: aliceId,
                                               localKey: aliceIdentity.publicKey,
                                               remoteIdentifier: Array("bob".utf8),
                                               remoteKey: malloryIdentity.publicKey)

        XCTAssertNotEqual(withBob.displayable.formatted, withMallory.displayable.formatted,
                          "a substituted identity key must change the safety number")
        XCTAssertFalse(try withBob.scannable.compare(againstEncoding: withMallory.scannable.encoding))
    }

    // MARK: - Address validation

    func testDeviceIdIsConstrainedToTheValidRange() {
        XCTAssertNoThrow(try ProtocolAddress(name: "x", deviceId: 1))
        XCTAssertNoThrow(try ProtocolAddress(name: "x", deviceId: 127))
        XCTAssertThrowsError(try ProtocolAddress(name: "x", deviceId: 0))
        XCTAssertThrowsError(try ProtocolAddress(name: "x", deviceId: 128))
    }

    // MARK: - Module

    func testPinnedVersionMatchesTheDependencyRecord() {
        // Guards against the module's recorded version drifting from Vendor/libsignal/PINS.env.
        XCTAssertEqual(CipherCrypto.libsignalVersion, "0.99.1")
    }
}
