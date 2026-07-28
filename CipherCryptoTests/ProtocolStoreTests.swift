//
//  ProtocolStoreTests.swift
//  CipherCryptoTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//
//  Drives real PQXDH sessions through the persistent store. The peer on the far side is
//  always libsignal's own in-memory store, so a passing round trip means our persistence
//  agrees with the reference implementation rather than merely with itself.
//

import Foundation
import LibSignalClient
import XCTest

@testable import CipherCrypto

final class ProtocolStoreTests: XCTestCase {

    // MARK: - Round trip

    func testFullSessionRoundTripThroughThePersistentStore() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let local = try LocalFixture(root: root)
            let peer = try PeerFixture(
                address: try ProtocolAddress(name: "peer-round-trip", deviceId: 1))

            try Local.establishSession(local, with: peer.address, bundle: try peer.makeBundle())

            let session = try XCTUnwrap(
                try local.store.loadSession(for: peer.address, context: NullContext()))
            XCTAssertTrue(session.hasCurrentState(requirePqRatio: 1.0),
                          "the persisted session must be fully post-quantum")

            let outbound = try Local.encrypt(local, "hello from disk", to: peer.address)
            XCTAssertEqual(outbound.type, .preKey)
            XCTAssertEqual(
                try peer.decrypt(outbound.bytes, type: outbound.type, from: local.address),
                "hello from disk")

            let reply = try peer.encrypt("and back again", to: local.address)
            XCTAssertEqual(reply.type, .whisper, "the ratchet stepped")
            XCTAssertEqual(
                try Local.decrypt(local, reply.bytes, type: reply.type, from: peer.address),
                "and back again")
        }.value
    }

    /// The point of persisting at all: a session must survive the process that made it.
    func testSessionSurvivesAStoreRestart() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        // One Keychain across both "launches" — that is what a real reinstall-free restart
        // looks like, and it is what makes the sealed records readable again.
        let secrets = InMemorySecretStorage()

        let handoff = try await Task { @CryptoActor
            () -> (localAddress: ProtocolAddress, peer: PeerFixture, first: Data,
                   firstType: CiphertextMessage.MessageType) in
            let local = try LocalFixture(root: root, secrets: secrets)
            let peer = try PeerFixture(
                address: try ProtocolAddress(name: "peer-restart", deviceId: 1))

            try Local.establishSession(local, with: peer.address, bundle: try peer.makeBundle())
            let first = try Local.encrypt(local, "before restart", to: peer.address)
            return (local.address, peer, first.bytes, first.type)
        }.value

        try await Task { @CryptoActor in
            XCTAssertEqual(
                try handoff.peer.decrypt(
                    handoff.first, type: handoff.firstType, from: handoff.localAddress),
                "before restart")

            // A brand new store object over the same directory and the same Keychain: this
            // is the reopen path, reading state nothing in this process ever cached.
            let reopened = try LocalFixture(root: root, secrets: secrets)

            let session = try XCTUnwrap(
                try reopened.store.loadSession(for: handoff.peer.address, context: NullContext()))
            XCTAssertTrue(session.hasCurrentState(requirePqRatio: 1.0))

            // The reopened store must still be *this* installation, or the peer's session
            // would not authenticate what it sends.
            let reply = try handoff.peer.encrypt("after restart", to: handoff.localAddress)
            XCTAssertEqual(
                try Local.decrypt(
                    reopened, reply.bytes, type: reply.type, from: handoff.peer.address),
                "after restart")
        }.value
    }

    /// The concurrency claim, demonstrated rather than asserted: every store callback
    /// libsignal makes during a real decrypt lands on the crypto queue.
    func testEveryStoreCallbackRunsOnTheCryptoQueue() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let local = try LocalFixture(root: root)
            let peer = try PeerFixture(
                address: try ProtocolAddress(name: "peer-isolation", deviceId: 1))

            try Local.establishSession(local, with: peer.address, bundle: try peer.makeBundle())
            let outbound = try Local.encrypt(local, "isolation", to: peer.address)
            _ = try peer.decrypt(outbound.bytes, type: outbound.type, from: local.address)
            let reply = try peer.encrypt("reply", to: local.address)
            _ = try Local.decrypt(local, reply.bytes, type: reply.type, from: peer.address)

            XCTAssertGreaterThan(local.spy.isolationObservations.count, 0,
                                 "the callbacks must actually have been taken")
            XCTAssertTrue(local.spy.isolationObservations.allSatisfy { $0 },
                          "a store callback ran outside the crypto domain")
            XCTAssertGreaterThan(local.spy.stores[.session, default: 0], 0,
                                 "the ratchet must have been persisted")
        }.value
    }

    // MARK: - Identity trust

    /// The two directions differ on purpose. Receiving stays possible so the user is warned
    /// instead of silently losing messages; sending stops so no new plaintext reaches a key
    /// the user has never seen.
    func testChangedIdentityBlocksSendingButNotReceiving() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let local = try LocalFixture(root: root)
            let address = try ProtocolAddress(name: "peer-rekey", deviceId: 1)

            let original = try PeerFixture(address: address)
            try Local.establishSession(local, with: address, bundle: try original.makeBundle())
            let first = try Local.encrypt(local, "trusted", to: address)
            XCTAssertEqual(
                try original.decrypt(first.bytes, type: first.type, from: local.address),
                "trusted")

            // A different installation claiming the same address: a new identity key.
            let impostor = try PeerFixture(address: address)
            _ = try impostor.makeBundle()
            try processPreKeyBundle(
                try Self.bundle(from: local, for: impostor),
                for: local.address, ourAddress: address,
                sessionStore: impostor.store, identityStore: impostor.store,
                context: NullContext())

            let intrusion = try impostor.encrypt("from a new key", to: local.address)

            // Receiving is allowed: the message decrypts and the change is recorded.
            XCTAssertEqual(
                try Local.decrypt(
                    local, intrusion.bytes, type: intrusion.type, from: address),
                "from a new key")

            let state = try XCTUnwrap(try local.store.peerIdentity(for: address))
            XCTAssertTrue(state.needsAcknowledgement)
            XCTAssertNotNil(state.changedAtMs)
            XCTAssertEqual(state.identityKey, impostor.identity.identityKey)

            // Sending is refused until the user has looked at the new safety number.
            XCTAssertThrowsError(try Local.encrypt(local, "reply", to: address)) { error in
                guard case SignalError.untrustedIdentity = error else {
                    return XCTFail("expected untrustedIdentity, got \(error)")
                }
            }
        }.value
    }

    func testAcceptingTheNewIdentityUnblocksSending() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let local = try LocalFixture(root: root)
            let address = try ProtocolAddress(name: "peer-accept", deviceId: 1)

            let original = try PeerFixture(address: address)
            try Local.establishSession(local, with: address, bundle: try original.makeBundle())

            let replacement = IdentityKeyPair.generate().identityKey
            _ = try local.store.saveIdentity(replacement, for: address, context: NullContext())
            XCTAssertFalse(
                try local.store.isTrustedIdentity(
                    replacement, for: address, direction: .sending, context: NullContext()))

            XCTAssertTrue(try local.store.acceptIdentity(replacement, for: address))

            XCTAssertTrue(
                try local.store.isTrustedIdentity(
                    replacement, for: address, direction: .sending, context: NullContext()),
                "an accepted key must unblock sending")
            let state = try XCTUnwrap(try local.store.peerIdentity(for: address))
            XCTAssertFalse(state.needsAcknowledgement)
        }.value
    }

    /// An approval names the key it approves. If another change lands between the screen
    /// being drawn and the tap, the approval must not apply to whatever arrived instead.
    func testAcceptingAStaleKeyIsRefused() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let local = try LocalFixture(root: root)
            let address = try ProtocolAddress(name: "peer-stale", deviceId: 1)

            let first = IdentityKeyPair.generate().identityKey
            let second = IdentityKeyPair.generate().identityKey
            let third = IdentityKeyPair.generate().identityKey

            _ = try local.store.saveIdentity(first, for: address, context: NullContext())
            _ = try local.store.saveIdentity(second, for: address, context: NullContext())
            _ = try local.store.saveIdentity(third, for: address, context: NullContext())

            XCTAssertFalse(try local.store.acceptIdentity(second, for: address),
                           "approving a key that is no longer stored must not take effect")
            XCTAssertTrue(
                try XCTUnwrap(try local.store.peerIdentity(for: address)).needsAcknowledgement)

            XCTAssertTrue(try local.store.acceptIdentity(third, for: address))
        }.value
    }

    func testFirstSightIsTrustedAndRecorded() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let local = try LocalFixture(root: root)
            let address = try ProtocolAddress(name: "peer-tofu", deviceId: 1)
            let key = IdentityKeyPair.generate().identityKey

            XCTAssertTrue(
                try local.store.isTrustedIdentity(
                    key, for: address, direction: .sending, context: NullContext()),
                "there is nothing to compare a first sighting against")

            XCTAssertEqual(
                try local.store.saveIdentity(key, for: address, context: NullContext()),
                .newOrUnchanged)
            XCTAssertEqual(
                try local.store.saveIdentity(key, for: address, context: NullContext()),
                .newOrUnchanged,
                "re-saving the same key is idempotent")

            let state = try XCTUnwrap(try local.store.peerIdentity(for: address))
            XCTAssertNil(state.changedAtMs)
            XCTAssertFalse(state.needsAcknowledgement)
        }.value
    }

    func testTrustStateSurvivesAStoreRestart() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }
        let secrets = InMemorySecretStorage()

        let address = try await Task { @CryptoActor () -> ProtocolAddress in
            let local = try LocalFixture(root: root, secrets: secrets)
            let address = try ProtocolAddress(name: "peer-trust-restart", deviceId: 1)
            _ = try local.store.saveIdentity(
                IdentityKeyPair.generate().identityKey, for: address, context: NullContext())
            _ = try local.store.saveIdentity(
                IdentityKeyPair.generate().identityKey, for: address, context: NullContext())
            return address
        }.value

        try await Task { @CryptoActor in
            let reopened = try LocalFixture(root: root, secrets: secrets)
            let state = try XCTUnwrap(try reopened.store.peerIdentity(for: address))
            XCTAssertTrue(state.needsAcknowledgement,
                          "an unacknowledged change must not be forgotten by a restart")
        }.value
    }

    // MARK: - Replay protection

    func testReplayedBaseKeyIsRejected() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let local = try LocalFixture(root: root)
            let baseKey = PrivateKey.generate().publicKey

            try local.store.markKyberPreKeyUsed(
                id: 1, signedPreKeyId: 2, baseKey: baseKey, context: NullContext())

            XCTAssertThrowsError(
                try local.store.markKyberPreKeyUsed(
                    id: 1, signedPreKeyId: 2, baseKey: baseKey, context: NullContext())
            ) { error in
                guard case SignalError.invalidMessage = error else {
                    return XCTFail("expected invalidMessage, got \(error)")
                }
            }

            // A different prekey pair is a different witness, so the same base key is new.
            XCTAssertNoThrow(
                try local.store.markKyberPreKeyUsed(
                    id: 9, signedPreKeyId: 2, baseKey: baseKey, context: NullContext()))
        }.value
    }

    func testBaseKeyWitnessSurvivesAStoreRestart() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }
        let secrets = InMemorySecretStorage()

        let baseKey = PrivateKey.generate().publicKey

        try await Task { @CryptoActor in
            let local = try LocalFixture(root: root, secrets: secrets)
            try local.store.markKyberPreKeyUsed(
                id: 1, signedPreKeyId: 2, baseKey: baseKey, context: NullContext())
        }.value

        try await Task { @CryptoActor in
            let reopened = try LocalFixture(root: root, secrets: secrets)
            XCTAssertThrowsError(
                try reopened.store.markKyberPreKeyUsed(
                    id: 1, signedPreKeyId: 2, baseKey: baseKey, context: NullContext()),
                "replay protection that a restart clears is not replay protection")
        }.value
    }

    /// At capacity the witness evicts oldest-first rather than failing. The tradeoff is
    /// argued in `markKyberPreKeyUsed` and recorded in docs/AUDIT.md.
    func testBaseKeyWitnessEvictsOldestAtCapacity() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let local = try LocalFixture(root: root)
            let oldest = PrivateKey.generate().publicKey

            try local.store.markKyberPreKeyUsed(
                id: 1, signedPreKeyId: 2, baseKey: oldest, context: NullContext())

            // Fill to capacity, which pushes the first entry out.
            for _ in 0..<CipherProtocolStore.baseKeyWitnessCapacity {
                try local.store.markKyberPreKeyUsed(
                    id: 1, signedPreKeyId: 2,
                    baseKey: PrivateKey.generate().publicKey, context: NullContext())
            }

            XCTAssertNoThrow(
                try local.store.markKyberPreKeyUsed(
                    id: 1, signedPreKeyId: 2, baseKey: oldest, context: NullContext()),
                "the oldest witness must have been evicted, not retained forever")
        }.value
    }

    // MARK: - Prekey ids

    func testPreKeyIdsAreMonotonicAcrossRestarts() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }
        let secrets = InMemorySecretStorage()

        let first = try await Task { @CryptoActor () -> ClosedRange<UInt32> in
            let local = try LocalFixture(root: root, secrets: secrets)
            return try local.store.reservePreKeyIds(count: 100)
        }.value

        XCTAssertEqual(first, 1...100)

        try await Task { @CryptoActor in
            let reopened = try LocalFixture(root: root, secrets: secrets)
            let second = try reopened.store.reservePreKeyIds(count: 50)
            XCTAssertEqual(second, 101...150,
                           "ids must never be reissued after a restart")

            let third = try reopened.store.reservePreKeyIds(count: 1)
            XCTAssertEqual(third, 151...151)
        }.value
    }

    func testExhaustingThePreKeyIdSpaceIsRefused() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let local = try LocalFixture(root: root)
            XCTAssertThrowsError(try local.store.reservePreKeyIds(count: 0x100_0000)) { error in
                XCTAssertEqual(error as? ProtocolStoreError, .preKeyIdSpaceExhausted)
            }
        }.value
    }

    // MARK: - Prekey lifecycle

    /// libsignal consumes the one-time prekey itself, from inside the decrypt path. That
    /// has to work against the persistent store too, or a prekey would live forever.
    func testLibsignalConsumesAPersistedOneTimePreKey() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let local = try LocalFixture(root: root)
            let peer = try PeerFixture(
                address: try ProtocolAddress(name: "peer-prekey", deviceId: 1))
            let context = NullContext()

            // Publish a bundle from the *local* store, so its private halves are persisted.
            let ids = try local.store.reservePreKeyIds(count: 3)
            let preKey = PrivateKey.generate()
            let signedPreKey = PrivateKey.generate()
            let kyber = KEMKeyPair.generate()
            let identity = try local.store.identityKeyPair(context: context)

            let signedSignature = identity.privateKey.generateSignature(
                message: signedPreKey.publicKey.serialize())
            let kyberSignature = identity.privateKey.generateSignature(
                message: kyber.publicKey.serialize())

            let preKeyId = ids.lowerBound
            let signedPreKeyId = ids.lowerBound + 1
            let kyberPreKeyId = ids.lowerBound + 2

            try local.store.storePreKey(
                PreKeyRecord(id: preKeyId, privateKey: preKey), id: preKeyId, context: context)
            try local.store.storeSignedPreKey(
                SignedPreKeyRecord(
                    id: signedPreKeyId, timestamp: 1000,
                    privateKey: signedPreKey, signature: signedSignature),
                id: signedPreKeyId, context: context)
            try local.store.storeKyberPreKey(
                KyberPreKeyRecord(
                    id: kyberPreKeyId, timestamp: 1000,
                    keyPair: kyber, signature: kyberSignature),
                id: kyberPreKeyId, context: context)

            XCTAssertEqual(try local.store.remainingPreKeyCount(), 1)

            let bundle = try PreKeyBundle(
                registrationId: try local.store.localRegistrationId(context: context),
                deviceId: local.address.deviceId,
                prekeyId: preKeyId,
                prekey: preKey.publicKey,
                signedPrekeyId: signedPreKeyId,
                signedPrekey: signedPreKey.publicKey,
                signedPrekeySignature: signedSignature,
                identity: identity.identityKey,
                kyberPrekeyId: kyberPreKeyId,
                kyberPrekey: kyber.publicKey,
                kyberPrekeySignature: kyberSignature)

            try processPreKeyBundle(
                bundle, for: local.address, ourAddress: peer.address,
                sessionStore: peer.store, identityStore: peer.store, context: context)

            let inbound = try peer.encrypt("hello local", to: local.address)
            XCTAssertEqual(
                try Local.decrypt(local, inbound.bytes, type: inbound.type, from: peer.address),
                "hello local")

            XCTAssertEqual(try local.store.remainingPreKeyCount(), 0,
                           "libsignal must have removed the consumed one-time prekey")
            XCTAssertGreaterThan(local.spy.removals[.preKey, default: 0], 0)
        }.value
    }

    // MARK: - Destruction

    func testDestroyAllStateClearsRecordsAndIdentity() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }
        let secrets = InMemorySecretStorage()

        try await Task { @CryptoActor in
            let local = try LocalFixture(root: root, secrets: secrets)
            let peer = try PeerFixture(
                address: try ProtocolAddress(name: "peer-destroy", deviceId: 1))

            try Local.establishSession(local, with: peer.address, bundle: try peer.makeBundle())
            XCTAssertNotNil(try local.store.loadSession(for: peer.address, context: NullContext()))

            try local.store.destroyAllState()

            XCTAssertNil(try local.store.loadSession(for: peer.address, context: NullContext()))
            XCTAssertNil(try local.store.peerIdentity(for: peer.address))
            XCTAssertNil(try secrets.load(DeviceIdentity.account))
            XCTAssertNil(try secrets.load(EncryptedFileRecordStore.encryptionKeyAccount))
        }.value
    }

    // MARK: - Helpers

    /// A bundle published by the local store, so a peer can start a session with it.
    @CryptoActor
    private static func bundle(from local: LocalFixture, for peer: PeerFixture) throws
        -> PreKeyBundle {
        let context = NullContext()
        let ids = try local.store.reservePreKeyIds(count: 3)

        let preKey = PrivateKey.generate()
        let signedPreKey = PrivateKey.generate()
        let kyber = KEMKeyPair.generate()
        let identity = try local.store.identityKeyPair(context: context)

        let signedSignature = identity.privateKey.generateSignature(
            message: signedPreKey.publicKey.serialize())
        let kyberSignature = identity.privateKey.generateSignature(
            message: kyber.publicKey.serialize())

        let preKeyId = ids.lowerBound
        let signedPreKeyId = ids.lowerBound + 1
        let kyberPreKeyId = ids.lowerBound + 2

        try local.store.storePreKey(
            PreKeyRecord(id: preKeyId, privateKey: preKey), id: preKeyId, context: context)
        try local.store.storeSignedPreKey(
            SignedPreKeyRecord(
                id: signedPreKeyId, timestamp: 1000,
                privateKey: signedPreKey, signature: signedSignature),
            id: signedPreKeyId, context: context)
        try local.store.storeKyberPreKey(
            KyberPreKeyRecord(
                id: kyberPreKeyId, timestamp: 1000,
                keyPair: kyber, signature: kyberSignature),
            id: kyberPreKeyId, context: context)

        _ = peer
        return try PreKeyBundle(
            registrationId: try local.store.localRegistrationId(context: context),
            deviceId: local.address.deviceId,
            prekeyId: preKeyId,
            prekey: preKey.publicKey,
            signedPrekeyId: signedPreKeyId,
            signedPrekey: signedPreKey.publicKey,
            signedPrekeySignature: signedSignature,
            identity: identity.identityKey,
            kyberPrekeyId: kyberPreKeyId,
            kyberPrekey: kyber.publicKey,
            kyberPrekeySignature: kyberSignature)
    }
}

// MARK: - Public surface

/// `CryptoEngine` is the only type outside this module anything else is meant to hold, so
/// its behaviour is pinned separately from the internals it delegates to.
final class CryptoEngineTests: XCTestCase {

    func testOpeningTwiceKeepsTheSameIdentity() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }
        let secrets = InMemorySecretStorage()

        let first = try await Task { @CryptoActor () -> (UInt32, Data) in
            let engine = try CryptoEngine(root: root, secrets: secrets)
            return (try engine.localRegistrationId, try engine.localIdentityKey)
        }.value

        try await Task { @CryptoActor in
            let reopened = try CryptoEngine(root: root, secrets: secrets)
            XCTAssertEqual(try reopened.localRegistrationId, first.0)
            XCTAssertEqual(try reopened.localIdentityKey, first.1)
        }.value
    }

    /// The public accessor must expose the public half and only the public half.
    func testExposedIdentityKeyIsThePublicHalf() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let engine = try CryptoEngine(root: root, secrets: InMemorySecretStorage())
            let exposed = try engine.localIdentityKey
            XCTAssertEqual(exposed.count, 33, "0x05 type byte plus 32 key bytes")
            XCTAssertNoThrow(try IdentityKey(bytes: exposed))
        }.value
    }

    func testPeerTrustFlowsThroughThePublicSurface() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        let secrets = InMemorySecretStorage()

        try await Task { @CryptoActor in
            let engine = try CryptoEngine(root: root, secrets: secrets)
            let peerName = "peer-public-surface"

            XCTAssertNil(try engine.peerIdentityState(name: peerName, deviceId: 1))

            // Seeded through a store over the same container and Keychain rather than
            // through a test-only hook on CryptoEngine: production types do not grow
            // accessors that exist only so a test can reach past them.
            let address = try ProtocolAddress(name: peerName, deviceId: 1)
            let original = IdentityKeyPair.generate().identityKey
            let replacement = IdentityKeyPair.generate().identityKey
            let seeding = try LocalFixture(root: root, secrets: secrets)
            _ = try seeding.store.saveIdentity(original, for: address, context: NullContext())
            _ = try seeding.store.saveIdentity(replacement, for: address, context: NullContext())

            let state = try XCTUnwrap(try engine.peerIdentityState(name: peerName, deviceId: 1))
            XCTAssertTrue(state.needsAcknowledgement)
            XCTAssertEqual(state.identityKey, replacement.serialize())

            XCTAssertFalse(
                try engine.acceptPeerIdentity(original.serialize(), name: peerName, deviceId: 1),
                "accepting a key that is no longer stored must not take effect")
            XCTAssertTrue(
                try engine.acceptPeerIdentity(
                    replacement.serialize(), name: peerName, deviceId: 1))

            let accepted = try XCTUnwrap(
                try engine.peerIdentityState(name: peerName, deviceId: 1))
            XCTAssertFalse(accepted.needsAcknowledgement)
        }.value
    }

    func testDestroyAllStateClearsTheInstallation() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }
        let secrets = InMemorySecretStorage()

        try await Task { @CryptoActor in
            let engine = try CryptoEngine(root: root, secrets: secrets)
            let before = try engine.localIdentityKey

            try engine.destroyAllState()

            XCTAssertNil(try secrets.load(DeviceIdentity.account))
            XCTAssertNil(try secrets.load(EncryptedFileRecordStore.encryptionKeyAccount))

            // A destroyed engine must refuse everything. Left usable it would keep
            // encrypting under an identity the Keychain no longer holds and seal records
            // under a deleted key, and the damage would only surface a launch later.
            for operation in [
                { _ = try engine.localIdentityKey },
                { _ = try engine.localRegistrationId },
                { _ = try engine.peerIdentityState(name: "anyone", deviceId: 1) },
                { try engine.destroyAllState() },
            ] as [() throws -> Void] {
                XCTAssertThrowsError(try operation()) { error in
                    XCTAssertEqual(error as? CryptoEngineError, .destroyed)
                }
            }

            let reopened = try CryptoEngine(root: root, secrets: secrets)
            XCTAssertNotEqual(try reopened.localIdentityKey, before,
                              "a destroyed installation must come back as a new one")
        }.value
    }
}
