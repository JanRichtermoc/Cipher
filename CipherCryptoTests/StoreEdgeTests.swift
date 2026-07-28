//
//  StoreEdgeTests.swift
//  CipherCryptoTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//
//  P2.S06 — the store's edges, driven with inputs a hostile container would contain.
//
//  These cover the case the happy-path tests cannot: the app's own container is not a
//  trusted input. A file-write exploit, a restored backup, or a sibling process on a
//  jailbroken device can put arbitrary bytes in a record slot, and every one of these
//  behaviours is what happens next.
//

import CryptoKit
import Foundation
import LibSignalClient
import XCTest

@testable import CipherCrypto

final class StoreEdgeTests: XCTestCase {

    // MARK: - Oversized records

    /// A record slot holding a huge file must be refused **before** it is read.
    ///
    /// `Data(contentsOf:)` allocates whatever it finds, so without a size check the process
    /// is killed for memory before the AEAD ever gets to reject the contents — a denial of
    /// service reachable with no key at all.
    func testAnOversizedRecordIsRefusedWithoutBeingRead() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let store = try EncryptedFileRecordStore(root: root, secrets: InMemorySecretStorage())
            try store.store(.session, "victim", Data("real record".utf8))
            XCTAssertNotNil(try store.load(.session, "victim"))

            // Overwrite the slot with something one byte past the ceiling. Sparse, so the
            // test does not actually write a megabyte — which is also the point: reading it
            // would have materialised every byte.
            let path = try XCTUnwrap(Self.recordURL(root: root, kind: .session, key: "victim"))
            let handle = try FileHandle(forWritingTo: path)
            try handle.truncate(atOffset: UInt64(EncryptedFileRecordStore.maxRecordBytes + 1))
            try handle.close()

            XCTAssertThrowsError(try store.load(.session, "victim")) { error in
                guard case RecordStoreError.recordTooLarge(let kind, let bytes) = error else {
                    return XCTFail("expected recordTooLarge, got \(error)")
                }
                XCTAssertEqual(kind, .session)
                XCTAssertGreaterThan(bytes, EncryptedFileRecordStore.maxRecordBytes)
            }
        }.value
    }

    /// The ceiling must not trip on anything the module legitimately writes. A cap that
    /// rejects a real record is an outage, not a control.
    func testTheLargestLegitimateRecordFitsComfortably() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let local = try LocalFixture(root: root)

            // The base-key witness at full capacity is the largest thing this module stores.
            for _ in 0..<CipherProtocolStore.baseKeyWitnessCapacity {
                try local.store.markKyberPreKeyUsed(
                    id: 1, signedPreKeyId: 2,
                    baseKey: PrivateKey.generate().publicKey, context: NullContext())
            }

            let path = try XCTUnwrap(
                Self.recordURL(root: root, kind: .baseKeyWitness, key: "1.2"))
            let size = try XCTUnwrap(
                try path.resourceValues(forKeys: [.fileSizeKey]).fileSize)

            XCTAssertLessThan(size * 8, EncryptedFileRecordStore.maxRecordBytes,
                              "the ceiling must leave real records an order of magnitude of room")
        }.value
    }

    // MARK: - Peer identity flags

    /// Unknown flag bits are refused, not dropped.
    ///
    /// Bit 0 suppresses the "safety number changed" warning. A record written by a future
    /// build that had added, say, a *verified* bit would otherwise be read here with that
    /// meaning silently discarded — showing the user a weaker trust state than the one
    /// actually recorded.
    func testUnknownPeerIdentityFlagBitsAreRefused() throws {
        let key = IdentityKeyPair.generate().identityKey
        let original = PeerIdentityRecord(
            identityKey: key, firstSeenMs: 111, changedAtMs: 222, needsAcknowledgement: true)

        var encoded = original.encode()
        XCTAssertEqual(try PeerIdentityRecord.decode(encoded), original,
                       "positive control: the record must decode before it is corrupted")

        // Every bit this build does not define, one at a time.
        for bit in 1..<8 {
            var mutated = encoded
            mutated[mutated.startIndex + 1] |= UInt8(1 << bit)
            XCTAssertThrowsError(try PeerIdentityRecord.decode(mutated),
                                 "flag bit \(bit) must not be silently ignored") { error in
                XCTAssertEqual(error as? ProtocolStoreError, .malformedPeerIdentity)
            }
        }

        // And the defined bit still round-trips in both states.
        encoded[encoded.startIndex + 1] = 0
        XCTAssertFalse(try PeerIdentityRecord.decode(encoded).needsAcknowledgement)
    }

    func testAPeerIdentityRecordFromAFutureVersionIsRefused() throws {
        var encoded = PeerIdentityRecord(
            identityKey: IdentityKeyPair.generate().identityKey,
            firstSeenMs: 1, changedAtMs: nil, needsAcknowledgement: false).encode()
        encoded[encoded.startIndex] = 2

        XCTAssertThrowsError(try PeerIdentityRecord.decode(encoded)) { error in
            XCTAssertEqual(error as? ProtocolStoreError, .malformedPeerIdentity)
        }
    }

    // MARK: - Destruction ordering

    /// `destroyAllState` removes records **before** the Keychain secrets.
    ///
    /// The ordering is the guarantee: interrupted after the records are gone, nothing
    /// readable is left; interrupted after the secrets are gone, whatever survives on disk is
    /// ciphertext under a key that no longer exists. The reverse order would leave a window
    /// where plaintext-recoverable records outlive the intent to destroy them.
    func testDestroyLeavesNothingReadableEvenIfTheKeychainSurvives() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }
        let secrets = InMemorySecretStorage()

        try await Task { @CryptoActor in
            let local = try LocalFixture(root: root, secrets: secrets)
            let peer = try PeerFixture(address: try ProtocolAddress(name: "peer", deviceId: 1))
            try Local.establishSession(local, with: peer.address, bundle: try peer.makeBundle())
            XCTAssertNotNil(try local.store.loadSession(for: peer.address, context: NullContext()))

            try local.store.destroyAllState()

            // A fresh store over the same directory: a new identity, a new record key, and
            // no trace of the session that was there.
            let reopened = try LocalFixture(root: root, secrets: secrets)
            XCTAssertNil(try reopened.store.loadSession(for: peer.address, context: NullContext()))
            XCTAssertNil(try reopened.store.peerIdentity(for: peer.address))
            XCTAssertEqual(try reopened.store.reservePreKeyIds(count: 1), 1...1,
                           "the prekey counter must have gone with everything else")
        }.value
    }

    /// A record sealed under a destroyed key is unreadable rather than merely absent.
    func testRecordsSealedUnderADestroyedKeyCannotBeOpened() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }
        let secrets = InMemorySecretStorage()

        try await Task { @CryptoActor in
            let first = try EncryptedFileRecordStore(root: root, secrets: secrets)
            try first.store(.metadata, "survivor", Data("secret".utf8))

            let path = try XCTUnwrap(
                Self.recordURL(root: root, kind: .metadata, key: "survivor"))
            let sealed = try Data(contentsOf: path)
            XCTAssertNil(sealed.range(of: Data("secret".utf8)),
                         "the record must not be plaintext on disk in the first place")

            // Destroy only the key, leaving the file — the state an interrupted destroy or a
            // partially restored backup would produce.
            try secrets.remove(EncryptedFileRecordStore.encryptionKeyAccount)
            let rekeyed = try EncryptedFileRecordStore(root: root, secrets: secrets)

            XCTAssertThrowsError(try rekeyed.load(.metadata, "survivor")) { error in
                XCTAssertEqual(error as? RecordStoreError, .corruptRecord(kind: .metadata),
                               "an unopenable record must never be reported as 'not found'")
            }
        }.value
    }

    // MARK: - Helpers

    /// Mirrors the store's own filename derivation so a test can reach a specific slot.
    /// Deliberately re-derived rather than exposed: a production accessor that hands out
    /// record paths is a liability, and if this drifts the tests that use it fail loudly.
    private static func recordURL(root: URL, kind: RecordKind, key: String) -> URL? {
        var separated = Data(kind.rawValue.utf8)
        separated.append(0x00)
        separated.append(contentsOf: Array(key.utf8))

        let name = Data(SHA256.hash(data: separated))
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")

        return root.appendingPathComponent(kind.rawValue, isDirectory: true)
            .appendingPathComponent(name, isDirectory: false)
    }
}
