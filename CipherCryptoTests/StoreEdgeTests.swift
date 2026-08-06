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

            var tagInput = Data(RecordKind.baseKeyWitness.rawValue.utf8)
            tagInput.append(0)
            tagInput.append(contentsOf: "1.2".utf8)
            let database = local.store.appDatabase
            let encoded = try XCTUnwrap(
                try database.get(
                    namespace: "proto-base-key-witness",
                    groupTag: database.groupTag(tagInput), ordinal: 0))

            XCTAssertLessThan(encoded.count * 8, SealedRecordDatabase.maxSealedBytes,
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
        //
        // Starts at 2, not 1: bit 1 was undefined when this was written and became
        // `verifiedFlag` in P5.S12, so the loop caught its own project's new feature as a
        // corruption. Moving the lower bound is the correct response *because the property
        // did not change* — undefined bits are still refused, and the bit that left this
        // range is now covered in the other direction by
        // SafetyNumberTests.testTheVerifiedBitRoundTripsAndUnknownFlagsAreRefused.
        //
        // Deliberately a literal rather than something derived from `knownFlags`: deriving
        // it would make this loop test whatever the source happens to define, so defining a
        // bit would silently delete its own case (AUDIT R5). Defining bit 2 must break this
        // test, and the person defining it must come here and say so.
        for bit in 2..<8 {
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

    /// If the first, Keychain-backed cryptographic erase fails, no recoverable file may already
    /// have been deleted. This pins the ordering rather than only the successful end state.
    func testKeychainFailureCannotDeleteFilesBeforeCryptographicErase() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }
        let secrets = InMemorySecretStorage(removeAllFailures: 1)

        try await Task { @CryptoActor in
            let local = try LocalFixture(root: root, secrets: secrets)
            let peer = try PeerFixture(address: try ProtocolAddress(name: "peer", deviceId: 1))
            try Local.establishSession(local, with: peer.address, bundle: try peer.makeBundle())
            XCTAssertNotNil(try local.store.loadSession(for: peer.address, context: NullContext()))

            XCTAssertThrowsError(try local.store.destroyAllState()) { error in
                XCTAssertTrue(error is TestSecretStorageError)
            }
            XCTAssertNotNil(
                try local.store.loadSession(for: peer.address, context: NullContext()),
                "a failed Keychain erase must happen before any recoverable file is removed")
            XCTAssertNotNil(try secrets.load(DeviceIdentity.account))
            XCTAssertNotNil(try secrets.load(EncryptedFileRecordStore.encryptionKeyAccount))

            // The same operation is retryable. The second Keychain call succeeds, after which
            // the whole private container is removed.
            try local.store.destroyAllState()
            XCTAssertFalse(FileManager.default.fileExists(atPath: root.path))
        }.value
    }

    /// An absent key beside ciphertext is an interrupted erase. Opening refuses before creating
    /// a replacement key, preserving the exact condition the cleanup path must finish.
    func testCiphertextBesideADestroyedKeyDoesNotMintAReplacement() async throws {
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
            XCTAssertThrowsError(
                try EncryptedFileRecordStore(root: root, secrets: secrets)
            ) { error in
                XCTAssertEqual(error as? RecordStoreError, .missingEncryptionKey)
            }
            XCTAssertNil(
                try secrets.load(EncryptedFileRecordStore.encryptionKeyAccount),
                "opening an interrupted erase minted a replacement record key")
        }.value
    }

    /// A downgraded build must not recognize only its own filenames and mint a replacement key
    /// beside ciphertext introduced by a newer store format.
    func testUnknownCryptoArtifactWithoutAKeyDoesNotMintAReplacement() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try Data("future sealed state".utf8).write(
            to: root.appendingPathComponent("future-records.v2"))
        let secrets = InMemorySecretStorage()

        try await Task { @CryptoActor in
            XCTAssertThrowsError(
                try EncryptedFileRecordStore(root: root, secrets: secrets)
            ) { error in
                XCTAssertEqual(error as? RecordStoreError, .missingEncryptionKey)
            }
            XCTAssertNil(
                try secrets.load(EncryptedFileRecordStore.encryptionKeyAccount),
                "opening unknown persisted state minted a replacement record key")
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
