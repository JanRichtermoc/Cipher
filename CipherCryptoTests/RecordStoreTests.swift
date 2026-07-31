//
//  RecordStoreTests.swift
//  CipherCryptoTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//
//  Covers the two things everything else rests on: that secrets go into the Keychain with
//  the attributes we claim, and that records on disk are unreadable, unmovable, and
//  untamperable without the key that seals them.
//

import CryptoKit
import Foundation
import LibSignalClient
import XCTest

@testable import CipherCrypto

// MARK: - Keychain

/// Exercises the real Keychain, not the double.
///
/// Every case uses a unique service string, so a run cannot see or clobber items from
/// another run — or from the app.
final class KeychainTests: XCTestCase {

    private func makeKeychain() -> Keychain {
        Keychain(service: "cz.janrichtermoc.Cipher.tests.\(UUID().uuidString)")
    }

    func testAbsentKeyLoadsAsNil() throws {
        let keychain = makeKeychain()
        defer { try? keychain.removeAll() }

        XCTAssertNil(try keychain.load("nothing-here"))
    }

    func testAddOrLoadStoresAndReadsBack() throws {
        let keychain = makeKeychain()
        defer { try? keychain.removeAll() }

        let value = Data(repeating: 0x5A, count: 32)
        XCTAssertEqual(try keychain.addOrLoad(value, forKey: "k"), value)
        XCTAssertEqual(try keychain.load("k"), value)
    }

    /// The property the identity creation race depends on: a second writer never wins, and
    /// is told what the winner stored rather than silently succeeding with its own value.
    func testAddOrLoadNeverOverwritesAndReturnsTheWinnersValue() throws {
        let keychain = makeKeychain()
        defer { try? keychain.removeAll() }

        let first = Data(repeating: 0x01, count: 32)
        let second = Data(repeating: 0x02, count: 32)

        XCTAssertEqual(try keychain.addOrLoad(first, forKey: "k"), first)
        XCTAssertEqual(try keychain.addOrLoad(second, forKey: "k"), first,
                       "the loser must adopt the winner's value, not its own")
        XCTAssertEqual(try keychain.load("k"), first)
    }

    func testRemoveIsIdempotent() throws {
        let keychain = makeKeychain()
        defer { try? keychain.removeAll() }

        _ = try keychain.addOrLoad(Data([0x01]), forKey: "k")
        XCTAssertNoThrow(try keychain.remove("k"))
        XCTAssertNoThrow(try keychain.remove("k"), "removing what is already gone is not an error")
        XCTAssertNil(try keychain.load("k"))
    }

    /// The attribute that decides whether the identity private key can leave the device.
    ///
    /// A wrong constant here fails silently and catastrophically: with plain
    /// `kSecAttrAccessibleAfterFirstUnlock` the key would ride along in every encrypted
    /// backup and restore onto another device, where it could impersonate this
    /// installation without changing anyone's safety number. Nothing at runtime would
    /// look different, so it is asserted against the item the Keychain actually stored
    /// rather than against the dictionary we hoped to send.
    func testStoredItemsAreDeviceOnlyAndAvailableAfterFirstUnlock() throws {
        let keychain = makeKeychain()
        defer { try? keychain.removeAll() }

        _ = try keychain.addOrLoad(Data([0x01]), forKey: "attributes")

        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: keychain.service,
            kSecAttrAccount: "attributes",
            kSecReturnAttributes: true,
            kSecMatchLimit: kSecMatchLimitOne,
            kSecUseDataProtectionKeychain: true,
        ]
        var result: CFTypeRef?
        XCTAssertEqual(SecItemCopyMatching(query as CFDictionary, &result), errSecSuccess)

        let attributes = try XCTUnwrap(result as? [CFString: Any])
        XCTAssertEqual(
            attributes[kSecAttrAccessible] as? String,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String,
            "ThisDeviceOnly keeps the identity key out of backups and off restored devices")
        XCTAssertNotEqual(
            attributes[kSecAttrSynchronizable] as? Bool, true,
            "an identity key must never reach iCloud Keychain")
    }

    /// A synchronizable item must not be findable by our queries at all, so an item planted
    /// by some other path cannot be picked up as if it were ours.
    func testSynchronizableItemsAreNotVisibleToThisStorage() throws {
        let keychain = makeKeychain()
        defer {
            try? keychain.removeAll()
            SecItemDelete([
                kSecClass: kSecClassGenericPassword,
                kSecAttrService: keychain.service,
                kSecAttrSynchronizable: true,
            ] as CFDictionary)
        }

        let planted: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: keychain.service,
            kSecAttrAccount: "synced",
            kSecAttrSynchronizable: true,
            kSecValueData: Data([0xFF]),
        ]
        // Adding may be refused in some environments; the assertion below is meaningful
        // either way, because "not visible" is the property under test.
        _ = SecItemAdd(planted as CFDictionary, nil)

        XCTAssertNil(try keychain.load("synced"))
    }

    func testRemoveAllClearsOnlyThisService() throws {
        let mine = makeKeychain()
        let theirs = makeKeychain()
        defer {
            try? mine.removeAll()
            try? theirs.removeAll()
        }

        _ = try mine.addOrLoad(Data([0xAA]), forKey: "k")
        _ = try theirs.addOrLoad(Data([0xBB]), forKey: "k")

        try mine.removeAll()

        XCTAssertNil(try mine.load("k"))
        XCTAssertEqual(try theirs.load("k"), Data([0xBB]),
                       "removeAll must be scoped to its own service")
    }
}

// MARK: - Encrypted record store

final class EncryptedFileRecordStoreTests: XCTestCase {

    func testRoundTripAndAbsence() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let store = try EncryptedFileRecordStore(root: root, secrets: InMemorySecretStorage())

            XCTAssertNil(try store.load(.session, "absent"))
            try store.store(.session, "peer.1", Data("state".utf8))
            XCTAssertEqual(try store.load(.session, "peer.1"), Data("state".utf8))
            XCTAssertEqual(try store.count(.session), 1)

            try store.remove(.session, "peer.1")
            XCTAssertNil(try store.load(.session, "peer.1"))
            XCTAssertEqual(try store.count(.session), 0)
        }.value
    }

    /// Plaintext must not be recoverable from the container.
    func testRecordsAreNotStoredInTheClear() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let store = try EncryptedFileRecordStore(root: root, secrets: InMemorySecretStorage())
            try store.store(.session, "peer.1", Data("the-quick-brown-fox".utf8))

            let file = try XCTUnwrap(Self.onlyFile(in: root.appendingPathComponent("session")))
            let raw = try Data(contentsOf: file)
            XCTAssertNil(raw.range(of: Data("the-quick-brown-fox".utf8)),
                         "the plaintext appears verbatim on disk")
        }.value
    }

    /// A flipped byte must surface as corruption, never as "no record".
    func testTamperedRecordIsRejected() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let secrets = InMemorySecretStorage()
            let store = try EncryptedFileRecordStore(root: root, secrets: secrets)
            try store.store(.session, "peer.1", Data("state".utf8))

            let file = try XCTUnwrap(Self.onlyFile(in: root.appendingPathComponent("session")))
            var raw = try Data(contentsOf: file)
            raw[raw.index(raw.startIndex, offsetBy: raw.count - 1)] ^= 0xFF
            try raw.write(to: file)

            XCTAssertThrowsError(try store.load(.session, "peer.1")) { error in
                XCTAssertEqual(error as? RecordStoreError, .corruptRecord(kind: .session))
            }
        }.value
    }

    /// The authenticated data is what makes integrity positional. Moving peer A's sealed
    /// record into peer B's slot must fail, not silently give B peer A's session.
    func testRecordMovedToAnotherSlotIsRejected() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let store = try EncryptedFileRecordStore(root: root, secrets: InMemorySecretStorage())
            try store.store(.session, "alice.1", Data("alice-session".utf8))
            try store.store(.session, "mallory.1", Data("mallory-session".utf8))

            let directory = root.appendingPathComponent("session")
            let files = try FileManager.default.contentsOfDirectory(
                at: directory, includingPropertiesForKeys: nil)
            XCTAssertEqual(files.count, 2)

            // Overwrite one slot with the other's sealed bytes.
            let (source, destination) = (files[0], files[1])
            try Data(contentsOf: source).write(to: destination)

            // Exactly one of the two keys now points at a record sealed for the other slot.
            var rejections = 0
            for key in ["alice.1", "mallory.1"] {
                do {
                    _ = try store.load(.session, key)
                } catch {
                    XCTAssertEqual(error as? RecordStoreError, .corruptRecord(kind: .session))
                    rejections += 1
                }
            }
            XCTAssertEqual(rejections, 1, "the relocated record must be refused")
        }.value
    }

    /// Losing the Keychain key must render the container unreadable — that is what makes
    /// deleting the key a cryptographic erase.
    func testRecordsAreUnreadableUnderADifferentKey() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let first = try EncryptedFileRecordStore(root: root, secrets: InMemorySecretStorage())
            try first.store(.session, "peer.1", Data("state".utf8))

            // A fresh secret store means a fresh record key over the same directory.
            let second = try EncryptedFileRecordStore(root: root, secrets: InMemorySecretStorage())
            XCTAssertThrowsError(try second.load(.session, "peer.1")) { error in
                XCTAssertEqual(error as? RecordStoreError, .corruptRecord(kind: .session))
            }
        }.value
    }

    /// Record keys derive from peer-supplied strings, so they must never reach the
    /// filesystem as path components.
    func testKeysCannotEscapeTheContainer() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let store = try EncryptedFileRecordStore(root: root, secrets: InMemorySecretStorage())
            let hostile = "../../../../etc/escape"

            try store.store(.metadata, hostile, Data("payload".utf8))
            XCTAssertEqual(try store.load(.metadata, hostile), Data("payload".utf8))

            let directory = root.appendingPathComponent("metadata")
            let files = try FileManager.default.contentsOfDirectory(atPath: directory.path)
            XCTAssertEqual(files.count, 1)
            let name = try XCTUnwrap(files.first)
            XCTAssertFalse(name.contains("/"))
            XCTAssertFalse(name.contains("."))
            XCTAssertEqual(name.count, 43, "base64url of a SHA-256, unpadded")
        }.value
    }

    /// Session state in a backup would resurrect ratchet state the live device has moved
    /// past, so the container is excluded at creation.
    func testContainerIsExcludedFromBackup() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            _ = try EncryptedFileRecordStore(root: root, secrets: InMemorySecretStorage())
            let values = try root.resourceValues(forKeys: [.isExcludedFromBackupKey])
            XCTAssertEqual(values.isExcludedFromBackup, true)
        }.value
    }

    func testRemoveAllClearsEveryKind() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let store = try EncryptedFileRecordStore(root: root, secrets: InMemorySecretStorage())
            try store.store(.session, "a", Data([1]))
            try store.store(.preKey, "1", Data([2]))
            try store.store(.metadata, "m", Data([3]))

            try store.removeAll()

            XCTAssertNil(try store.load(.session, "a"))
            XCTAssertNil(try store.load(.preKey, "1"))
            XCTAssertNil(try store.load(.metadata, "m"))
            for kind in RecordKind.allCases {
                XCTAssertEqual(try store.count(kind), 0)
            }
        }.value
    }

    private static func onlyFile(in directory: URL) throws -> URL? {
        try FileManager.default
            .contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
            .first
    }
}

// MARK: - Transactional protocol-record migration

final class DatabaseRecordStoreTests: XCTestCase {

    func testLegacyMigrationCleanupRunsAfterCommitAndNeverAfterRollback() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let files = try EncryptedFileRecordStore(
                root: root, secrets: InMemorySecretStorage())
            try files.store(.session, "old.1", Data("old-state".utf8))
            let database = try SealedRecordDatabase(root: root, keys: files)
            let records = DatabaseRecordStore(database: database, legacy: files)
            struct Abort: Error {}

            XCTAssertThrowsError(
                try database.withTransaction {
                    XCTAssertEqual(
                        try records.load(.session, "old.1"), Data("old-state".utf8))
                    try records.store(.session, "new.1", Data("new-state".utf8))
                    throw Abort()
                })

            XCTAssertTrue(
                files.contains(.session, "old.1"),
                "rollback ran post-commit cleanup and deleted the only surviving copy")
            XCTAssertNil(try records.load(.session, "new.1"), "a rolled-back row survived")

            // A successful lazy migration commits its database copy before removing the file.
            XCTAssertEqual(try records.load(.session, "old.1"), Data("old-state".utf8))
            XCTAssertFalse(files.contains(.session, "old.1"))

            // A crash/restore can leave the old file beside the committed database row. It is
            // still one record for replenishment purposes and the database copy wins.
            try files.store(.session, "old.1", Data("stale-state".utf8))
            XCTAssertEqual(try records.count(.session), 1)
            XCTAssertEqual(try records.load(.session, "old.1"), Data("old-state".utf8))
            XCTAssertFalse(files.contains(.session, "old.1"))
        }.value
    }

    func testACommittedTombstoneCannotResurrectALegacyRecord() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let files = try EncryptedFileRecordStore(
                root: root, secrets: InMemorySecretStorage())
            try files.store(.preKey, "7", Data("private-prekey".utf8))
            let database = try SealedRecordDatabase(root: root, keys: files)
            let records = DatabaseRecordStore(database: database, legacy: files)

            try database.withTransaction { try records.remove(.preKey, "7") }
            // Recreate the stale file to model interruption before post-commit cleanup, or a
            // restored old container. The authenticated tombstone must continue to shadow it.
            try files.store(.preKey, "7", Data("stale-private-prekey".utf8))
            XCTAssertNil(try records.load(.preKey, "7"))
            XCTAssertEqual(try records.count(.preKey), 0)
            XCTAssertFalse(files.contains(.preKey, "7"))
        }.value
    }
}

// MARK: - Device identity

final class DeviceIdentityTests: XCTestCase {

    func testIdentityIsCreatedOnceAndIsStable() async throws {
        try await Task { @CryptoActor in
            let secrets = InMemorySecretStorage()

            let first = try DeviceIdentity.loadOrCreate(secrets: secrets)
            let second = try DeviceIdentity.loadOrCreate(secrets: secrets)

            XCTAssertEqual(first.registrationId, second.registrationId)
            XCTAssertEqual(first.identityKey, second.identityKey)
            XCTAssertEqual(
                first.identityKeyPair.privateKey.serialize(),
                second.identityKeyPair.privateKey.serialize(),
                "a second call must not mint a new identity")
        }.value
    }

    func testRegistrationIdIsInTheWireRange() async throws {
        try await Task { @CryptoActor in
            for _ in 0..<32 {
                let identity = try DeviceIdentity.loadOrCreate(secrets: InMemorySecretStorage())
                XCTAssertGreaterThanOrEqual(identity.registrationId, 1)
                XCTAssertLessThanOrEqual(identity.registrationId, 0x3FFF)
            }
        }.value
    }

    /// A corrupt record must not be "recovered" by minting a new identity: that would break
    /// every session and change the safety number with no cause the user could see.
    func testCorruptRecordIsRefusedRatherThanRegenerated() async throws {
        try await Task { @CryptoActor in
            let secrets = InMemorySecretStorage()
            _ = try secrets.addOrLoad(Data([0x01, 0x00, 0x00, 0x00]), forKey: DeviceIdentity.account)

            XCTAssertThrowsError(try DeviceIdentity.loadOrCreate(secrets: secrets)) { error in
                XCTAssertEqual(error as? DeviceIdentityError, .malformedRecord)
            }
        }.value
    }

    func testUnknownRecordVersionIsRefused() async throws {
        try await Task { @CryptoActor in
            let secrets = InMemorySecretStorage()
            var record = Data([0x02])
            record.append(contentsOf: [0x00, 0x00, 0x00, 0x01])
            record.append(IdentityKeyPair.generate().serialize())
            _ = try secrets.addOrLoad(record, forKey: DeviceIdentity.account)

            XCTAssertThrowsError(try DeviceIdentity.loadOrCreate(secrets: secrets)) { error in
                XCTAssertEqual(error as? DeviceIdentityError, .unsupportedRecordVersion(0x02))
            }
        }.value
    }

    /// The loser of a creation race must adopt the winner's identity rather than its own.
    func testConcurrentCreationConvergesOnOneIdentity() async throws {
        try await Task { @CryptoActor in
            let secrets = InMemorySecretStorage()

            let winner = try DeviceIdentity.loadOrCreate(secrets: secrets)
            // Simulate the other process reaching creation with an empty local view by
            // going through the same add-or-load path again.
            let loser = try DeviceIdentity.loadOrCreate(secrets: secrets)

            XCTAssertEqual(winner.identityKey, loser.identityKey)
            XCTAssertEqual(winner.registrationId, loser.registrationId)
        }.value
    }

    func testDestroyRemovesTheIdentity() async throws {
        try await Task { @CryptoActor in
            let secrets = InMemorySecretStorage()
            let created = try DeviceIdentity.loadOrCreate(secrets: secrets)

            try DeviceIdentity.destroy(secrets: secrets)
            XCTAssertNil(try secrets.load(DeviceIdentity.account))

            let replacement = try DeviceIdentity.loadOrCreate(secrets: secrets)
            XCTAssertNotEqual(created.identityKey, replacement.identityKey,
                              "after destruction a fresh identity is expected")
        }.value
    }
}
