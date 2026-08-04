//
//  SealedRowStoreTests.swift
//  CipherCryptoTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//
//  P5.S11's `Done when`, as tests: no plaintext message body at rest, and the store is
//  unreadable without the Keychain key. Plus the properties that make those two true rather
//  than coincidental — the AAD binding a row to its slot, and the blind index keeping a peer's
//  identifier off disk entirely.
//

import CryptoKit
import Foundation
import SQLite3
import XCTest

@testable import CipherCrypto

final class SealedRowStoreTests: XCTestCase {

    /// Static for the same reason as in `SealedAppStoreTests`: an instance member captured in a
    /// `@CryptoActor` closure is `self` crossing an isolation boundary.
    @CryptoActor
    private static func makeEngine(
        _ root: URL, _ secrets: SecretStorage = InMemorySecretStorage()
    ) throws -> CryptoEngine {
        try CryptoEngine(root: root, secrets: secrets)
    }

    func testProtocolNamespacesAreReservedFromTheAppSurface() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root)
            XCTAssertThrowsError(
                try engine.storeSealedRow(
                    namespace: "proto-session", group: "crafted", ordinal: 0,
                    value: Data("overwrite".utf8))
            ) { error in
                XCTAssertEqual(error as? SealedStoreError, .invalidNamespace)
            }
        }.value
    }

    // MARK: - Reading the container as an attacker would

    /// Every byte of every file in the container, concatenated.
    ///
    /// **The whole container, not the database file.** Under WAL a freshly committed row can
    /// live only in `records.sqlite3-wal` until a checkpoint, so a scan of the main file alone
    /// would report "no plaintext found" against a store that had just written some — a check
    /// passing for the wrong reason, which is AUDIT §0's R2, and specifically R3's shape: the
    /// audit must read everything that ships, not the one artefact it thinks of first.
    private static func containerBytes(_ root: URL) throws -> Data {
        var out = Data()
        let files = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil)
        while let url = files?.nextObject() as? URL {
            var isDirectory: ObjCBool = false
            FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory)
            guard !isDirectory.boolValue else { continue }
            out.append(try Data(contentsOf: url))
        }
        return out
    }

    private static func contains(_ haystack: Data, _ needle: String) -> Bool {
        haystack.range(of: Data(needle.utf8)) != nil
    }

    // MARK: - Done when: no plaintext at rest

    func testNoPlaintextBodyIsAtRestAnywhereInTheContainer() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        // Distinctive enough that a match cannot be a coincidence of encoding.
        let body = "sokolniki-meet-at-eleven-QZX"
        let peer = UUID().uuidString.lowercased()

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root)
            try engine.storeSealedRow(
                namespace: "msg", group: peer, ordinal: 7, value: Data(body.utf8))
        }.value

        let bytes = try Self.containerBytes(root)

        // The positive control. `containerBytes` reporting "not found" is exactly what a broken
        // scanner reports too, so before believing the verdict, prove the scan can find a
        // string that IS in the container. Without this the test passes just as happily against
        // an empty directory.
        let control = "positive-control-\(UUID().uuidString)"
        try Data(control.utf8).write(to: root.appendingPathComponent("control.probe"))
        let withControl = try Self.containerBytes(root)
        XCTAssertTrue(
            Self.contains(withControl, control),
            "the container scan cannot find a string that is in the container, so its "
                + "verdict about the message body means nothing")

        XCTAssertFalse(Self.contains(bytes, body), "the message body is in plaintext at rest")
    }

    /// The peer's identifier must not reach disk either — a plaintext column of ACIs would be
    /// the social graph, which is the thing the design most refuses to hand anyone.
    func testThePeerIdentifierIsNotAtRest() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        let peer = UUID().uuidString.lowercased()

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root)
            try engine.storeSealedRow(
                namespace: "conv", group: peer, ordinal: 0, value: Data("nickname".utf8))
        }.value

        let bytes = try Self.containerBytes(root)
        XCTAssertFalse(
            Self.contains(bytes, peer),
            "the peer's identifier is in a plaintext column; the group must be blinded")
        // Upper-cased too: a UUID written without `lowercased()` elsewhere would be the same
        // identifier in a form this test would otherwise miss.
        XCTAssertFalse(Self.contains(bytes, peer.uppercased()))
    }

    // MARK: - Done when: unreadable without the Keychain key

    func testTheStoreIsUnreadableWithoutTheKeychainKey() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        let secrets = InMemorySecretStorage()
        let group = UUID().uuidString.lowercased()

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root, secrets)
            try engine.storeSealedRow(
                namespace: "msg", group: group, ordinal: 1, value: Data("body".utf8))
        }.value

        // A second installation over the same files: same container, different Keychain. This
        // is the device thief who copied the container but cannot take the key with it.
        //
        // Opening must FAIL. It must not succeed and report an empty store — which is what this
        // did before the key check existed, because a different master key derives a different
        // index key, so every lookup missed and every read returned `nil`. "You have no
        // messages" is the worst of the available answers: it is wrong, it looks normal, and
        // the app would start writing new rows beside the unreadable ones.
        try await Task { @CryptoActor in
            let wrongSecrets = InMemorySecretStorage()
            _ = try wrongSecrets.addOrLoad(
                Data(repeating: 0xA5, count: 32),
                forKey: EncryptedFileRecordStore.encryptionKeyAccount)
            XCTAssertThrowsError(
                try Self.makeEngine(root, wrongSecrets)
            ) { error in
                XCTAssertEqual(error as? SealedDatabaseError, .corruptRecord)
            }
        }.value
    }

    /// The reserved key-check row must be unreachable from the public surface. If a caller
    /// could address that namespace it could overwrite the row that decides whether the
    /// container opens.
    func testTheKeyCheckSlotCannotBeAddressedByACaller() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root)
            XCTAssertThrowsError(
                try engine.storeSealedRow(
                    namespace: "cipher.key-check", group: "g", ordinal: 0, value: Data("x".utf8))
            ) { error in
                XCTAssertEqual(error as? SealedStoreError, .invalidNamespace)
            }
        }.value
    }

    /// The same store, reopened with the *same* key, must still read — otherwise the test above
    /// would pass against a store that never worked at all.
    func testTheStoreIsReadableAcrossAReopenWithTheSameKey() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        let secrets = InMemorySecretStorage()
        let group = UUID().uuidString.lowercased()

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root, secrets)
            try engine.storeSealedRow(
                namespace: "msg", group: group, ordinal: 1, value: Data("body".utf8))
        }.value

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root, secrets)
            XCTAssertEqual(
                try engine.loadSealedRow(namespace: "msg", group: group, ordinal: 1),
                Data("body".utf8))
        }.value
    }

    // MARK: - The AAD binds a row to its slot

    /// Moving a sealed blob to another ordinal must fail to open, not return the wrong message.
    ///
    /// Done by rewriting the row through SQLite directly, because that is what an attacker with
    /// container write access has: the file, and a copy of sqlite3.
    func testARowCopiedToAnotherSlotFailsToOpen() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        let secrets = InMemorySecretStorage()
        let group = UUID().uuidString.lowercased()

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root, secrets)
            try engine.storeSealedRow(
                namespace: "msg", group: group, ordinal: 1, value: Data("first".utf8))
            try engine.storeSealedRow(
                namespace: "msg", group: group, ordinal: 2, value: Data("second".utf8))
        }.value

        // Copy ordinal 1's sealed bytes over ordinal 2's, leaving everything else alone.
        try Self.relocateSealedBlob(root: root, from: 1, to: 2)

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root, secrets)
            XCTAssertThrowsError(
                try engine.loadSealedRow(namespace: "msg", group: group, ordinal: 2)
            ) { error in
                XCTAssertEqual(error as? SealedDatabaseError, .corruptRecord)
            }
            // The untouched row still opens, so the failure above is about the relocation and
            // not about the file having been opened by another process.
            XCTAssertEqual(
                try engine.loadSealedRow(namespace: "msg", group: group, ordinal: 1),
                Data("first".utf8))
        }.value
    }

    /// Opens the database outside the module and moves one row's blob onto another's slot.
    private static func relocateSealedBlob(root: URL, from: Int, to: Int) throws {
        let path = root.appendingPathComponent("records.sqlite3").path
        var db: OpaquePointer?
        XCTAssertEqual(sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, nil), SQLITE_OK)
        defer { sqlite3_close(db) }

        let sql = """
            UPDATE sealed_record SET sealed = (
              SELECT sealed FROM sealed_record WHERE ordinal = \(from)
            ) WHERE ordinal = \(to)
            """
        XCTAssertEqual(sqlite3_exec(db, sql, nil, nil, nil), SQLITE_OK)
    }

    // MARK: - Query shape

    func testListReturnsAGroupInOrdinalOrder() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        let group = UUID().uuidString.lowercased()

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root)
            // Written out of order, to prove the ordering comes from the query.
            for ordinal in [3, 1, 2] {
                try engine.storeSealedRow(
                    namespace: "msg", group: group, ordinal: ordinal,
                    value: Data("m\(ordinal)".utf8))
            }

            let rows = try engine.listSealedRows(namespace: "msg", group: group)
            XCTAssertEqual(rows.map(\.ordinal), [1, 2, 3])
            XCTAssertEqual(rows.map { String(decoding: $0.value, as: UTF8.self) },
                           ["m1", "m2", "m3"])
        }.value
    }

    func testGroupsAreIsolatedFromEachOther() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        let a = UUID().uuidString.lowercased()
        let b = UUID().uuidString.lowercased()

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root)
            try engine.storeSealedRow(namespace: "msg", group: a, ordinal: 1, value: Data("a".utf8))
            try engine.storeSealedRow(namespace: "msg", group: b, ordinal: 1, value: Data("b".utf8))

            XCTAssertEqual(try engine.listSealedRows(namespace: "msg", group: a).count, 1)
            XCTAssertEqual(
                try engine.loadSealedRow(namespace: "msg", group: a, ordinal: 1), Data("a".utf8))
            XCTAssertEqual(
                try engine.loadSealedRow(namespace: "msg", group: b, ordinal: 1), Data("b".utf8))

            // Deleting one group leaves the other whole.
            try engine.removeSealedGroup(namespace: "msg", group: a)
            XCTAssertEqual(try engine.listSealedRows(namespace: "msg", group: a).count, 0)
            XCTAssertEqual(try engine.listSealedRows(namespace: "msg", group: b).count, 1)
        }.value
    }

    func testNamespacesAreSeparateSlots() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        let group = UUID().uuidString.lowercased()

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root)
            try engine.storeSealedRow(
                namespace: "msg", group: group, ordinal: 1, value: Data("message".utf8))
            try engine.storeSealedRow(
                namespace: "conv", group: group, ordinal: 1, value: Data("conversation".utf8))

            XCTAssertEqual(
                try engine.loadSealedRow(namespace: "msg", group: group, ordinal: 1),
                Data("message".utf8))
            XCTAssertEqual(
                try engine.loadSealedRow(namespace: "conv", group: group, ordinal: 1),
                Data("conversation".utf8))
        }.value
    }

    func testListNamespaceSpansEveryGroup() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root)
            for index in 0..<3 {
                try engine.storeSealedRow(
                    namespace: "conv", group: UUID().uuidString.lowercased(), ordinal: 0,
                    value: Data("c\(index)".utf8))
            }
            // A different namespace must not appear in the result.
            try engine.storeSealedRow(
                namespace: "msg", group: UUID().uuidString.lowercased(), ordinal: 0,
                value: Data("not-a-conversation".utf8))

            let values = try engine.listSealedNamespace(namespace: "conv")
                .map { String(decoding: $0, as: UTF8.self) }
            XCTAssertEqual(values.sorted(), ["c0", "c1", "c2"])
        }.value
    }

    // MARK: - Transactions

    func testATransactionThatThrowsLeavesNothingBehind() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        let group = UUID().uuidString.lowercased()

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root)
            struct Abort: Error {}

            XCTAssertThrowsError(
                try engine.withSealedTransaction { transaction in
                    try transaction.store(
                        namespace: "msg", group: group, ordinal: 1, value: Data("one".utf8))
                    try transaction.store(
                        namespace: "msg", group: group, ordinal: 2, value: Data("two".utf8))
                    throw Abort()
                }
            )

            // Both writes are gone, not just the one after the failure.
            XCTAssertEqual(try engine.listSealedRows(namespace: "msg", group: group).count, 0)
        }.value
    }

    func testATransactionThatSucceedsCommitsEverything() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        let group = UUID().uuidString.lowercased()

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root)
            try engine.withSealedTransaction { transaction in
                try transaction.store(
                    namespace: "msg", group: group, ordinal: 1, value: Data("one".utf8))
                try transaction.store(
                    namespace: "msg", group: group, ordinal: 2, value: Data("two".utf8))
            }
            XCTAssertEqual(try engine.listSealedRows(namespace: "msg", group: group).count, 2)
        }.value
    }

    // MARK: - Deletion residue

    /// A logical delete must remove the exact sealed bytes from both the main database and its
    /// WAL. Checkpointing alone leaves deleted cells in free space; `secure_delete` alone leaves
    /// the old main page reachable until its WAL frame is checkpointed. This assertion needs
    /// both controls to be real.
    func testLogicalDeletionScrubsTheMainDatabaseAndTruncatesTheWAL() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root)
            XCTAssertTrue(
                try engine.store.appDatabase.secureDeletionIsEnabled(),
                "the live SQLite connection did not enable full secure deletion")

            try engine.storeSealedRow(
                namespace: "erase-probe", group: "group", ordinal: 7,
                value: Data(repeating: 0x6B, count: 512))

            // Put the row into the main file first. Otherwise a WAL-only row plus a truncated
            // WAL could make a disabled secure_delete setting pass for the wrong reason.
            let sealed = try Self.checkpointAndReadSealedProbe(root: root)
            XCTAssertNotNil(
                try Self.containerBytes(root).range(of: sealed),
                "positive control: the scan could not find the stored sealed row")

            try engine.storeSealedRow(
                namespace: "erase-probe", group: "group", ordinal: 7,
                value: Data(repeating: 0x4D, count: 512))
            XCTAssertNil(
                try Self.containerBytes(root).range(of: sealed),
                "replaced ciphertext remains recoverable from the database or WAL")

            let replacement = try Self.checkpointAndReadSealedProbe(root: root)
            XCTAssertNotNil(
                try Self.containerBytes(root).range(of: replacement),
                "positive control: the scan could not find the replacement sealed row")
            try engine.removeSealedRow(namespace: "erase-probe", group: "group", ordinal: 7)
            XCTAssertNil(
                try engine.loadSealedRow(namespace: "erase-probe", group: "group", ordinal: 7))
            XCTAssertNil(
                try Self.containerBytes(root).range(of: replacement),
                "deleted ciphertext remains recoverable from the database or WAL")

            let wal = root.appendingPathComponent("records.sqlite3-wal")
            if FileManager.default.fileExists(atPath: wal.path) {
                let size = try wal.resourceValues(forKeys: [.fileSizeKey]).fileSize
                XCTAssertEqual(size, 0, "the WAL retained frames after a logical deletion")
            }
        }.value
    }

    /// Turning secure_delete on cannot repair free pages an older build already left behind.
    /// Opening a pre-marker database performs one crash-retryable VACUUM before recording that
    /// its historical residue has been scrubbed.
    func testOpeningAPreHygieneDatabaseScrubsHistoricalDeletedCiphertext() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }
        let secrets = InMemorySecretStorage()

        try await Task { @CryptoActor in
            var engine: CryptoEngine? = try Self.makeEngine(root, secrets)
            engine = nil

            let residue = try Self.plantPreHygieneDeletionResidue(root: root)
            XCTAssertNotNil(
                try Self.containerBytes(root).range(of: residue),
                "positive control: the old deleted value was not present before migration")

            engine = try Self.makeEngine(root, secrets)
            XCTAssertTrue(try XCTUnwrap(engine).store.appDatabase.secureDeletionIsEnabled())
            XCTAssertNil(
                try Self.containerBytes(root).range(of: residue),
                "historical deleted ciphertext survived the deletion-hygiene migration")
        }.value
    }

    /// Group/message clears and protocol-record removals happen inside transactions. The
    /// post-COMMIT path must apply the same scrub as a standalone DELETE.
    func testTransactionalDeletionScrubsCommittedResidue() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root)
            try engine.storeSealedRow(
                namespace: "erase-transaction", group: "group", ordinal: 3,
                value: Data(repeating: 0x2A, count: 512))
            let sealed = try Self.checkpointAndReadSealedProbe(
                root: root, namespace: "erase-transaction", ordinal: 3)
            XCTAssertNotNil(
                try Self.containerBytes(root).range(of: sealed),
                "positive control: the transaction probe was not present before deletion")

            try engine.withSealedTransaction { transaction in
                try transaction.remove(
                    namespace: "erase-transaction", group: "group", ordinal: 3)
            }

            XCTAssertNil(
                try Self.containerBytes(root).range(of: sealed),
                "transactionally deleted ciphertext remains in the database or WAL")
            let wal = root.appendingPathComponent("records.sqlite3-wal")
            if FileManager.default.fileExists(atPath: wal.path) {
                XCTAssertEqual(
                    try wal.resourceValues(forKeys: [.fileSizeKey]).fileSize, 0,
                    "the WAL retained frames after a transactional deletion")
            }
        }.value
    }

    private static func checkpointAndReadSealedProbe(
        root: URL, namespace: String = "erase-probe", ordinal: Int = 7
    ) throws -> Data {
        let path = root.appendingPathComponent("records.sqlite3").path
        var db: OpaquePointer?
        guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, nil) == SQLITE_OK, let db else {
            if db != nil { sqlite3_close(db) }
            throw SealedDatabaseError.ioFailure("test could not open the database")
        }
        defer { sqlite3_close(db) }

        var frames: Int32 = 0
        var checkpointed: Int32 = 0
        guard sqlite3_wal_checkpoint_v2(
            db, nil, SQLITE_CHECKPOINT_TRUNCATE, &frames, &checkpointed) == SQLITE_OK
        else {
            throw SealedDatabaseError.ioFailure("test could not checkpoint the database")
        }

        var statement: OpaquePointer?
        let sql = "SELECT sealed FROM sealed_record WHERE namespace = ? AND ordinal = ?"
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK,
              let statement
        else {
            if statement != nil { sqlite3_finalize(statement) }
            throw SealedDatabaseError.ioFailure("test could not prepare the probe read")
        }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_bind_text(statement, 1, namespace, -1, Self.sqliteTransient) == SQLITE_OK,
              sqlite3_bind_int64(statement, 2, Int64(ordinal)) == SQLITE_OK
        else {
            throw SealedDatabaseError.ioFailure("test could not bind the probe read")
        }
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw SealedDatabaseError.ioFailure("test could not find the probe row")
        }
        let count = Int(sqlite3_column_bytes(statement, 0))
        guard count > 0, let bytes = sqlite3_column_blob(statement, 0) else {
            throw SealedDatabaseError.corruptRecord
        }
        return Data(bytes: bytes, count: count)
    }

    private static let sqliteTransient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

    private static func plantPreHygieneDeletionResidue(root: URL) throws -> Data {
        let path = root.appendingPathComponent("records.sqlite3").path
        var db: OpaquePointer?
        guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, nil) == SQLITE_OK, let db else {
            if db != nil { sqlite3_close(db) }
            throw SealedDatabaseError.ioFailure("test could not open the old database")
        }
        defer { sqlite3_close(db) }

        let residue = Data(repeating: 0xB7, count: 512)
        let residueHex = residue.map { String(format: "%02x", $0) }.joined()
        let tagHex = Data(repeating: 0x41, count: 32)
            .map { String(format: "%02x", $0) }.joined()
        let statements = [
            "PRAGMA secure_delete = OFF",
            "DELETE FROM sealed_record WHERE namespace = 'cipher.key-check' AND ordinal = 1",
            "INSERT INTO sealed_record(namespace, group_tag, ordinal, sealed) "
                + "VALUES('old-residue', X'\(tagHex)', 9, X'\(residueHex)')",
            "PRAGMA wal_checkpoint(TRUNCATE)",
            "DELETE FROM sealed_record WHERE namespace = 'old-residue'",
            "PRAGMA wal_checkpoint(TRUNCATE)",
        ]
        for sql in statements {
            guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else {
                throw SealedDatabaseError.ioFailure("test could not plant old deletion residue")
            }
        }
        return residue
    }

    // MARK: - Slot validation

    func testInvalidNamespacesAreRefusedOnBothPaths() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root)

            for namespace in ["", "Msg", "msg/1", "msg_1", String(repeating: "m", count: 33)] {
                XCTAssertThrowsError(
                    try engine.storeSealedRow(
                        namespace: namespace, group: "g", ordinal: 0, value: Data("x".utf8)),
                    "namespace \(namespace) was accepted")
            }

            // And inside a transaction. The handle was written without this check at first,
            // which would have left the validated and unvalidated paths differing only in
            // whether the caller happened to open a transaction.
            XCTAssertThrowsError(
                try engine.withSealedTransaction { transaction in
                    try transaction.store(
                        namespace: "BAD", group: "g", ordinal: 0, value: Data("x".utf8))
                })
        }.value
    }

    func testAnOversizedValueIsRefused() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root)
            let oversized = Data(count: CryptoEngine.maxSealedRowBytes + 1)
            XCTAssertThrowsError(
                try engine.storeSealedRow(
                    namespace: "msg", group: "g", ordinal: 0, value: oversized)
            ) { error in
                XCTAssertEqual(
                    error as? SealedStoreError, .valueTooLarge(oversized.count))
            }
        }.value
    }

    // MARK: - Destruction

    func testDestroyAllStateRemovesTheDatabaseAndItsSiblings() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root)
            try engine.storeSealedRow(
                namespace: "msg", group: "g", ordinal: 1, value: Data("body".utf8))

            XCTAssertTrue(
                FileManager.default.fileExists(
                    atPath: root.appendingPathComponent("records.sqlite3").path))

            try engine.destroyAllState()

            for url in SealedRecordDatabase.fileURLs(root: root) {
                XCTAssertFalse(
                    FileManager.default.fileExists(atPath: url.path),
                    "\(url.lastPathComponent) survived destroyAllState")
            }
        }.value
    }

    // MARK: - Key separation

    /// The two subkeys must differ. If sealing and indexing shared one key, bytes would be
    /// meaningful in both roles — which is the kind of reuse that turns a single mistake into
    /// two.
    func testTheSealingAndIndexSubkeysDiffer() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let files = try EncryptedFileRecordStore(
                root: root, secrets: InMemorySecretStorage())
            let value = files.deriveSubkey(info: "cipher.sealed-record-database.value.v1")
            let index = files.deriveSubkey(info: "cipher.sealed-record-database.index.v1")

            let valueBytes = value.withUnsafeBytes { Data($0) }
            let indexBytes = index.withUnsafeBytes { Data($0) }
            XCTAssertNotEqual(valueBytes, indexBytes)
            XCTAssertEqual(valueBytes.count, 32)

            // Derivation is deterministic — a fresh subkey per call would make every stored row
            // unreadable on the next launch.
            let again = files.deriveSubkey(info: "cipher.sealed-record-database.value.v1")
            XCTAssertEqual(again.withUnsafeBytes { Data($0) }, valueBytes)
        }.value
    }

    // MARK: - Storage accounting (AUDIT 4.14)

    /// The load-bearing SQLite assumption behind the whole quota, asserted rather than believed.
    ///
    /// Eviction runs *inside* the transaction that appends the message which triggered it, and
    /// it decides when to stop by re-reading `usedBytes`. Both halves of that have to be true:
    /// the freed space must be visible before the commit, and it must be visible as a *fall* in
    /// the figure. `page_count` alone satisfies neither — SQLite never hands freed pages back to
    /// the filesystem — so a quota built on it would trip once and then evict on every append
    /// forever, against a number that never moves. This test is what says the freelist
    /// subtraction is doing that job.
    func testFreedSpaceIsVisibleToTheQuotaInsideTheSameTransaction() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root)
            let payload = Data(repeating: 0xAB, count: 4_000)
            for ordinal in 0..<400 {
                try engine.storeSealedRow(
                    namespace: "msg", group: "peer", ordinal: ordinal, value: payload)
            }

            try engine.withSealedTransaction { transaction in
                let before = try transaction.usedBytes()
                XCTAssertGreaterThan(before, 1_000_000, "400 × 4 KiB should be on disk")

                let removed = try transaction.removeRowsBelow(
                    namespace: "msg", group: "peer", ordinal: 350)
                XCTAssertEqual(removed, 350)

                // Before COMMIT. If this only became true afterwards, eviction could never tell
                // whether it had reclaimed enough and would trim to the floor every time.
                let after = try transaction.usedBytes()
                XCTAssertLessThan(
                    after, before / 2,
                    "freed pages must leave usedBytes inside the same transaction")
            }

            // And the survivors are intact and still authenticate in their own slots.
            let rows = try engine.listSealedRows(namespace: "msg", group: "peer")
            XCTAssertEqual(rows.map(\.ordinal), Array(350..<400))
            XCTAssertEqual(rows.first?.value, payload)
        }.value
    }

    /// `removeRowsBelow` is a retention primitive, so it must take exactly the rows below the
    /// floor — in one group, in one namespace, and nothing else.
    func testTrimmingRemovesOnlyRowsBelowTheFloorInItsOwnGroup() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root)
            for ordinal in 0..<10 {
                try engine.storeSealedRow(
                    namespace: "msg", group: "kept", ordinal: ordinal,
                    value: Data("kept-\(ordinal)".utf8))
                try engine.storeSealedRow(
                    namespace: "msg", group: "trimmed", ordinal: ordinal,
                    value: Data("trimmed-\(ordinal)".utf8))
                try engine.storeSealedRow(
                    namespace: "other", group: "trimmed", ordinal: ordinal,
                    value: Data("other-\(ordinal)".utf8))
            }

            try engine.withSealedTransaction { transaction in
                let removed = try transaction.removeRowsBelow(
                    namespace: "msg", group: "trimmed", ordinal: 6)
                XCTAssertEqual(removed, 6)
            }

            XCTAssertEqual(
                try engine.listSealedRows(namespace: "msg", group: "trimmed").map(\.ordinal),
                Array(6..<10))
            // A different group in the same namespace, and the same group in a different
            // namespace, are both untouched.
            XCTAssertEqual(
                try engine.listSealedRows(namespace: "msg", group: "kept").map(\.ordinal),
                Array(0..<10))
            XCTAssertEqual(
                try engine.listSealedRows(namespace: "other", group: "trimmed").map(\.ordinal),
                Array(0..<10))
        }.value
    }

    /// The conversation cap counts rows, and it is read on the receive path — so it must count
    /// its own namespace only, and must not unseal anything to do it.
    func testRowCountCountsOneNamespaceWithoutUnsealing() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root)
            for index in 0..<7 {
                try engine.storeSealedRow(
                    namespace: "conv", group: "peer-\(index)", ordinal: 0,
                    value: Data("conversation".utf8))
            }
            for ordinal in 0..<25 {
                try engine.storeSealedRow(
                    namespace: "msg", group: "peer-0", ordinal: ordinal,
                    value: Data("message".utf8))
            }

            XCTAssertEqual(try engine.sealedRowCount(namespace: "conv"), 7)
            XCTAssertEqual(try engine.sealedRowCount(namespace: "msg"), 25)
            XCTAssertEqual(try engine.sealedRowCount(namespace: "flag"), 0)
        }.value
    }
}
