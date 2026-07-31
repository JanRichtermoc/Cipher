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
            XCTAssertThrowsError(
                try Self.makeEngine(root, InMemorySecretStorage())
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
}
