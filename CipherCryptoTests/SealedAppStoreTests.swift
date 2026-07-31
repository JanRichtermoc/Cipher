//
//  SealedAppStoreTests.swift
//  CipherCryptoTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//
//  The app's message store lives in the crypto module's container so that one Keychain item is
//  the cryptographic erase for protocol state and message bodies together. These tests pin that
//  property, and the slot-collision refusal that makes the namespace boundary real.
//

import CryptoKit
import Foundation
import SQLite3
import XCTest

@testable import CipherCrypto

final class SealedAppStoreTests: XCTestCase {

    /// Static, and every test owns its own container. An instance method or property captured
    /// inside a `@CryptoActor` closure is `self` crossing an isolation boundary, which strict
    /// concurrency refuses — see `StoreEdgeTests` for the same shape.
    @CryptoActor
    private static func makeEngine(
        _ root: URL, _ secrets: SecretStorage = InMemorySecretStorage()
    ) throws -> CryptoEngine {
        try CryptoEngine(root: root, secrets: secrets)
    }

    // MARK: Round trip

    func testStoreLoadRemove() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root)
            XCTAssertNil(try engine.loadSealed(namespace: "msg", key: "a"))

            try engine.storeSealed(namespace: "msg", key: "a", value: Data("body".utf8))
            XCTAssertEqual(try engine.loadSealed(namespace: "msg", key: "a"), Data("body".utf8))

            try engine.removeSealed(namespace: "msg", key: "a")
            XCTAssertNil(try engine.loadSealed(namespace: "msg", key: "a"))
            // Removing what is not there is a no-op, so a retried delete is not an error.
            XCTAssertNoThrow(try engine.removeSealed(namespace: "msg", key: "a"))
        }.value
    }

    func testNamespacesAreSeparateSlots() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root)
            try engine.storeSealed(namespace: "msg", key: "1", value: Data("one".utf8))
            try engine.storeSealed(namespace: "conv", key: "1", value: Data("two".utf8))

            XCTAssertEqual(try engine.loadSealed(namespace: "msg", key: "1"), Data("one".utf8))
            XCTAssertEqual(try engine.loadSealed(namespace: "conv", key: "1"), Data("two".utf8))
        }.value
    }

    // MARK: Nothing on disk is readable, and nothing is plaintext

    func testTheStoredBytesAreNotThePlaintext() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root)
            let secret = "the quick brown fox jumped"
            try engine.storeSealed(namespace: "msg", key: "k", value: Data(secret.utf8))

            // Whatever landed on disk must not contain the plaintext anywhere. This is the
            // "persist ciphertext, never plaintext" claim, checked against the filesystem rather
            // than asserted about the code path.
            let files = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil)
            var checked = 0
            while let url = files?.nextObject() as? URL {
                guard let bytes = try? Data(contentsOf: url), !bytes.isEmpty else { continue }
                checked += 1
                XCTAssertNil(
                    bytes.range(of: Data(secret.utf8)),
                    "plaintext found on disk in \(url.lastPathComponent)")
            }
            XCTAssertGreaterThan(checked, 0, "no files were examined — the check proved nothing")
        }.value
    }

    func testATamperedRecordIsRefusedRatherThanReadAsAbsent() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }
        let secrets = InMemorySecretStorage()

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root, secrets)
            try engine.storeSealed(namespace: "msg", key: "k", value: Data("body".utf8))
        }.value

        // Truncate the sealed database blob through SQLite, exactly as an attacker with
        // container write access would. The key-check row is left intact so reopening proves
        // this particular app record — not the whole database — is what fails authentication.
        try Self.truncateAppDataBlob(root)

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root, secrets)
            XCTAssertThrowsError(try engine.loadSealed(namespace: "msg", key: "k")) { error in
                XCTAssertEqual(error as? RecordStoreError, .corruptRecord(kind: .appData))
            }
        }.value
    }

    private static func truncateAppDataBlob(_ root: URL) throws {
        let path = root.appendingPathComponent("records.sqlite3").path
        var database: OpaquePointer?
        XCTAssertEqual(sqlite3_open_v2(path, &database, SQLITE_OPEN_READWRITE, nil), SQLITE_OK)
        defer { sqlite3_close(database) }
        let sql = """
            UPDATE sealed_record
            SET sealed = substr(sealed, 1, length(sealed) - 1)
            WHERE namespace = 'proto-app-data'
            """
        XCTAssertEqual(sqlite3_exec(database, sql, nil, nil, nil), SQLITE_OK)
        XCTAssertEqual(sqlite3_changes(database), 1, "the fault injection reached no app row")
    }

    // MARK: The slot collision the namespace rule exists to prevent

    func testANamespaceContainingTheSeparatorIsRefused() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root)

            // ("msg/1", "x") and ("msg", "1/x") would compose to the same record key and select
            // the same authenticated database slot (and the same legacy filename), so the AAD
            // binding would agree they belong together. Only the left-hand side has to be
            // unambiguous, so the separator is refused there.
            XCTAssertThrowsError(
                try engine.storeSealed(namespace: "msg/1", key: "x", value: Data("collide".utf8))
            ) { error in
                XCTAssertEqual(error as? SealedStoreError, .invalidNamespace)
            }

            // Proof that the refusal is load-bearing rather than tidiness: the key form that
            // would have collided is legal, and it must keep its own slot.
            try engine.storeSealed(namespace: "msg", key: "1/x", value: Data("mine".utf8))
            XCTAssertEqual(try engine.loadSealed(namespace: "msg", key: "1/x"), Data("mine".utf8))
        }.value
    }

    func testMalformedNamespacesAndKeysAreRefused() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root)
            for namespace in ["", "MSG", "msg_1", "msg 1", String(repeating: "m", count: 33)] {
                XCTAssertThrowsError(
                    try engine.storeSealed(namespace: namespace, key: "k", value: Data())
                ) { error in
                    XCTAssertEqual(
                        error as? SealedStoreError, .invalidNamespace,
                        "namespace \(namespace.debugDescription) should be refused")
                }
            }
            XCTAssertThrowsError(try engine.storeSealed(namespace: "msg", key: "", value: Data())) {
                XCTAssertEqual($0 as? SealedStoreError, .invalidKey)
            }
            XCTAssertThrowsError(
                try engine.loadSealed(
                    namespace: "msg", key: String(repeating: "k", count: 257))
            ) { XCTAssertEqual($0 as? SealedStoreError, .invalidKey) }
        }.value
    }

    func testAnOversizedValueIsRefusedBeforeItIsWritten() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root)
            let oversized = Data(count: CryptoEngine.maxSealedValueBytes + 1)

            XCTAssertThrowsError(
                try engine.storeSealed(namespace: "msg", key: "big", value: oversized)
            ) { error in
                XCTAssertEqual(
                    error as? SealedStoreError, .valueTooLarge(oversized.count))
            }
            XCTAssertNil(try engine.loadSealed(namespace: "msg", key: "big"))

            // The ceiling has to leave room for the AEAD overhead inside the record store's own
            // limit, or a value would write and then refuse to load.
            XCTAssertLessThan(
                CryptoEngine.maxSealedValueBytes, EncryptedFileRecordStore.maxRecordBytes)
        }.value
    }

    // MARK: The reason this lives in the crypto container

    func testDestroyAllStateErasesAppRecordsToo() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }
        // Shared across both engines, exactly as the real Keychain is: the point is that the
        // record encryption key is *gone* afterwards, not that a fresh double forgot it.
        let secrets = InMemorySecretStorage()

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root, secrets)
            try engine.storeSealed(namespace: "msg", key: "k", value: Data("body".utf8))
            try engine.destroyAllState()

            // Every operation refuses afterwards, and — the part that matters — the record
            // encryption key is gone, so anything still on disk is ciphertext no key can open.
            XCTAssertThrowsError(try engine.loadSealed(namespace: "msg", key: "k")) { error in
                XCTAssertEqual(error as? CryptoEngineError, .destroyed)
            }
            XCTAssertNil(try secrets.load(EncryptedFileRecordStore.encryptionKeyAccount))

            // A fresh engine over the same container mints a new key and cannot read the old
            // record. It reads as absent rather than corrupt because the *filename* is derived
            // from the key material's slot, not from the encryption key — the previous file is
            // gone with the container.
            let reopened = try Self.makeEngine(root, secrets)
            XCTAssertNil(try reopened.loadSealed(namespace: "msg", key: "k"))
        }.value
    }
}
