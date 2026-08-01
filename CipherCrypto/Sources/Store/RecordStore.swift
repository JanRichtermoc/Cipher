//
//  RecordStore.swift
//  CipherCrypto
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

/// The kinds of record the protocol store persists.
///
/// A closed enum rather than free-form strings: the raw value becomes both a directory
/// name and part of the AEAD's authenticated data, so it is a storage format decision and
/// must not be something a caller can invent at a call site.
internal enum RecordKind: String, CaseIterable, Sendable {
    /// Double Ratchet session state, keyed by protocol address. Contains chain keys.
    case session
    /// One-time prekeys, keyed by id. Contains private halves.
    case preKey = "prekey"
    /// The signed prekey, keyed by id. Contains a private half.
    case signedPreKey = "signed-prekey"
    /// Kyber prekeys, keyed by id. Contains private halves.
    case kyberPreKey = "kyber-prekey"
    /// Peer identity keys and their trust state, keyed by protocol address. Public data,
    /// but its *integrity* is what safety numbers rest on.
    case peerIdentity = "peer-identity"
    /// Base keys already seen against a given (kyber prekey, signed prekey) pair. Replay
    /// protection for session establishment.
    case baseKeyWitness = "base-key-witness"
    /// Small counters and flags owned by this module.
    case metadata
    /// Application records — conversations and message bodies (P5.S10). Sealed and destroyed
    /// exactly like everything above, which is the whole reason they live here rather than in
    /// a second store the app would have to key separately. See `SealedAppStore.swift`.
    case appData = "app-data"
}

/// A synchronous, namespaced blob store.
///
/// Synchronous is a requirement, not a simplification: libsignal invokes the store
/// protocols from inside an FFI call and they cannot suspend. Everything here therefore
/// runs on the crypto queue, which is also why the implementations assert isolation.
///
/// There is deliberately **no key enumeration**. The current database keeps keys inside its
/// sealed values and exposes no way to list them; legacy filenames are one-way hashes. Nothing
/// in the design needs enumeration: prekey ids come from a monotonic counter in `.metadata`
/// rather than from "what ids exist", which can never reuse an id that was just consumed.
internal protocol RecordStore: AnyObject {
    func load(_ kind: RecordKind, _ key: String) throws -> Data?
    func store(_ kind: RecordKind, _ key: String, _ value: Data) throws
    func remove(_ kind: RecordKind, _ key: String) throws
    /// Number of records of `kind`. Used for prekey replenishment thresholds.
    func count(_ kind: RecordKind) throws -> Int
    /// Destroys every record. The caller is responsible for any key material that made
    /// them readable.
    func removeAll() throws
}

/// Protocol records stored in the same SQLite transaction as the message archive.
///
/// libsignal advances a ratchet while decrypting. If that write commits separately from the
/// plaintext archive, a full disk or crash can consume the only usable message key while the
/// relay copy remains unacknowledged; the retry then looks permanently undecryptable and is
/// dropped. Keeping both sets of sealed rows on one connection makes receive all-or-nothing.
///
/// Existing file records are migrated lazily because their filenames are one-way hashes and
/// cannot be enumerated back into record keys. A database value or authenticated tombstone
/// always shadows the legacy slot. The old file is removed only after the database commit, so
/// rollback can never delete the last copy.
internal final class DatabaseRecordStore: RecordStore {

    private static let envelopeVersion: UInt8 = 1
    private static let maxKeyBytes = 4096
    private static let ordinal = 0

    private let database: SealedRecordDatabase
    private let legacy: EncryptedFileRecordStore

    internal init(database: SealedRecordDatabase, legacy: EncryptedFileRecordStore) {
        CryptoActor.assertIsolated()
        self.database = database
        self.legacy = legacy
        retryCommittedLegacyCleanup()
    }

    internal func load(_ kind: RecordKind, _ key: String) throws -> Data? {
        CryptoActor.assertIsolated()
        return try mapErrors(kind) {
            let tag = recordTag(kind, key)
            if let tombstone = try database.get(
                namespace: tombstoneNamespace(kind), groupTag: tag, ordinal: Self.ordinal)
            {
                _ = try decode(tombstone, expectedKey: key, kind: kind)
                scheduleLegacyRemoval(kind, key)
                return nil
            }
            if let stored = try database.get(
                namespace: valueNamespace(kind), groupTag: tag, ordinal: Self.ordinal)
            {
                let value = try decode(stored, expectedKey: key, kind: kind)
                scheduleLegacyRemoval(kind, key)
                return value
            }

            guard let value = try legacy.load(kind, key) else { return nil }
            try putValue(kind, key, value)
            scheduleLegacyRemoval(kind, key)
            return value
        }
    }

    internal func store(_ kind: RecordKind, _ key: String, _ value: Data) throws {
        CryptoActor.assertIsolated()
        try mapErrors(kind) {
            try database.atomically {
                try putValue(kind, key, value)
                try database.remove(
                    namespace: tombstoneNamespace(kind), groupTag: recordTag(kind, key),
                    ordinal: Self.ordinal)
                scheduleLegacyRemoval(kind, key)
            }
        }
    }

    internal func remove(_ kind: RecordKind, _ key: String) throws {
        CryptoActor.assertIsolated()
        try mapErrors(kind) {
            try database.atomically {
                let tag = recordTag(kind, key)
                try database.remove(
                    namespace: valueNamespace(kind), groupTag: tag, ordinal: Self.ordinal)
                // The tombstone is itself sealed and bound to this slot. It prevents a legacy
                // file from being resurrected if cleanup is interrupted after the commit.
                try database.put(
                    namespace: tombstoneNamespace(kind), groupTag: tag, ordinal: Self.ordinal,
                    value: try encode(key: key, value: Data(), kind: kind))
                scheduleLegacyRemoval(kind, key)
            }
        }
    }

    internal func count(_ kind: RecordKind) throws -> Int {
        CryptoActor.assertIsolated()
        return try mapErrors(kind) {
            let values = try database.listNamespace(valueNamespace(kind))
                .map { try decodeEnvelope($0.value, kind: kind) }
            let tombstones = try database.listNamespace(tombstoneNamespace(kind))
                .map { try decodeEnvelope($0.value, kind: kind) }

            var total = try legacy.count(kind) + values.count
            // A lazily migrated value may still have its old file if post-commit cleanup was
            // interrupted. It is one record, not two. A tombstoned legacy file is zero records.
            for entry in values where legacy.contains(kind, entry.key) { total -= 1 }
            for entry in tombstones where legacy.contains(kind, entry.key) { total -= 1 }
            return max(0, total)
        }
    }

    internal func removeAll() throws {
        CryptoActor.assertIsolated()
        try mapErrors(.metadata) {
            try database.withTransaction {
                for kind in RecordKind.allCases {
                    try database.removeNamespace(valueNamespace(kind))
                    try database.removeNamespace(tombstoneNamespace(kind))
                }
            }
            try legacy.removeAll()
        }
    }

    private func putValue(_ kind: RecordKind, _ key: String, _ value: Data) throws {
        let encoded = try encode(key: key, value: value, kind: kind)
        // Account for the database envelope byte, AES-GCM nonce and authentication tag. Refuse
        // before sealing so a value that writes is guaranteed to pass the bounded read.
        guard encoded.count + 1 + 12 + 16 <= SealedRecordDatabase.maxSealedBytes else {
            throw RecordStoreError.recordTooLarge(kind: kind, bytes: encoded.count)
        }
        try database.put(
            namespace: valueNamespace(kind), groupTag: recordTag(kind, key),
            ordinal: Self.ordinal, value: encoded)
    }

    private func scheduleLegacyRemoval(_ kind: RecordKind, _ key: String) {
        guard legacy.contains(kind, key) else { return }
        database.afterCommit { [legacy] in
            do {
                try legacy.remove(kind, key)
            } catch {
                // The database value/tombstone is already durable and shadows this copy. A
                // cleanup failure must not report the committed crypto operation as rolled back.
                CipherLog.store.error("could not remove a migrated legacy record")
            }
        }
    }

    /// Retries file cleanup which a previous process lost after committing its database copy.
    ///
    /// Both value rows and tombstones carry the original key inside their sealed envelope, so
    /// cleanup does not depend on a one-shot migration marker or on being able to reverse a
    /// legacy hashed filename. A failed unlink remains harmless (the database row shadows it)
    /// and is retried on every open until it succeeds.
    private func retryCommittedLegacyCleanup() {
        for kind in RecordKind.allCases {
            for namespace in [valueNamespace(kind), tombstoneNamespace(kind)] {
                let entries: [(groupTag: Data, ordinal: Int, value: Data)]
                do {
                    entries = try database.listNamespace(namespace)
                } catch {
                    CipherLog.store.error("could not inspect committed legacy cleanup records")
                    continue
                }
                for entry in entries {
                    do {
                        let key = try decodeEnvelope(entry.value, kind: kind).key
                        guard legacy.contains(kind, key) else { continue }
                        try legacy.remove(kind, key)
                    } catch {
                        // One damaged cleanup record must not prevent valid entries later in the
                        // namespace from being retried. Its own normal access still fails closed.
                        CipherLog.store.error("legacy record cleanup will be retried")
                    }
                }
            }
        }
    }

    private func valueNamespace(_ kind: RecordKind) -> String { "proto-\(kind.rawValue)" }
    private func tombstoneNamespace(_ kind: RecordKind) -> String { "proto-del-\(kind.rawValue)" }

    private func recordTag(_ kind: RecordKind, _ key: String) -> Data {
        var input = Data(kind.rawValue.utf8)
        input.append(0)
        input.append(contentsOf: key.utf8)
        return database.groupTag(input)
    }

    private func encode(key: String, value: Data, kind: RecordKind) throws -> Data {
        let keyBytes = Data(key.utf8)
        guard !keyBytes.isEmpty, keyBytes.count <= Self.maxKeyBytes else {
            throw RecordStoreError.ioFailure("a \(kind.rawValue) record key was invalid")
        }
        var out = Data([Self.envelopeVersion])
        withUnsafeBytes(of: UInt32(keyBytes.count).bigEndian) { out.append(contentsOf: $0) }
        out.append(keyBytes)
        out.append(value)
        return out
    }

    private func decode(_ bytes: Data, expectedKey: String, kind: RecordKind) throws -> Data {
        let entry = try decodeEnvelope(bytes, kind: kind)
        guard entry.key == expectedKey else { throw RecordStoreError.corruptRecord(kind: kind) }
        return entry.value
    }

    private func decodeEnvelope(_ bytes: Data, kind: RecordKind) throws
        -> (key: String, value: Data) {
        guard bytes.count >= 5, bytes[bytes.startIndex] == Self.envelopeVersion else {
            throw RecordStoreError.corruptRecord(kind: kind)
        }
        var keyLength: UInt32 = 0
        for offset in 1...4 {
            keyLength = (keyLength << 8) | UInt32(bytes[bytes.index(bytes.startIndex, offsetBy: offset)])
        }
        let count = Int(keyLength)
        guard count > 0, count <= Self.maxKeyBytes, bytes.count >= 5 + count else {
            throw RecordStoreError.corruptRecord(kind: kind)
        }
        let keyStart = bytes.index(bytes.startIndex, offsetBy: 5)
        let keyEnd = bytes.index(keyStart, offsetBy: count)
        guard let key = String(data: bytes[keyStart..<keyEnd], encoding: .utf8) else {
            throw RecordStoreError.corruptRecord(kind: kind)
        }
        return (key, Data(bytes[keyEnd...]))
    }

    private func mapErrors<T>(_ kind: RecordKind, _ body: () throws -> T) throws -> T {
        do {
            return try body()
        } catch let error as RecordStoreError {
            throw error
        } catch let error as SealedDatabaseError {
            switch error {
            case .corruptRecord:
                throw RecordStoreError.corruptRecord(kind: kind)
            case .unsupportedValueVersion(let version):
                throw RecordStoreError.unsupportedRecordVersion(version)
            case .rowTooLarge(let bytes):
                throw RecordStoreError.recordTooLarge(kind: kind, bytes: bytes)
            case .closed, .nestedTransaction, .secureDeletionPending, .ioFailure:
                throw RecordStoreError.ioFailure("the protocol database was unavailable")
            }
        }
    }
}

// MARK: - Errors

internal enum RecordStoreError: Error, Equatable {
    /// A record failed to decrypt or its authenticated data did not match.
    ///
    /// This is never a normal state. It means the row or legacy file was truncated, corrupted,
    /// moved between slots, or written by a different installation's key. It is surfaced rather
    /// than swallowed: silently treating a damaged session record as "no session" would
    /// hand an attacker with write access to the container a free session-reset primitive.
    case corruptRecord(kind: RecordKind)
    /// The on-disk envelope version is not one this build understands.
    case unsupportedRecordVersion(UInt8)
    /// The record encryption key in the Keychain is not the expected size.
    case malformedEncryptionKey
    /// Ciphertext exists but the Keychain key which owned it is gone. This is an interrupted
    /// cryptographic erase, never a fresh store and never a reason to mint a replacement key.
    case missingEncryptionKey
    /// A slot holds more bytes than any record this module writes, so it was refused
    /// **without being read**. Distinct from `corruptRecord`: nothing was authenticated here,
    /// and the point is that the allocation never happened.
    case recordTooLarge(kind: RecordKind, bytes: Int)
    case ioFailure(String)
}
