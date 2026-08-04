//
//  SealedRecordDatabase.swift
//  CipherCrypto
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import CryptoKit
import Foundation
import SQLite3

/// A queryable store whose every value is sealed, and whose every index key names nobody.
///
/// ## Why a database, and what was wrong with files
///
/// `EncryptedFileRecordStore` originally gave one sealed file per protocol record. That was
/// wrong for conversations and, more seriously, could not commit a ratchet advance together
/// with the plaintext archive. This database now backs both shapes: queryable archive rows and
/// protocol key-value rows through `DatabaseRecordStore`. `AUDIT.md` 4.3 was explicit that the
/// original archive residual was **query shape, not confidentiality**; the shared transaction
/// closes the separate receive-durability defect without giving up either property.
///
/// ## What is in plaintext on disk, exactly
///
/// Three things, and nothing else: the namespace (`conv`, `msg`, …, which is in the source
/// code anyway), the caller's ordinal, and the length of each sealed value. In particular:
///
/// - **No message body, nickname, timestamp or state** — all of that is inside `sealed`.
/// - **No peer identifier.** A peer's rows are found by a *blind index* (see `groupTag`), not
///   by a column holding a UUID. This is not decoration: the file store's filenames are
///   `base64url(SHA-256(kind ‖ 0x00 ‖ key))`, so the container has never named a
///   correspondent, and a plaintext peer column would have been a straight regression. The
///   list of who this device talks to is the social graph the whole design refuses to hand
///   anyone (`THREAT_MODEL.md` §1.1); handing it instead to anything with container access
///   would be answering the wrong question.
///
/// **The residual an index does cost, stated rather than implied:** whoever holds the file can
/// *group* rows by tag and count them, learning "three conversations, of 200, 40 and 5
/// messages", without learning who any of them is. The hash-per-file layout did not permit
/// that, because each filename mixed in the ordinal. This is the price of an index — the
/// alternative is not having one — and it is bounded by the fact that reaching the container at
/// all already means code executing on the device after first unlock (`AUDIT.md` 2.1).
///
/// ## Keys
///
/// Two subkeys, both HKDF-SHA256 from the **existing** record encryption key: one seals
/// values, one computes group tags. Deriving rather than minting a second Keychain item is
/// load-bearing — deleting that one item must stay the cryptographic erase for everything, or
/// "delete everything" deletes half of it and leaves the rest as ciphertext whose key is still
/// in the Keychain. Distinct `info` strings, so bytes can never be meaningful in the other
/// role.
///
/// ## Isolation
///
/// Not `Sendable`, like every other store here, and every entry point asserts the crypto
/// queue. The SQLite connection is owned by this object and never escapes it.
internal final class SealedRecordDatabase {

    /// On-disk envelope version for a sealed value. A row written by a newer build is refused,
    /// never guessed at — the same rule as the file store's record version.
    private static let valueVersion: UInt8 = 1

    /// Ceiling on one sealed value, checked **before** the blob is copied out of SQLite.
    ///
    /// Same reasoning as `EncryptedFileRecordStore.maxRecordBytes`: the container is not a
    /// trusted input, and an attacker who can write into it can leave a huge blob in a row.
    /// `sqlite3_column_bytes` reports the length without materialising it, so the allocation is
    /// refused rather than attempted.
    internal static let maxSealedBytes = 1024 * 1024

    private let root: URL
    private let fileManager: FileManager
    private let sealingKey: SymmetricKey
    private let indexKey: SymmetricKey
    private var handle: OpaquePointer?
    private var transactionIsActive = false
    private var transactionNeedsSecureCheckpoint = false
    private var secureCheckpointIsPending = false
    private var afterCommitActions: [() -> Void] = []

    /// Base name of the database. Its `-wal` and `-shm` siblings are part of the store and are
    /// protected alongside it; see `applyFileProtection`.
    private static let fileName = "records.sqlite3"

    // MARK: - Opening

    internal init(root: URL, keys: RecordKeyDeriving, fileManager: FileManager = .default) throws {
        CryptoActor.assertIsolated()

        self.root = root
        self.fileManager = fileManager
        // Distinct info strings are the domain separation. No salt: HKDF does not need one
        // when the input key material is already a uniformly random 256-bit CSPRNG key, and a
        // salt stored beside the ciphertext would add a moving part without adding an
        // unpredictable one.
        self.sealingKey = keys.deriveSubkey(info: "cipher.sealed-record-database.value.v1")
        self.indexKey = keys.deriveSubkey(info: "cipher.sealed-record-database.index.v1")

        try open()
    }

    private func open() throws {
        let path = root.appendingPathComponent(Self.fileName, isDirectory: false)

        // The root is created by `EncryptedFileRecordStore` with the protection class and the
        // backup exclusion already on it. Created here too rather than depending on
        // construction order: this type must be correct about its own container.
        if !fileManager.fileExists(atPath: root.path) {
            do {
                try fileManager.createDirectory(
                    at: root, withIntermediateDirectories: true,
                    attributes: [
                        .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication
                    ])
            } catch {
                throw SealedDatabaseError.ioFailure("creating the database root failed")
            }
        }

        var db: OpaquePointer?
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE
        guard sqlite3_open_v2(path.path, &db, flags, nil) == SQLITE_OK, db != nil else {
            if db != nil { sqlite3_close(db) }
            throw SealedDatabaseError.ioFailure("opening the database failed")
        }
        self.handle = db

        // WAL: a commit appends to a log rather than rewriting pages in place, so an
        // interrupted write cannot leave a torn page in the main file.
        try execute("PRAGMA journal_mode = WAL")

        // A logical delete must overwrite the deleted cell inside the page SQLite writes.
        // Without this, checkpointing the page can faithfully copy the old sealed value into
        // free space in the main database, where it remains recoverable while the installation
        // still has the key. `ON`, not `FAST`: FAST only scrubs some b-tree content.
        try execute("PRAGMA secure_delete = ON")
        guard try pragmaInteger("PRAGMA secure_delete") == 1 else {
            throw SealedDatabaseError.ioFailure("secure deletion was not enabled")
        }

        // Once a checkpoint has copied frames into the main database, leave no preallocated WAL
        // behind. The explicit TRUNCATE checkpoints below are the primary control; this keeps a
        // future automatic checkpoint from retaining capacity unexpectedly.
        try execute("PRAGMA journal_size_limit = 0")

        // FULL, not NORMAL, and this one is a correctness requirement rather than a
        // preference. The receive path acknowledges a message to the relay only once it is
        // durably stored, and the relay then deletes its copy — an envelope decrypts exactly
        // once, so a message lost after acknowledgement is lost permanently. Under
        // `synchronous = NORMAL` in WAL mode a commit is not flushed, so a power loss can
        // discard a transaction the app has already treated as durable. That is precisely the
        // failure `ConversationArchive`'s header exists to prevent.
        try execute("PRAGMA synchronous = FULL")

        // A spill to a temporary file would put pages outside this container. They would still
        // be sealed, but the container rules are the container rules.
        try execute("PRAGMA temp_store = MEMORY")

        try execute("""
            CREATE TABLE IF NOT EXISTS sealed_record (
              namespace TEXT NOT NULL,
              group_tag BLOB NOT NULL,
              ordinal   INTEGER NOT NULL,
              sealed    BLOB NOT NULL,
              PRIMARY KEY (namespace, group_tag, ordinal)
            ) WITHOUT ROWID
            """)

        try verifyKey()
        try migrateDeletionHygieneIfNeeded()

        // Finish a checkpoint an interrupted older process may have left behind before any
        // caller is allowed to use the store. This is also what makes a failed post-commit
        // truncation retryable across a relaunch.
        try checkpointAndTruncateWAL()

        // After the schema write, so the WAL exists to be protected.
        try applyFileProtection()
    }

    /// Refuses to open a database this key cannot read.
    ///
    /// **Found by its own test, and the reason this exists at all.** Every other store here
    /// surfaces a wrong key as `corruptRecord`, never as absence — AUDIT 4.9 is explicit that
    /// silently treating unreadable state as "nothing here" would be a free reset primitive.
    /// The blind index broke that for this store without anyone having to make a mistake: a
    /// wrong master key derives a different *index* key, so `groupTag` produces a different tag,
    /// every lookup misses, and reads return `nil`. The file store cannot fail that way because
    /// its filenames are unkeyed — the file is found and the AEAD then rejects it.
    ///
    /// The consequence would not have been a subtle one. A device whose Keychain item was
    /// replaced would show an empty conversation list and begin writing new rows beside the old
    /// ones, so "your messages are gone" would be the *reported* state and orphaning them would
    /// be the actual one.
    ///
    /// So: one row, at a slot whose tag is a fixed constant rather than a derived one — it has
    /// to be findable *before* we know the key is right — holding a known plaintext sealed
    /// under the sealing key. Absent means a new database and it is written. Present but
    /// unopenable means this key does not own this container, and nothing further happens.
    private func verifyKey() throws {
        let namespace = Self.keyCheckNamespace
        let tag = Self.keyCheckTag

        if let stored = try get(namespace: namespace, groupTag: tag, ordinal: 0) {
            guard stored == Self.keyCheckPlaintext else {
                // Opened, so the key is right, but the contents are not what we wrote.
                throw SealedDatabaseError.corruptRecord
            }
            return
        }
        try put(
            namespace: namespace, groupTag: tag, ordinal: 0, value: Self.keyCheckPlaintext)
    }

    /// Reserved for the key check, and **unreachable by any caller**: the `.` puts it outside
    /// the `[a-z0-9-]` set `SealedRowSlot.validate` enforces at the public boundary, so no
    /// namespace an app can name will ever address this row. Reserving it by convention — a
    /// name nobody was expected to pick — would have been a collision waiting for the first
    /// caller who picked it, and the row it would overwrite is the one that decides whether the
    /// container opens at all.
    private static let keyCheckNamespace = "cipher.key-check"

    /// A constant, not a derived tag: the row has to be findable before the key is trusted.
    private static let keyCheckTag = Data(SHA256.hash(data: Data("cipher.key-check.v1".utf8)))

    private static let keyCheckPlaintext = Data("cipher.sealed-record-database.v1".utf8)

    /// A sealed marker distinct from the key check. Its absence means this database may have
    /// been written by a build which neither enabled secure_delete nor scrubbed old free pages.
    private static let deletionHygienePlaintext = Data("cipher.deletion-hygiene.v1".utf8)

    /// Scrubs residue created by builds which predate secure deletion.
    ///
    /// Enabling the pragma only affects future page edits. `VACUUM` rebuilds the existing main
    /// file so ciphertext left in its free space by an older logical delete is removed too. The
    /// marker is written only after VACUUM succeeds; interruption retries rather than claiming
    /// the historical residue was cleaned.
    private func migrateDeletionHygieneIfNeeded() throws {
        if let stored = try get(
            namespace: Self.keyCheckNamespace, groupTag: Self.keyCheckTag, ordinal: 1)
        {
            guard stored == Self.deletionHygienePlaintext else {
                throw SealedDatabaseError.corruptRecord
            }
            return
        }

        try checkpointAndTruncateWAL()
        try execute("VACUUM")
        try put(
            namespace: Self.keyCheckNamespace, groupTag: Self.keyCheckTag, ordinal: 1,
            value: Self.deletionHygienePlaintext)
    }

    /// Applies the container rules to the database and to every sibling SQLite maintains.
    ///
    /// The siblings are the trap. `-wal` and `-shm` are created by SQLite, not by us, and a
    /// freshly committed row can live **only** in the `-wal` until a checkpoint — so an audit
    /// or a protection policy that covers `records.sqlite3` alone covers the one file the data
    /// might not be in yet. (R3 in `AUDIT.md` §0 is the same shape: a fence that covers code
    /// and not resources.)
    ///
    /// Recreation is covered by inheritance — a file created inside a directory takes that
    /// directory's protection class, and the root carries it — but inheritance is a mechanism
    /// to rely on knowingly, not to assume, so the attribute is set explicitly here and
    /// asserted in the tests rather than reasoned about.
    private func applyFileProtection() throws {
        for url in Self.fileURLs(root: root) {
            guard fileManager.fileExists(atPath: url.path) else { continue }
            do {
                try fileManager.setAttributes(
                    [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
                    ofItemAtPath: url.path)
            } catch {
                throw SealedDatabaseError.ioFailure("setting the database protection class failed")
            }
            do {
                var resource = URLResourceValues()
                resource.isExcludedFromBackup = true
                var mutable = url
                try mutable.setResourceValues(resource)
            } catch {
                throw SealedDatabaseError.ioFailure("excluding the database from backup failed")
            }
        }
    }

    /// The database and every file SQLite keeps beside it. Used by protection, by destruction,
    /// and by the test that greps the whole store for plaintext.
    internal static func fileURLs(root: URL) -> [URL] {
        [fileName, "\(fileName)-wal", "\(fileName)-shm"].map {
            root.appendingPathComponent($0, isDirectory: false)
        }
    }

    // MARK: - The blind index

    /// The index tag for a caller's group identifier — a peer's ACI, in practice.
    ///
    /// `HMAC-SHA256` under a key derived from the record key, so the tag is unforgeable and
    /// uncorrelatable without that key, and equality lookups still work because the same input
    /// gives the same tag. **Not truncated:** 32 bytes costs 16 more bytes per row than a
    /// halved tag and removes the need for a collision argument, and a collision here would
    /// merge two people's conversations rather than merely degrade a lookup.
    ///
    /// Not a plain hash: a bare `SHA-256(uuid)` is trivially reversed by enumerating candidate
    /// UUIDs held elsewhere — the relay knows the ACIs it routes to — so the key is what makes
    /// this a blind index rather than an obfuscation.
    internal func groupTag(_ group: Data) -> Data {
        CryptoActor.assertIsolated()
        var mac = HMAC<SHA256>(key: indexKey)
        mac.update(data: group)
        return Data(mac.finalize())
    }

    // MARK: - Sealing

    /// AAD binding a value to the exact slot it belongs in.
    ///
    /// Identical in purpose to the file store's: without it, AES-GCM would only promise that
    /// *some* value we once wrote is intact, and a row's blob could be copied to another
    /// ordinal — or another namespace — and be believed there. `group_tag` is fixed length and
    /// the namespace cannot contain `0x00` (it is validated `[a-z0-9-]` at the public
    /// boundary), so the concatenation is unambiguous.
    private func authenticatedData(_ namespace: String, _ tag: Data, _ ordinal: Int) -> Data {
        var aad = Data([Self.valueVersion])
        aad.append(contentsOf: Array(namespace.utf8))
        aad.append(0x00)
        aad.append(tag)
        aad.append(0x00)
        withUnsafeBytes(of: Int64(ordinal).bigEndian) { aad.append(contentsOf: $0) }
        return aad
    }

    private func seal(_ value: Data, _ namespace: String, _ tag: Data, _ ordinal: Int) throws
        -> Data {
        do {
            let box = try AES.GCM.seal(
                value, using: sealingKey,
                authenticating: authenticatedData(namespace, tag, ordinal))
            guard let combined = box.combined else {
                throw SealedDatabaseError.ioFailure("sealed box had no combined representation")
            }
            var out = Data(capacity: combined.count + 1)
            out.append(Self.valueVersion)
            out.append(combined)
            return out
        } catch let error as SealedDatabaseError {
            throw error
        } catch {
            throw SealedDatabaseError.ioFailure("sealing a value failed")
        }
    }

    private func unseal(_ stored: Data, _ namespace: String, _ tag: Data, _ ordinal: Int) throws
        -> Data {
        guard let version = stored.first else { throw SealedDatabaseError.corruptRecord }
        guard version == Self.valueVersion else {
            throw SealedDatabaseError.unsupportedValueVersion(version)
        }
        do {
            let box = try AES.GCM.SealedBox(combined: stored.dropFirst())
            return try AES.GCM.open(
                box, using: sealingKey,
                authenticating: authenticatedData(namespace, tag, ordinal))
        } catch {
            // Tampering, truncation, a row copied between slots, or a key that no longer
            // matches. Never degraded to "not found": treating a damaged row as absent hands
            // anyone with container write access a way to erase state by corrupting it.
            throw SealedDatabaseError.corruptRecord
        }
    }

    // MARK: - Reads and writes

    internal func put(namespace: String, groupTag tag: Data, ordinal: Int, value: Data) throws {
        CryptoActor.assertIsolated()
        try retrySecureCheckpointIfNeeded()
        let replacesExistingValue = try slotExists(
            namespace: namespace, groupTag: tag, ordinal: ordinal)
        let sealed = try seal(value, namespace, tag, ordinal)

        let sql = """
            INSERT INTO sealed_record (namespace, group_tag, ordinal, sealed)
            VALUES (?, ?, ?, ?)
            ON CONFLICT (namespace, group_tag, ordinal) DO UPDATE SET sealed = excluded.sealed
            """
        try withStatement(sql) { statement in
            try bind(statement, 1, text: namespace)
            try bind(statement, 2, blob: tag)
            try bind(statement, 3, int: ordinal)
            try bind(statement, 4, blob: sealed)
            guard sqlite3_step(statement) == SQLITE_DONE else {
                throw SealedDatabaseError.ioFailure("writing a row failed")
            }
        }
        if replacesExistingValue { try noteLogicalDeletion() }
    }

    internal func get(namespace: String, groupTag tag: Data, ordinal: Int) throws -> Data? {
        CryptoActor.assertIsolated()
        try retrySecureCheckpointIfNeeded()

        let sql = """
            SELECT sealed FROM sealed_record
            WHERE namespace = ? AND group_tag = ? AND ordinal = ?
            """
        var out: Data?
        try withStatement(sql) { statement in
            try bind(statement, 1, text: namespace)
            try bind(statement, 2, blob: tag)
            try bind(statement, 3, int: ordinal)
            switch sqlite3_step(statement) {
            case SQLITE_ROW:
                out = try unseal(try readBlob(statement, 0), namespace, tag, ordinal)
            case SQLITE_DONE:
                out = nil
            default:
                throw SealedDatabaseError.ioFailure("reading a row failed")
            }
        }
        return out
    }

    /// Every row in a group, ordered by ordinal.
    ///
    /// This is the whole point of the type: one indexed query where the file store needed one
    /// read per message, from a caller that already had to know every ordinal.
    internal func list(namespace: String, groupTag tag: Data) throws
        -> [(ordinal: Int, value: Data)] {
        CryptoActor.assertIsolated()
        try retrySecureCheckpointIfNeeded()

        let sql = """
            SELECT ordinal, sealed FROM sealed_record
            WHERE namespace = ? AND group_tag = ?
            ORDER BY ordinal ASC
            """
        var out: [(ordinal: Int, value: Data)] = []
        try withStatement(sql) { statement in
            try bind(statement, 1, text: namespace)
            try bind(statement, 2, blob: tag)
            while true {
                switch sqlite3_step(statement) {
                case SQLITE_ROW:
                    let ordinal = Int(sqlite3_column_int64(statement, 0))
                    let sealed = try readBlob(statement, 1)
                    out.append((ordinal, try unseal(sealed, namespace, tag, ordinal)))
                case SQLITE_DONE:
                    return
                default:
                    throw SealedDatabaseError.ioFailure("listing rows failed")
                }
            }
        }
        return out
    }

    /// Every row in a namespace, across all groups.
    ///
    /// This is what lets the archive stop keeping an index of its own conversations. Under the
    /// old layout there was no way to ask "what exists?" — filenames are hashes and the record
    /// store deliberately offers no enumeration — so a separate index record listed every peer
    /// and had to be kept in step with the records it described, by hand, on every create and
    /// every delete. Two things that can disagree, where one would do.
    ///
    /// The group tag comes back with each row because unsealing needs it: the tag is in the
    /// authenticated data. It is still a blind tag, and still names nobody — the caller
    /// recovers identity from *inside* the sealed value, which is the only place it exists.
    internal func listNamespace(_ namespace: String) throws
        -> [(groupTag: Data, ordinal: Int, value: Data)] {
        CryptoActor.assertIsolated()
        try retrySecureCheckpointIfNeeded()

        let sql = """
            SELECT group_tag, ordinal, sealed FROM sealed_record
            WHERE namespace = ?
            ORDER BY group_tag ASC, ordinal ASC
            """
        var out: [(groupTag: Data, ordinal: Int, value: Data)] = []
        try withStatement(sql) { statement in
            try bind(statement, 1, text: namespace)
            while true {
                switch sqlite3_step(statement) {
                case SQLITE_ROW:
                    let tag = try readBlob(statement, 0)
                    let ordinal = Int(sqlite3_column_int64(statement, 1))
                    let sealed = try readBlob(statement, 2)
                    out.append((tag, ordinal, try unseal(sealed, namespace, tag, ordinal)))
                case SQLITE_DONE:
                    return
                default:
                    throw SealedDatabaseError.ioFailure("listing a namespace failed")
                }
            }
        }
        return out
    }

    internal func remove(namespace: String, groupTag tag: Data, ordinal: Int) throws {
        CryptoActor.assertIsolated()
        try retrySecureCheckpointIfNeeded()

        let sql = """
            DELETE FROM sealed_record
            WHERE namespace = ? AND group_tag = ? AND ordinal = ?
            """
        try withStatement(sql) { statement in
            try bind(statement, 1, text: namespace)
            try bind(statement, 2, blob: tag)
            try bind(statement, 3, int: ordinal)
            guard sqlite3_step(statement) == SQLITE_DONE else {
                throw SealedDatabaseError.ioFailure("deleting a row failed")
            }
        }
        try noteLogicalDeletion()
    }

    /// Deletes every row in a group. One statement, where the file store needed a loop over
    /// every ordinal the caller had to know about.
    internal func removeGroup(namespace: String, groupTag tag: Data) throws {
        CryptoActor.assertIsolated()
        try retrySecureCheckpointIfNeeded()

        let sql = "DELETE FROM sealed_record WHERE namespace = ? AND group_tag = ?"
        try withStatement(sql) { statement in
            try bind(statement, 1, text: namespace)
            try bind(statement, 2, blob: tag)
            guard sqlite3_step(statement) == SQLITE_DONE else {
                throw SealedDatabaseError.ioFailure("deleting a group failed")
            }
        }
        try noteLogicalDeletion()
    }

    internal func removeNamespace(_ namespace: String) throws {
        CryptoActor.assertIsolated()
        try retrySecureCheckpointIfNeeded()

        let sql = "DELETE FROM sealed_record WHERE namespace = ?"
        try withStatement(sql) { statement in
            try bind(statement, 1, text: namespace)
            guard sqlite3_step(statement) == SQLITE_DONE else {
                throw SealedDatabaseError.ioFailure("deleting a namespace failed")
            }
        }
        try noteLogicalDeletion()
    }

    // MARK: - Transactions

    /// Runs `body` inside one transaction, rolling back if it throws.
    ///
    /// The archive's append writes a message and advances a counter. As two separate writes
    /// that pair had to be *ordered* so a crash between them was survivable — message first,
    /// counter second, leaving an orphan rather than a counter pointing at nothing. One
    /// transaction removes the window instead of arranging to survive it.
    ///
    /// This does **not** make `SerialGate` redundant, and is not a substitute for it: AUDIT
    /// 4.10 is closed with the gate as its named guard, and the interleaving it prevents is in
    /// the caller's read-modify-write across `await`s, not in this connection. Deliberately not
    /// reentrant — a nested call is a bug in the caller, and SQLite would otherwise fail the
    /// inner `BEGIN`.
    internal func withTransaction<T>(_ body: () throws -> T) throws -> T {
        CryptoActor.assertIsolated()
        guard !transactionIsActive else { throw SealedDatabaseError.nestedTransaction }
        try retrySecureCheckpointIfNeeded()

        try execute("BEGIN IMMEDIATE")
        transactionIsActive = true
        transactionNeedsSecureCheckpoint = false
        afterCommitActions.removeAll(keepingCapacity: true)
        let value: T
        do {
            value = try body()
        } catch {
            try? execute("ROLLBACK")
            afterCommitActions.removeAll(keepingCapacity: true)
            transactionNeedsSecureCheckpoint = false
            transactionIsActive = false
            throw error
        }

        do {
            try execute("COMMIT")
        } catch {
            // A failed COMMIT leaves the transaction active; rollback is still meaningful here.
            try? execute("ROLLBACK")
            afterCommitActions.removeAll(keepingCapacity: true)
            transactionNeedsSecureCheckpoint = false
            transactionIsActive = false
            throw error
        }

        let actions = afterCommitActions
        let needsCheckpoint = transactionNeedsSecureCheckpoint
        afterCommitActions.removeAll(keepingCapacity: true)
        transactionNeedsSecureCheckpoint = false
        transactionIsActive = false

        // These actions remove legacy copies which the committed rows now shadow. They
        // deliberately run after COMMIT: running one before it would make rollback delete
        // the only surviving copy of a protocol record.
        for action in actions { action() }

        if needsCheckpoint {
            do {
                try checkpointAndTruncateWAL()
                secureCheckpointIsPending = false
            } catch {
                // COMMIT already succeeded. Throwing now would lie to every caller about the
                // transaction outcome; for an inbound ratchet, that lie causes replay of an
                // already-consumed message key. Preserve the committed result, and fail closed
                // before the next database operation until this scrub succeeds.
                secureCheckpointIsPending = true
                CipherLog.store.error("secure-delete WAL truncation will be retried")
            }
        }
        return value
    }

    /// Joins an existing transaction or creates one when the caller is otherwise outside one.
    /// A record replacement is two statements (write value, clear tombstone); this keeps that
    /// pair indivisible without nesting when libsignal is already inside an inbound transaction.
    internal func atomically<T>(_ body: () throws -> T) throws -> T {
        CryptoActor.assertIsolated()
        if transactionIsActive { return try body() }
        return try withTransaction(body)
    }

    /// Runs `action` once the surrounding transaction commits, or immediately when no explicit
    /// transaction is active. Used only for cleanup of a legacy copy after its database
    /// replacement is durable; the action must never be required for correctness.
    internal func afterCommit(_ action: @escaping () -> Void) {
        CryptoActor.assertIsolated()
        if transactionIsActive {
            afterCommitActions.append(action)
        } else {
            action()
        }
    }

    // MARK: - Destruction

    /// Closes the connection and deletes the entire crypto container.
    ///
    /// `destroyAllState` has already removed the Keychain service before calling this. Within the
    /// physical-cleanup half, the connection is closed before its files are unlinked.
    internal func destroy() throws {
        CryptoActor.assertIsolated()

        try close()
        try Self.destroyContainer(root: root, fileManager: fileManager)
    }

    /// Removes persisted crypto state without opening it or creating replacement keys.
    /// Used only by the account-cleanup recovery path after the Keychain erase has succeeded.
    internal static func destroyContainer(
        root: URL, fileManager: FileManager = .default
    ) throws {
        guard fileManager.fileExists(atPath: root.path) else { return }
        do {
            try fileManager.removeItem(at: root)
        } catch {
            throw SealedDatabaseError.ioFailure("removing the crypto container failed")
        }
    }

    private func close() throws {
        if let handle {
            guard sqlite3_close(handle) == SQLITE_OK else {
                throw SealedDatabaseError.ioFailure("closing the database failed")
            }
            self.handle = nil
        }
    }

    deinit {
        // No `assertIsolated` here: `deinit` runs on whatever thread releases the last
        // reference, and `sqlite3_close` on an idle connection is thread-safe. Closing is the
        // thing that must not be skipped, because the alternative is a leaked file descriptor
        // for the lifetime of the process.
        if let handle { sqlite3_close(handle) }
    }

    // MARK: - SQLite plumbing

    private func requireHandle() throws -> OpaquePointer {
        guard let handle else { throw SealedDatabaseError.closed }
        return handle
    }

    /// `secure_delete` scrubs the new page image; this copies that image into the main file and
    /// truncates the WAL that may still contain the previous image. Both halves are required.
    private func checkpointAndTruncateWAL() throws {
        guard !transactionIsActive else { throw SealedDatabaseError.nestedTransaction }
        let db = try requireHandle()
        var frames: Int32 = 0
        var checkpointed: Int32 = 0
        guard sqlite3_wal_checkpoint_v2(
            db, nil, SQLITE_CHECKPOINT_TRUNCATE, &frames, &checkpointed) == SQLITE_OK
        else {
            throw SealedDatabaseError.ioFailure("truncating the database WAL failed")
        }
    }

    private func retrySecureCheckpointIfNeeded() throws {
        guard secureCheckpointIsPending, !transactionIsActive else { return }
        try checkpointAndTruncateWAL()
        secureCheckpointIsPending = false
    }

    private func noteLogicalDeletion() throws {
        let db = try requireHandle()
        guard sqlite3_changes(db) > 0 else { return }
        if transactionIsActive {
            transactionNeedsSecureCheckpoint = true
            return
        }
        do {
            try checkpointAndTruncateWAL()
            secureCheckpointIsPending = false
        } catch {
            secureCheckpointIsPending = true
            throw SealedDatabaseError.secureDeletionPending
        }
    }

    /// Reads the effective value from this connection, not the SQL string we attempted to set.
    private func pragmaInteger(_ sql: String) throws -> Int {
        var value: Int?
        try withStatement(sql) { statement in
            guard sqlite3_step(statement) == SQLITE_ROW else {
                throw SealedDatabaseError.ioFailure("reading a database pragma failed")
            }
            value = Int(sqlite3_column_int64(statement, 0))
        }
        guard let value else {
            throw SealedDatabaseError.ioFailure("reading a database pragma failed")
        }
        return value
    }

    /// Checks only the primary key. No value is copied or authenticated, so replacement keeps
    /// the existing overwrite semantics while still learning whether an older sealed value must
    /// be scrubbed from the database/WAL.
    private func slotExists(namespace: String, groupTag tag: Data, ordinal: Int) throws -> Bool {
        let sql = """
            SELECT 1 FROM sealed_record
            WHERE namespace = ? AND group_tag = ? AND ordinal = ?
            """
        var exists = false
        try withStatement(sql) { statement in
            try bind(statement, 1, text: namespace)
            try bind(statement, 2, blob: tag)
            try bind(statement, 3, int: ordinal)
            switch sqlite3_step(statement) {
            case SQLITE_ROW: exists = true
            case SQLITE_DONE: exists = false
            default: throw SealedDatabaseError.ioFailure("checking a row slot failed")
            }
        }
        return exists
    }

    /// Test-visible assertion of the setting on the live connection.
    internal func secureDeletionIsEnabled() throws -> Bool {
        CryptoActor.assertIsolated()
        return try pragmaInteger("PRAGMA secure_delete") == 1
    }

    // MARK: - Storage accounting (AUDIT 4.14)

    /// Bytes this database occupies logically — allocated pages, less the ones on the freelist.
    ///
    /// **`page_count` alone is the wrong measure, and quietly so.** SQLite never returns freed
    /// pages to the filesystem: it moves them to an internal freelist and reuses them. So the
    /// file does not shrink when rows are deleted, and a quota built on `page_count` would latch
    /// on permanently the first time it tripped — every later append would evict, forever, while
    /// the figure it was reacting to never moved. Subtracting the freelist gives a number that
    /// *falls* when rows go away, which is the only kind a quota can use.
    ///
    /// Both pragmas are header reads rather than scans, so this is cheap enough to sit on the
    /// receive path, and both reflect the state of an **open** transaction — which eviction
    /// depends on, because it has to see the space it just freed in order to know when to stop.
    /// That is asserted by `testFreedSpaceIsVisibleToTheQuotaInsideTheSameTransaction` rather
    /// than assumed from the documentation.
    internal func usedBytes() throws -> Int {
        CryptoActor.assertIsolated()
        try retrySecureCheckpointIfNeeded()
        let pages = try pragmaInteger("PRAGMA page_count")
        let free = try pragmaInteger("PRAGMA freelist_count")
        let pageSize = try pragmaInteger("PRAGMA page_size")
        return max(0, pages - free) * pageSize
    }

    /// How many rows a namespace holds. Used to bound the number of conversations; a range scan
    /// over one namespace of the primary key, and only ever called on the small `conv` range.
    internal func rowCount(namespace: String) throws -> Int {
        CryptoActor.assertIsolated()
        try retrySecureCheckpointIfNeeded()

        var count = 0
        try withStatement("SELECT COUNT(*) FROM sealed_record WHERE namespace = ?") { statement in
            try bind(statement, 1, text: namespace)
            guard sqlite3_step(statement) == SQLITE_ROW else {
                throw SealedDatabaseError.ioFailure("counting rows failed")
            }
            count = Int(sqlite3_column_int64(statement, 0))
        }
        return count
    }

    /// Deletes every row in a group below `ordinal`, and reports how many went.
    ///
    /// One statement, so a retention trim is not a loop of deletes the caller has to keep
    /// consistent — and it inherits `noteLogicalDeletion`, so trimmed ciphertext is scrubbed on
    /// the same terms as any other delete rather than being left recoverable in the WAL.
    @discardableResult
    internal func removeRowsBelow(namespace: String, groupTag tag: Data, ordinal: Int) throws
        -> Int {
        CryptoActor.assertIsolated()
        try retrySecureCheckpointIfNeeded()

        let sql = """
            DELETE FROM sealed_record
            WHERE namespace = ? AND group_tag = ? AND ordinal < ?
            """
        try withStatement(sql) { statement in
            try bind(statement, 1, text: namespace)
            try bind(statement, 2, blob: tag)
            try bind(statement, 3, int: ordinal)
            guard sqlite3_step(statement) == SQLITE_DONE else {
                throw SealedDatabaseError.ioFailure("trimming rows failed")
            }
        }
        // Read before `noteLogicalDeletion`, which consults the same counter. No statement runs
        // in between, so this is still the DELETE's count.
        let removed = Int(sqlite3_changes(try requireHandle()))
        try noteLogicalDeletion()
        return removed
    }

    /// Runs a statement that returns no rows.
    ///
    /// `sqlite3_exec` rather than prepare/step: these are fixed, literal statements with no
    /// bound values, so there is nothing for a parameter to protect. Every statement that
    /// touches caller data goes through `withStatement` and binds.
    private func execute(_ sql: String) throws {
        let db = try requireHandle()
        guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else {
            // The SQLite message is deliberately not interpolated: these statements carry no
            // caller data, so it could only add noise, and a habit of pasting driver messages
            // into logs is how record contents eventually reach one.
            throw SealedDatabaseError.ioFailure("a database statement failed")
        }
    }

    private func withStatement(_ sql: String, _ body: (OpaquePointer) throws -> Void) throws {
        let db = try requireHandle()
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK, let statement else {
            if statement != nil { sqlite3_finalize(statement) }
            throw SealedDatabaseError.ioFailure("preparing a statement failed")
        }
        defer { sqlite3_finalize(statement) }
        try body(statement)
    }

    private func bind(_ statement: OpaquePointer, _ index: Int32, text: String) throws {
        // SQLITE_TRANSIENT: SQLite copies the bytes, so the Swift string's storage does not
        // have to outlive the call. The alternative is a dangling pointer that works until it
        // does not.
        guard sqlite3_bind_text(statement, index, text, -1, Self.transient) == SQLITE_OK else {
            throw SealedDatabaseError.ioFailure("binding a text value failed")
        }
    }

    private func bind(_ statement: OpaquePointer, _ index: Int32, blob: Data) throws {
        // An empty blob would give `withUnsafeBytes` a nil base address, and
        // `sqlite3_bind_blob` with a null pointer binds SQL NULL rather than an empty blob — a
        // silent type change. No caller passes an empty tag or an empty sealed value (a seal is
        // never shorter than its nonce and tag), so this guards against a future one rather
        // than a live case.
        guard !blob.isEmpty else {
            throw SealedDatabaseError.ioFailure("refused to bind an empty blob")
        }
        let status = blob.withUnsafeBytes { buffer in
            sqlite3_bind_blob(
                statement, index, buffer.baseAddress, Int32(buffer.count), Self.transient)
        }
        guard status == SQLITE_OK else {
            throw SealedDatabaseError.ioFailure("binding a blob failed")
        }
    }

    private func bind(_ statement: OpaquePointer, _ index: Int32, int value: Int) throws {
        guard sqlite3_bind_int64(statement, index, Int64(value)) == SQLITE_OK else {
            throw SealedDatabaseError.ioFailure("binding an integer failed")
        }
    }

    /// Reads a blob column, refusing an oversized one **before** copying it out.
    private func readBlob(_ statement: OpaquePointer, _ column: Int32) throws -> Data {
        let count = Int(sqlite3_column_bytes(statement, column))
        guard count > 0 else { throw SealedDatabaseError.corruptRecord }
        guard count <= Self.maxSealedBytes else {
            CipherLog.store.error("refused an oversized database row without reading it")
            throw SealedDatabaseError.rowTooLarge(bytes: count)
        }
        guard let pointer = sqlite3_column_blob(statement, column) else {
            throw SealedDatabaseError.corruptRecord
        }
        return Data(bytes: pointer, count: count)
    }

    /// `SQLITE_TRANSIENT` is a cast of -1 to a function pointer, which the C macro does and
    /// Swift cannot import.
    private static let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
}

// MARK: - Key derivation

/// Derives purpose-separated subkeys from the record encryption key.
///
/// A protocol so the master key stays inside `EncryptedFileRecordStore` and gets no second
/// holder: this type receives derived keys and never the key they came from.
internal protocol RecordKeyDeriving: AnyObject {
    func deriveSubkey(info: String) -> SymmetricKey
}

// MARK: - Errors

internal enum SealedDatabaseError: Error, Equatable {
    /// A row failed to decrypt or its authenticated data did not match. Never "not found".
    case corruptRecord
    /// Written by a build with a newer value format. Refused rather than partially believed.
    case unsupportedValueVersion(UInt8)
    /// A row holds more bytes than any value this module writes, so it was refused **without
    /// being read**. Nothing was authenticated; the point is that the allocation never
    /// happened.
    case rowTooLarge(bytes: Int)
    /// The connection is closed — the state was destroyed. Every operation refuses afterwards.
    case closed
    /// A nested transaction is a caller bug. Refused explicitly rather than delegated to an
    /// SQLite error whose behaviour could change with the transaction mode.
    case nestedTransaction
    /// A delete committed, but SQLite could not yet checkpoint and truncate the WAL. The next
    /// operation and the next open both retry before accepting more work.
    case secureDeletionPending
    case ioFailure(String)
}
