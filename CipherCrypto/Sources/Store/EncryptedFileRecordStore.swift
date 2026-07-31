//
//  EncryptedFileRecordStore.swift
//  CipherCrypto
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import CryptoKit
import Foundation
import Security

/// The legacy protocol-record layout and the sole holder of the Keychain-backed master key.
///
/// Current records live in `DatabaseRecordStore`, which lazily imports these independently
/// sealed files. This type remains the migration reader and key-derivation root; removing it
/// would make existing sessions unreadable after an upgrade.
///
/// ## Why encrypt at all when iOS already protects the file
///
/// Data Protection is applied as well (`.completeUntilFirstUserAuthentication`, matching
/// the Keychain accessibility of the key), but it is not sufficient on its own:
///
/// - It protects the file at rest against an attacker holding the powered-off device. It
///   does nothing once the device has been unlocked once, which is most of its life.
/// - Encrypting under a Keychain key makes deletion of that one Keychain item a
///   **cryptographic erase** of every session, prekey, and trust decision at once. That is
///   the primitive a "delete everything now" control needs, and overwriting files on a
///   flash-translation-layer device is not a substitute for it.
/// - The Keychain item is `ThisDeviceOnly`, so records copied out of the container — by a
///   backup, a container dump, or a file-read exploit — are useless off the device.
///
/// ## Per-record authenticated data
///
/// Each record is sealed with AAD = `version ‖ kind ‖ 0x00 ‖ key`. The AAD is what makes
/// the integrity guarantee positional rather than merely per-file: an attacker with write
/// access to the container cannot take the session file for peer A and drop it into peer
/// B's slot, or move a prekey record to a different id, because the slot identity is
/// authenticated alongside the bytes. Without it, AES-GCM would only promise that *some*
/// record we once wrote is intact.
///
/// ## Filenames
///
/// A record key is derived from `ProtocolAddress.name`, which is a peer-supplied string.
/// It never becomes a path component: the filename is
/// `base64url(SHA-256(kind ‖ 0x00 ‖ key))`, a fixed-length, path-safe, case-distinct
/// token. That removes traversal (`../`), reserved names, length limits, and the
/// case-folding collisions a case-insensitive filesystem would otherwise introduce between
/// two distinct service ids. The true key is still authenticated by the AAD, so even a
/// hash collision could not cause a record to be misread — it would fail to open.
///
/// Not `Sendable` by construction: like the protocol store it backs, it is confined to the
/// crypto queue and every entry point says so.
internal final class EncryptedFileRecordStore: RecordStore, RecordKeyDeriving {

    /// Keychain account holding the 256-bit record encryption key.
    internal static let encryptionKeyAccount = "record-encryption-key"

    /// On-disk envelope version. Bumping this is how key rotation or an algorithm change
    /// would be rolled out; a record written by a newer build is refused, not guessed at.
    private static let recordVersion: UInt8 = 1

    private static let keyByteCount = 32

    /// Ceiling on one record, checked **before** the file is read into memory.
    ///
    /// `Data(contentsOf:)` allocates whatever it finds. The container is not a trusted input:
    /// an attacker who can write into it — a file-write exploit, a restored backup, a
    /// malicious sibling process on a jailbroken device — can leave a multi-gigabyte file in
    /// a record slot. Without this the read would be attempted, and the process would be
    /// killed for memory before the AEAD ever got the chance to reject the contents. That is
    /// a denial of service reachable *without any key*, which is exactly the class of thing
    /// a size check belongs in front of.
    ///
    /// 1 MiB is far above anything legitimate: the largest record this module writes is the
    /// base-key witness at `3 + 512 × 32` bytes ≈ 16 KiB, and a session record with a full
    /// complement of archived states is well under a hundred. It is deliberately not tight —
    /// a cap that trips on a real record would be a self-inflicted outage — it is only tight
    /// enough that the allocation is bounded.
    internal static let maxRecordBytes = 1024 * 1024

    private let root: URL
    private let masterKey: SymmetricKey
    private let fileManager: FileManager

    /// Opens (creating if needed) the record store rooted at `root`.
    ///
    /// The encryption key is fetched from `secrets` or created there atomically, so two
    /// processes racing on first launch converge on one key rather than each minting one
    /// and rendering the other's records unreadable.
    internal init(root: URL, secrets: SecretStorage, fileManager: FileManager = .default) throws {
        CryptoActor.assertIsolated()

        self.root = root
        self.fileManager = fileManager

        var candidate = Data(count: Self.keyByteCount)
        candidate.withUnsafeMutableBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            // The platform CSPRNG. A failure here is not recoverable and must never fall
            // back to a weaker source.
            let status = SecRandomCopyBytes(kSecRandomDefault, buffer.count, base)
            precondition(status == errSecSuccess, "the system CSPRNG failed")
        }

        var stored = try secrets.addOrLoad(candidate, forKey: Self.encryptionKeyAccount)
        // `candidate` lost the race if another writer got there first; either way this copy
        // is done with. Both values are uniquely referenced and unsliced, which is the row
        // of the table in `SecretData` measured to write through to the real buffer.
        candidate.resetBytes(in: candidate.startIndex..<candidate.endIndex)

        guard stored.count == Self.keyByteCount else {
            stored.resetBytes(in: stored.startIndex..<stored.endIndex)
            throw RecordStoreError.malformedEncryptionKey
        }
        // SymmetricKey copies into storage it zeroes on release, so this is the last hop
        // the key makes through a type that does not.
        self.masterKey = SymmetricKey(data: stored)
        stored.resetBytes(in: stored.startIndex..<stored.endIndex)

        try createRootIfNeeded()
    }

    // MARK: - Layout

    private func createRootIfNeeded() throws {
        if !fileManager.fileExists(atPath: root.path) {
            do {
                try fileManager.createDirectory(
                    at: root,
                    withIntermediateDirectories: true,
                    attributes: [
                        .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication
                    ]
                )
            } catch {
                throw RecordStoreError.ioFailure("creating the record root failed")
            }
        }

        // Session state must never travel in a backup. Restoring a snapshot of the ratchet
        // onto another device would desynchronise both sides and resurrect message keys the
        // live device has already stepped past. A silent failure here would put every
        // session in the user's next iCloud backup, so it is loud.
        do {
            var resource = URLResourceValues()
            resource.isExcludedFromBackup = true
            var mutableRoot = root
            try mutableRoot.setResourceValues(resource)
        } catch {
            throw RecordStoreError.ioFailure("excluding the record root from backup failed")
        }
    }

    private func directory(for kind: RecordKind) -> URL {
        root.appendingPathComponent(kind.rawValue, isDirectory: true)
    }

    /// `base64url(SHA-256(kind ‖ 0x00 ‖ key))`. The separator keeps `("a", "bc")` and
    /// `("ab", "c")` from hashing alike.
    private func filename(_ kind: RecordKind, _ recordKey: String) -> String {
        Data(SHA256.hash(data: domainSeparated(kind, recordKey)))
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private func domainSeparated(_ kind: RecordKind, _ recordKey: String) -> Data {
        var out = Data(kind.rawValue.utf8)
        out.append(0x00)
        out.append(contentsOf: Array(recordKey.utf8))
        return out
    }

    private func url(_ kind: RecordKind, _ recordKey: String) -> URL {
        directory(for: kind).appendingPathComponent(filename(kind, recordKey), isDirectory: false)
    }

    /// Whether a legacy slot still exists, without reading or authenticating its contents.
    /// Used only to avoid double-counting a row already migrated into SQLite. A normal load
    /// still authenticates the record before any caller can use it.
    internal func contains(_ kind: RecordKind, _ recordKey: String) -> Bool {
        CryptoActor.assertIsolated()
        return fileManager.fileExists(atPath: url(kind, recordKey).path)
    }

    /// AAD binding a sealed record to the exact slot it belongs in.
    private func authenticatedData(_ kind: RecordKind, _ recordKey: String) -> Data {
        var aad = Data([Self.recordVersion])
        aad.append(domainSeparated(kind, recordKey))
        return aad
    }

    // MARK: - RecordStore

    internal func load(_ kind: RecordKind, _ recordKey: String) throws -> Data? {
        CryptoActor.assertIsolated()

        let path = url(kind, recordKey)
        // Absent is a normal, expected state — no session yet, a prekey already consumed.
        // Present-but-unreadable is not, and is surfaced below rather than folded into it.
        guard fileManager.fileExists(atPath: path.path) else { return nil }

        // Size first, then read. `.fileSizeKey` rather than `attributesOfItem`, which would
        // also hand back creation and modification dates — required-reason APIs this module
        // has no business touching (see docs/PRIVACY_MANIFEST.md).
        let declaredSize: Int
        do {
            declaredSize = try path.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
        } catch {
            throw RecordStoreError.ioFailure("sizing a \(kind.rawValue) record failed")
        }
        guard declaredSize <= Self.maxRecordBytes else {
            // Not `corruptRecord`: nothing was authenticated, so this says only that the slot
            // holds something too large to be one of ours.
            CipherLog.store.error("refused an oversized record without reading it")
            throw RecordStoreError.recordTooLarge(kind: kind, bytes: declaredSize)
        }

        let onDisk: Data
        do {
            onDisk = try Data(contentsOf: path)
        } catch {
            throw RecordStoreError.ioFailure("reading a \(kind.rawValue) record failed")
        }

        // The size could have changed between the two calls. A second check costs nothing and
        // closes the window rather than reasoning about whether it is exploitable.
        guard onDisk.count <= Self.maxRecordBytes else {
            throw RecordStoreError.recordTooLarge(kind: kind, bytes: onDisk.count)
        }

        guard let version = onDisk.first else { throw RecordStoreError.corruptRecord(kind: kind) }
        guard version == Self.recordVersion else {
            throw RecordStoreError.unsupportedRecordVersion(version)
        }

        do {
            let box = try AES.GCM.SealedBox(combined: onDisk.dropFirst())
            return try AES.GCM.open(
                box, using: sealingKey(for: kind),
                authenticating: authenticatedData(kind, recordKey))
        } catch {
            // Tampering, truncation, a record moved between slots, or a key that no longer
            // matches. Never degrade this to "not found": doing so would hand an attacker
            // with write access to the container a free session-reset primitive.
            throw RecordStoreError.corruptRecord(kind: kind)
        }
    }

    internal func store(_ kind: RecordKind, _ recordKey: String, _ value: Data) throws {
        CryptoActor.assertIsolated()

        let combined: Data
        do {
            let sealed = try AES.GCM.seal(
                value, using: sealingKey(for: kind),
                authenticating: authenticatedData(kind, recordKey))
            guard let box = sealed.combined else {
                throw RecordStoreError.ioFailure("sealed box had no combined representation")
            }
            combined = box
        } catch let error as RecordStoreError {
            throw error
        } catch {
            throw RecordStoreError.ioFailure("sealing a \(kind.rawValue) record failed")
        }

        var out = Data(capacity: combined.count + 1)
        out.append(Self.recordVersion)
        out.append(combined)

        let directory = directory(for: kind)
        do {
            if !fileManager.fileExists(atPath: directory.path) {
                try fileManager.createDirectory(
                    at: directory,
                    withIntermediateDirectories: true,
                    attributes: [
                        .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication
                    ]
                )
            }
            // `.atomic` writes a sibling temp file and renames it, so a crash mid-write
            // leaves the previous record intact rather than a half-written one. A torn
            // session record is indistinguishable from tampering on the next read.
            try out.write(
                to: url(kind, recordKey),
                options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        } catch {
            throw RecordStoreError.ioFailure("writing a \(kind.rawValue) record failed")
        }
    }

    internal func remove(_ kind: RecordKind, _ recordKey: String) throws {
        CryptoActor.assertIsolated()

        let path = url(kind, recordKey)
        guard fileManager.fileExists(atPath: path.path) else { return }
        do {
            try fileManager.removeItem(at: path)
        } catch {
            throw RecordStoreError.ioFailure("removing a \(kind.rawValue) record failed")
        }
    }

    internal func count(_ kind: RecordKind) throws -> Int {
        CryptoActor.assertIsolated()

        let directory = directory(for: kind)
        guard fileManager.fileExists(atPath: directory.path) else { return 0 }
        do {
            return try fileManager.contentsOfDirectory(atPath: directory.path).count
        } catch {
            throw RecordStoreError.ioFailure("listing \(kind.rawValue) records failed")
        }
    }

    internal func removeAll() throws {
        CryptoActor.assertIsolated()

        // Remove only this store's kind directories. The root is shared with the sealed SQLite
        // database; unlinking it would invalidate that database's live WAL/SHM descriptors.
        for kind in RecordKind.allCases {
            let path = directory(for: kind)
            guard fileManager.fileExists(atPath: path.path) else { continue }
            do {
                try fileManager.removeItem(at: path)
            } catch {
                throw RecordStoreError.ioFailure("removing \(kind.rawValue) records failed")
            }
        }
        try createRootIfNeeded()
    }

    // MARK: - Keys

    /// One key for all kinds today. The indirection exists so per-kind separation can be
    /// introduced without touching a call site, and so this file has exactly one place
    /// where "which key seals this?" is answered.
    private func sealingKey(for _: RecordKind) -> SymmetricKey { masterKey }

    /// A purpose-separated subkey for another store in this container.
    ///
    /// `SealedRecordDatabase` needs to seal values and to compute blind-index tags, and it
    /// must do both under key material that dies with **this** Keychain item — otherwise
    /// `destroyAllState` stops being a cryptographic erase of everything and becomes one of
    /// half of it. Handing out derived keys rather than `masterKey` keeps that item's only
    /// in-memory holder in this file: a subkey cannot be used to open a record file, and
    /// cannot be walked back to the key that would.
    ///
    /// HKDF-SHA256, no salt. A salt earns its place when the input key material is
    /// low-entropy or reused across contexts; here it is a uniformly random 256-bit CSPRNG
    /// key, so the `info` string is doing the only work that needs doing — separating one
    /// purpose from another — and a stored salt would add a moving part rather than an
    /// unpredictable one.
    internal func deriveSubkey(info: String) -> SymmetricKey {
        CryptoActor.assertIsolated()
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: masterKey,
            info: Data(info.utf8),
            outputByteCount: Self.keyByteCount)
    }
}
