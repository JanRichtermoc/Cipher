//
//  AttachmentStore.swift
//  CipherCrypto
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

/// The local cache of attachment ciphertext (P6.S04).
///
/// ## Why files, and why in this module
///
/// A sealed row is capped at `CryptoEngine.maxSealedRowBytes` — half a megabyte — because the
/// database reads a value whole. An attachment is megabytes, so it is a file. What it is *not*
/// is a file somewhere else: this directory lives **inside the crypto container**, so
/// `destroyAllState` removes it along with everything else. A cache beside the container would
/// be a second thing every erase path had to remember, and the first one that forgot would
/// leave attachment ciphertext on a device whose account had been destroyed.
///
/// ## What is on disk, and what opens it
///
/// The bytes here are exactly what was uploaded: AES-GCM ciphertext under a per-attachment key
/// that is **not in this directory**. The key lives in the sealed message row that points at
/// the blob, under the one Keychain item whose deletion is a cryptographic erase of everything
/// (`SealedAppStore`). So deleting the message is already an erase of the attachment; unlinking
/// the file is the second half, and the two are ordered so that the *key* goes first.
///
/// That ordering is why an interrupted wipe is survivable rather than a leak: a file left
/// behind after its row is gone is ciphertext no key on the device can open, and
/// ``removeAttachments(except:)`` finds it on the next sweep.
///
/// ## No enumeration of anything but ids
///
/// A file name is a blob id — a value the relay already knows, since it minted it. Nothing
/// about the conversation, the peer, or the content is derivable from this directory, which is
/// why the names are not blinded the way sealed-row groups are.
extension CryptoEngine {

    /// Ceiling on one cached blob. Derived from what the cipher will ever produce, so a
    /// widened attachment limit widens this with it rather than silently refusing legal blobs.
    nonisolated public static var maxAttachmentCiphertextBytes: Int {
        AttachmentCipher.ciphertextSize(forPlaintext: AttachmentCipher.maxPlaintextBytes)
    }

    /// Writes `ciphertext` under `id`, replacing whatever was there.
    public func storeAttachment(id: UUID, ciphertext: Data) throws {
        try requireLive()
        guard !ciphertext.isEmpty,
              ciphertext.count <= Self.maxAttachmentCiphertextBytes
        else {
            throw AttachmentStoreError.valueTooLarge(ciphertext.count)
        }

        let directory = try attachmentDirectory()
        do {
            try ciphertext.write(
                to: Self.attachmentURL(id: id, in: directory),
                options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        } catch {
            // The id is the capability to fetch and delete this blob (`BACKEND.md` §2.8) and
            // a file error names its path, so the path never reaches the message — the same
            // rule the relay's own blob package follows for the same reason.
            throw AttachmentStoreError.ioFailure("writing an attachment failed")
        }
    }

    /// The cached ciphertext for `id`, or nil if this device does not hold it.
    ///
    /// A file larger than the ceiling is refused rather than read: the size is checked from
    /// the bytes actually read, because a length taken from the filesystem and then trusted is
    /// a bound on a different number than the one that reaches memory.
    public func attachmentCiphertext(id: UUID) throws -> Data? {
        try requireLive()
        let url = try Self.attachmentURL(id: id, in: attachmentDirectory())
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }

        let data: Data
        do {
            data = try Data(contentsOf: url, options: [.mappedIfSafe])
        } catch {
            throw AttachmentStoreError.ioFailure("reading an attachment failed")
        }
        guard data.count <= Self.maxAttachmentCiphertextBytes else {
            throw AttachmentStoreError.valueTooLarge(data.count)
        }
        return data
    }

    /// Unlinks one cached blob. Absent is success: a wipe that has already happened must not
    /// look like a failure to the path retrying it.
    public func removeAttachment(id: UUID) throws {
        try requireLive()
        let url = try Self.attachmentURL(id: id, in: attachmentDirectory())
        do {
            try FileManager.default.removeItem(at: url)
        } catch CocoaError.fileNoSuchFile {
            return
        } catch {
            guard !FileManager.default.fileExists(atPath: url.path) else {
                throw AttachmentStoreError.ioFailure("removing an attachment failed")
            }
        }
    }

    /// Every blob id this device has cached.
    public func cachedAttachmentIds() throws -> Set<UUID> {
        try requireLive()
        return try Self.ids(in: try attachmentDirectory())
    }

    /// Unlinks every cached blob whose id is not in `keep`, and reports what went.
    ///
    /// **This is the wipe that covers every deletion path rather than one of them.** Messages
    /// leave the archive through six routes — an expiry sweep, an explicit delete, a cleared
    /// chat, a deleted conversation, a per-conversation trim and a quota eviction — and four of
    /// those remove rows in bulk without decoding them, so none of them can name the blob ids
    /// they just orphaned. Deriving the live set from the rows that remain and removing the
    /// difference is one mechanism that cannot be forgotten by a seventh route, and it also
    /// finishes an unlink that a previous run was interrupted during.
    ///
    /// - Parameter keep: the blob ids still referenced by a stored message. An empty set is a
    ///   legitimate instruction to remove everything — the caller derives it from the archive,
    ///   so "nothing is referenced" is a real state and not a missing argument.
    @discardableResult
    public func removeAttachments(except keep: Set<UUID>) throws -> [UUID] {
        try requireLive()
        let directory = try attachmentDirectory()
        var removed: [UUID] = []
        for id in try Self.ids(in: directory) where !keep.contains(id) {
            try removeAttachment(id: id)
            removed.append(id)
        }
        return removed
    }

    // MARK: - Layout

    private static let attachmentDirectoryName = "attachments"

    private func attachmentDirectory() throws -> URL {
        let directory = root.appendingPathComponent(
            Self.attachmentDirectoryName, isDirectory: true)
        if !FileManager.default.fileExists(atPath: directory.path) {
            do {
                try FileManager.default.createDirectory(
                    at: directory, withIntermediateDirectories: true,
                    attributes: [
                        .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication
                    ])
            } catch {
                throw AttachmentStoreError.ioFailure("creating the attachment cache failed")
            }
        }
        // The container root is already excluded from backup by the record store, and on iOS
        // that exclusion covers everything beneath it. Not re-applied here, so there is one
        // place that decides it rather than two that can disagree.
        return directory
    }

    /// Lowercased UUID, no extension. A blob is not a document and has no type: giving it one
    /// would be a claim about bytes that are ciphertext.
    private static func attachmentURL(id: UUID, in directory: URL) -> URL {
        directory.appendingPathComponent(id.uuidString.lowercased(), isDirectory: false)
    }

    /// The ids in the cache directory. Anything whose name is not a UUID is ignored rather
    /// than removed: this module did not put it there, and a sweep that deletes what it does
    /// not recognise is one bad path away from deleting the database.
    private static func ids(in directory: URL) throws -> Set<UUID> {
        let names: [String]
        do {
            names = try FileManager.default.contentsOfDirectory(atPath: directory.path)
        } catch {
            throw AttachmentStoreError.ioFailure("listing the attachment cache failed")
        }
        return Set(names.compactMap(UUID.init(uuidString:)))
    }
}

public enum AttachmentStoreError: Error, Equatable, Sendable {
    /// Empty, or larger than any attachment this build can produce or accept.
    case valueTooLarge(Int)
    /// A filesystem operation failed. The message never names the path, because the file name
    /// is the blob id and the blob id is the capability.
    case ioFailure(String)
}
