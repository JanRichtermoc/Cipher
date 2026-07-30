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
/// There is deliberately **no key enumeration**. Filenames are hashes, so a key cannot be
/// recovered from disk, and nothing in the design needs to: prekey ids come from a
/// monotonic counter in `.metadata` rather than from "what ids exist", which is the safer
/// arrangement anyway because it can never reuse an id that was just consumed.
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

// MARK: - Errors

internal enum RecordStoreError: Error, Equatable {
    /// A record failed to decrypt or its authenticated data did not match.
    ///
    /// This is never a normal state. It means the file was truncated, corrupted, moved
    /// between slots, or written by a different installation's key. It is surfaced rather
    /// than swallowed: silently treating a damaged session record as "no session" would
    /// hand an attacker with write access to the container a free session-reset primitive.
    case corruptRecord(kind: RecordKind)
    /// The on-disk envelope version is not one this build understands.
    case unsupportedRecordVersion(UInt8)
    /// The record encryption key in the Keychain is not the expected size.
    case malformedEncryptionKey
    /// A slot holds a file larger than any record this module writes, so it was refused
    /// **without being read**. Distinct from `corruptRecord`: nothing was authenticated here,
    /// and the point is that the allocation never happened.
    case recordTooLarge(kind: RecordKind, bytes: Int)
    case ioFailure(String)
}
