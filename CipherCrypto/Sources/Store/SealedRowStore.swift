//
//  SealedRowStore.swift
//  CipherCrypto
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

/// The app's queryable sealed storage (P5.S11): the public face of `SealedRecordDatabase`.
///
/// ## Why this is a sibling of `SealedAppStore` and not a replacement for it
///
/// `SealedAppStore` is a key-value surface — one sealed blob per key, addressed by a key the
/// caller already holds. This one adds the two questions that cannot be asked of it: *give me
/// everything in this group, in order*, and *delete everything in this group*. That is the
/// whole of AUDIT 4.3's residual, which was query shape rather than confidentiality.
///
/// Both surfaces survive because the older one is what the migration reads: repointing the
/// archive at the database means reading the records written in the old format first, and a
/// migration that could not read the old format would be a deletion.
///
/// ## The boundary this deliberately keeps
///
/// Bytes in, bytes out — and a *group*, which to this module is an opaque string it blinds and
/// never interprets. The crypto module still does not learn what a conversation is
/// (`SealedAppStore.swift` argues why), and the app still does not learn how sealing works.
/// The app passes a peer's ACI as a group; what reaches disk is an HMAC of it under a key
/// derived from the record key, so the container names nobody.
extension CryptoEngine {

    /// Ceiling on one row's value. The same as the key-value surface's, for the same reason:
    /// well below the database's own ceiling, so a value that writes can always be read back.
    public static let maxSealedRowBytes = maxSealedValueBytes

    /// Stores a row, replacing whatever occupied that slot.
    public func storeSealedRow(
        namespace: String, group: String, ordinal: Int, value: Data
    ) throws {
        try requireLive()
        try Self.validate(namespace: namespace, group: group)
        guard value.count <= Self.maxSealedRowBytes else {
            throw SealedStoreError.valueTooLarge(value.count)
        }
        let database = store.appDatabase
        try database.put(
            namespace: namespace, groupTag: database.groupTag(Data(group.utf8)),
            ordinal: ordinal, value: value)
    }

    /// Loads one row, or `nil` if that slot is empty.
    ///
    /// A row that exists but fails to authenticate throws rather than reading as empty — the
    /// same rule as every other record in this container, and for the same reason: treating
    /// tampering as absence hands an attacker with container write access a way to erase state
    /// by corrupting it.
    public func loadSealedRow(namespace: String, group: String, ordinal: Int) throws -> Data? {
        try requireLive()
        try Self.validate(namespace: namespace, group: group)
        let database = store.appDatabase
        return try database.get(
            namespace: namespace, groupTag: database.groupTag(Data(group.utf8)), ordinal: ordinal)
    }

    /// Every row in a group, ordered by ordinal. One query, not one read per row.
    public func listSealedRows(namespace: String, group: String) throws
        -> [(ordinal: Int, value: Data)] {
        try requireLive()
        try Self.validate(namespace: namespace, group: group)
        let database = store.appDatabase
        return try database.list(
            namespace: namespace, groupTag: database.groupTag(Data(group.utf8)))
    }

    /// Every row in a namespace, across every group.
    ///
    /// The group tags are deliberately **not** returned: they are blind, so they would name
    /// nobody to a caller anyway, and a caller that wants identity must read it from inside the
    /// value it just unsealed — which is the only place identity exists.
    public func listSealedNamespace(namespace: String) throws -> [Data] {
        try requireLive()
        // Namespace-only, so the group half of the usual check has nothing to validate. Passed
        // a placeholder rather than skipping the call, so a future rule added to the namespace
        // half cannot be one this path silently misses.
        try Self.validate(namespace: namespace, group: "-")
        return try store.appDatabase.listNamespace(namespace).map(\.value)
    }

    public func removeSealedRow(namespace: String, group: String, ordinal: Int) throws {
        try requireLive()
        try Self.validate(namespace: namespace, group: group)
        let database = store.appDatabase
        try database.remove(
            namespace: namespace, groupTag: database.groupTag(Data(group.utf8)), ordinal: ordinal)
    }

    /// Deletes every row in a group. One statement, where the old layout needed the caller to
    /// know every ordinal and issue one unlink each.
    public func removeSealedGroup(namespace: String, group: String) throws {
        try requireLive()
        try Self.validate(namespace: namespace, group: group)
        let database = store.appDatabase
        try database.removeGroup(
            namespace: namespace, groupTag: database.groupTag(Data(group.utf8)))
    }

    /// Runs a sequence of row operations as one transaction.
    ///
    /// **The closure is `@CryptoActor` and synchronous, and that is the point.** The archive's
    /// append reads a counter, writes a message under it, and writes the counter back. Spread
    /// across three `await`s that sequence is three separate hops onto this actor, and a
    /// transaction spanning them would be a transaction spanning suspensions — which is how
    /// AUDIT 4.10 happened in the first place. Running the whole body in one hop means the
    /// database sees one atomic unit and no other work can interleave inside it.
    ///
    /// It does **not** replace `SerialGate`. The gate serialises the archive's own
    /// read-modify-write against other callers; this makes the write half indivisible. Both,
    /// deliberately: 4.10 is closed with the gate named as its guard.
    public func withSealedTransaction<T: Sendable>(
        _ body: @CryptoActor (SealedRowTransaction) throws -> T
    ) throws -> T {
        try requireLive()
        let database = store.appDatabase
        return try database.withTransaction {
            try body(SealedRowTransaction(database: database))
        }
    }

    fileprivate static func validate(namespace: String, group: String) throws {
        try SealedRowSlot.validate(namespace: namespace, group: group)
    }
}

/// Validation for a row's slot, in one place because there are two ways in.
///
/// Both the engine's methods and `SealedRowTransaction`'s call this. That is the point: the
/// transaction handle was written first without it, which would have left the validated path
/// and the unvalidated path differing only in whether the caller happened to open a
/// transaction — the shape of AUDIT 5.6, where a control was applied to the buttons and not to
/// the mechanism.
internal enum SealedRowSlot {

    /// `[a-z0-9-]`, bounded, non-empty — for both halves.
    ///
    /// The namespace rule is inherited from `SealedAppStore`, where a `/` would have been a
    /// slot collision. Here it earns its place differently: the namespace goes into the AEAD's
    /// authenticated data delimited by a `0x00` byte, so a namespace that could contain one
    /// would make the authenticated data ambiguous between two different slots. The group is
    /// bounded but otherwise unconstrained in content, because it is hashed before it reaches
    /// disk and never becomes part of a path or a delimited field.
    internal static func validate(namespace: String, group: String) throws {
        guard !namespace.isEmpty, namespace.count <= 32,
              namespace.allSatisfy({ $0.isASCII && ($0.isLowercase || $0.isNumber || $0 == "-") })
        else {
            throw SealedStoreError.invalidNamespace
        }
        guard !group.isEmpty, group.count <= 256 else { throw SealedStoreError.invalidKey }
    }
}

/// The row operations available inside `withSealedTransaction`.
///
/// A handle rather than the database itself, so the transaction body can read and write rows
/// and can do nothing else — it cannot begin a nested transaction, close the connection, or
/// destroy the store. `@CryptoActor` and non-`Sendable`: it is created and consumed inside one
/// actor hop and must not outlive it.
@CryptoActor
public struct SealedRowTransaction {

    private let database: SealedRecordDatabase

    internal init(database: SealedRecordDatabase) {
        self.database = database
    }

    public func store(namespace: String, group: String, ordinal: Int, value: Data) throws {
        try SealedRowSlot.validate(namespace: namespace, group: group)
        guard value.count <= CryptoEngine.maxSealedRowBytes else {
            throw SealedStoreError.valueTooLarge(value.count)
        }
        try database.put(
            namespace: namespace, groupTag: database.groupTag(Data(group.utf8)),
            ordinal: ordinal, value: value)
    }

    public func load(namespace: String, group: String, ordinal: Int) throws -> Data? {
        try SealedRowSlot.validate(namespace: namespace, group: group)
        return try database.get(
            namespace: namespace, groupTag: database.groupTag(Data(group.utf8)), ordinal: ordinal)
    }

    public func list(namespace: String, group: String) throws -> [(ordinal: Int, value: Data)] {
        try SealedRowSlot.validate(namespace: namespace, group: group)
        return try database.list(
            namespace: namespace, groupTag: database.groupTag(Data(group.utf8)))
    }

    public func remove(namespace: String, group: String, ordinal: Int) throws {
        try SealedRowSlot.validate(namespace: namespace, group: group)
        try database.remove(
            namespace: namespace, groupTag: database.groupTag(Data(group.utf8)), ordinal: ordinal)
    }

    public func removeGroup(namespace: String, group: String) throws {
        try SealedRowSlot.validate(namespace: namespace, group: group)
        try database.removeGroup(
            namespace: namespace, groupTag: database.groupTag(Data(group.utf8)))
    }
}
