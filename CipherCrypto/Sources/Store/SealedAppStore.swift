//
//  SealedAppStore.swift
//  CipherCrypto
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

/// Sealed storage the **app** owns, inside the crypto module's container.
///
/// ## Why the app's message store lives here at all
///
/// `AUDIT.md` 4.3 states the requirement rather than leaving it to be discovered: when message
/// storage arrives it must share the crypto queue and this container. Both halves are load
/// bearing.
///
/// - **This container** means one Keychain item — the record encryption key — is the
///   cryptographic erase for *everything*, protocol state and message bodies together.
///   `destroyAllState` already deletes it. A separate app-side store with its own key would
///   mean "delete everything" deleted half of it and the other half survived as ciphertext
///   whose key was still in the Keychain, which is not the same thing at all.
/// - **The crypto queue** means a message write cannot interleave with a ratchet write. The
///   receive path decrypts (stepping the session) and then persists the plaintext; if those two
///   ran on different queues, the ordering that makes "acknowledge only what is durable" true
///   would be a coincidence.
///
/// Records inherit every property the protocol records have: AES-GCM under the Keychain key,
/// AAD binding the value to its exact slot, `ThisDeviceOnly` key material, excluded from
/// backup, `completeUntilFirstUserAuthentication` file protection, and a size ceiling checked
/// before anything is read into memory.
///
/// ## What this surface deliberately is not
///
/// It is bytes in, bytes out. The crypto module does not learn what a conversation is, and the
/// app does not learn how sealing works. P5.S11 replaced the original file implementation with
/// the database adapter without changing this API, so legacy archive migration can still read
/// the same logical keys while current protocol and archive state share one connection.
///
/// It is also **not a home for key material**. Everything secret this module holds has a typed
/// record kind and a validated codec; a caller reaching for this to stash a key would be
/// choosing an unvalidated blob over one of those. There is no enumeration either: record keys
/// stay inside sealed database values, so the caller keeps its own index, exactly as
/// `reservePreKeyIds` does rather than asking storage what exists.
extension CryptoEngine {

    /// Ceiling on one sealed value.
    ///
    /// Half of `EncryptedFileRecordStore.maxRecordBytes`, so the value plus the AEAD's nonce
    /// and tag cannot approach a limit whose failure mode is a record that writes and then
    /// refuses to load. A message body is bounded far below this by
    /// `MessagePayload.maxEncodedBytes`.
    public static let maxSealedValueBytes = 512 * 1024

    /// Stores `value` under `namespace`/`key`, replacing whatever was there.
    public func storeSealed(namespace: String, key: String, value: Data) throws {
        try requireLive()
        let recordKey = try Self.sealedRecordKey(namespace: namespace, key: key)
        guard value.count <= Self.maxSealedValueBytes else {
            throw SealedStoreError.valueTooLarge(value.count)
        }
        try store.storeAppData(recordKey, value)
    }

    /// Loads a sealed value, or `nil` if the slot is empty.
    ///
    /// A slot that exists but fails to authenticate throws rather than reading as empty — the
    /// same rule as every other record in this container, and for the same reason: silently
    /// treating tampering as absence hands an attacker with container write access a way to
    /// erase state by corrupting it.
    public func loadSealed(namespace: String, key: String) throws -> Data? {
        try requireLive()
        return try store.loadAppData(try Self.sealedRecordKey(namespace: namespace, key: key))
    }

    public func removeSealed(namespace: String, key: String) throws {
        try requireLive()
        try store.removeAppData(try Self.sealedRecordKey(namespace: namespace, key: key))
    }

    /// `namespace/key`, with the namespace constrained so the composition is unambiguous.
    ///
    /// **A namespace containing `/` would be a slot collision, not a cosmetic problem.**
    /// `("chat/1", "x")` and `("chat", "1/x")` would compose to the same record key, hash to
    /// the same filename, *and* produce the same authenticated data — so the AAD binding that
    /// catches a relocated record would agree they belong in the same place. Forbidding the
    /// separator in the left-hand side is what keeps the two apart. The key may contain it
    /// freely, because only one side needs to be unambiguous.
    private static func sealedRecordKey(namespace: String, key: String) throws -> String {
        guard !namespace.isEmpty, namespace.count <= 32,
              namespace.allSatisfy({ $0.isASCII && ($0.isLowercase || $0.isNumber || $0 == "-") })
        else {
            throw SealedStoreError.invalidNamespace
        }
        guard !key.isEmpty, key.count <= 256 else { throw SealedStoreError.invalidKey }
        return "\(namespace)/\(key)"
    }
}

public enum SealedStoreError: Error, Equatable, Sendable {
    /// Empty, over-long, or containing anything but `[a-z0-9-]` — see `sealedRecordKey`.
    case invalidNamespace
    case invalidKey
    case valueTooLarge(Int)
}
