//
//  AccountKey.swift
//  Cipher
//
//  The device's re-authentication key (AUDIT 5.41).
//

import CryptoKit
import Foundation
import Security

/// An Ed25519 key pair the device holds for the life of the account, used only to prove
/// possession when the relay will not renew a session token.
///
/// # Why this exists at all
///
/// The session token used to be the *only* credential path: rotation needs the old token,
/// and redeeming an invite mints a **new** account. So an account whose token hash was gone
/// could not authenticate again by any route, and "revoke all sessions" was indistinguishable
/// from disbanding the circle — AUDIT 5.41.
///
/// # Why not the libsignal identity key, which the relay already stores
///
/// That would add no key and no column. It is not buildable: a libsignal identity key is
/// Curve25519 and its signatures are XEd25519, so verifying one in Go needs field arithmetic
/// the standard library does not expose — hand-rolling it is forbidden by the plan's §0.6, and
/// importing a curve library would make it the relay's first cryptographic dependency. The
/// same wall P7.S01 hit with the server-issued sender certificate. Ed25519 is in CryptoKit
/// here and in `crypto/ed25519` there, so neither side gains a dependency.
///
/// # What it is not
///
/// Not an identity, not a second identity key, and **not a recovery mechanism**. It lives only
/// on this device and is never backed up or synced, so losing the device still loses the
/// account — the property `BACKEND.md` §6 states and the UI relies on. It only removes the
/// case where the *relay* ends a session and the device cannot come back.
nonisolated struct AccountKey: Sendable {

    /// Its own Keychain service, so `removeAll` on the session or crypto services cannot take
    /// it by accident and vice versa — the same separation `SessionStore` already keeps.
    static let service = "cz.janrichtermoc.Cipher.accountkey"
    private static let account = "account-key"

    private let service: String

    init(service: String = AccountKey.service) {
        self.service = service
    }

    private func baseQuery() -> [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: Self.account,
            // Never iCloud Keychain. A re-authentication key that syncs is a
            // re-authentication key on a device the user did not enrol.
            kSecAttrSynchronizable: false,
            kSecUseDataProtectionKeychain: true,
        ]
    }

    /// Loads the private key, or nil when none has been created.
    func current() -> Curve25519.Signing.PrivateKey? {
        var query = baseQuery()
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne

        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data,
              let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: data)
        else { return nil }
        return key
    }

    /// Creates and stores a key if there is none, and returns the key in use either way.
    ///
    /// Idempotent on purpose: the publish path runs on every launch that finds no key on the
    /// relay, and it must never mint a second one — the relay refuses to replace a published
    /// key, so a device that rotated locally would lock itself out of re-authentication.
    @discardableResult
    func ensure() throws -> Curve25519.Signing.PrivateKey {
        if let existing = current() { return existing }

        let key = Curve25519.Signing.PrivateKey()
        var attributes = baseQuery()
        attributes[kSecValueData] = key.rawRepresentation
        // `WhenUnlockedThisDeviceOnly`, matching the session credential rather than the
        // crypto records: re-authentication is something the user is present for, so it never
        // needs to be readable while the device is locked, and the stricter class is free.
        attributes[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly

        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw AccountKeyError.keychain(status)
        }
        return key
    }

    /// Removes the key. Called only from account erasure, alongside every other secret.
    func clear() throws {
        let status = SecItemDelete(baseQuery() as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw AccountKeyError.keychain(status)
        }
    }

    /// The public half, base64 for the wire.
    static func publicKeyBase64(_ key: Curve25519.Signing.PrivateKey) -> String {
        key.publicKey.rawRepresentation.base64EncodedString()
    }

    /// Signs a challenge for `aci`.
    ///
    /// The payload is built here and on the relay from the same three parts, in the same
    /// order: a context string, the account, and the challenge. The context is domain
    /// separation — without it, any other place that ever asks this device to sign a
    /// server-chosen blob becomes a signing oracle for re-authentication. The version suffix
    /// lets the payload change later without a signature minted for the old shape being valid
    /// for the new one. **Both sides must change together.**
    static let signatureContext = "cipher-reauth-v1"

    static func signingPayload(aci: UUID, challenge: String) -> Data {
        Data("\(signatureContext):\(aci.uuidString.lowercased()):\(challenge)".utf8)
    }

    func sign(aci: UUID, challenge: String) throws -> String {
        let key = try ensure()
        let signature = try key.signature(for: Self.signingPayload(aci: aci, challenge: challenge))
        return signature.base64EncodedString()
    }
}

enum AccountKeyError: Error, Equatable {
    case keychain(OSStatus)
}
