//
//  SessionCredential.swift
//  Cipher
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import Security

/// Proof that this installation has an authenticated session.
///
/// ## Presence *is* the authentication state
///
/// There is no `isAuthenticated` boolean anywhere. Being signed in means "a credential is in
/// the Keychain"; being signed out means it is not. That is the whole point of this type:
/// the previous design kept `isAuthenticated` in `UserDefaults`, which is a plist in the
/// app container that any jailbroken device — or anyone with a file-write primitive — can
/// edit. Flipping one boolean there used to grant a signed-in app. It cannot now, because
/// nothing reads a boolean; `SessionStore.current` reads the Keychain, and the Keychain is
/// not a file the app's own sandbox lets you rewrite.
///
/// ## There is no way to mint a production credential yet, deliberately
///
/// A real credential is issued by the relay when an invite code is redeemed, which lands in
/// P5.S09. Until then `.serverIssued` is unreachable and a Release build genuinely cannot
/// authenticate. That is the honest state of an app with no server (AUDIT 5.1) — the
/// alternative is a locally minted token that looks like authentication and proves nothing,
/// which the plan forbids in as many words.
struct SessionCredential: Equatable, Sendable {

    /// Where the credential came from. Stored, not inferred, so `origin` survives a relaunch
    /// and a development credential can never be mistaken for a real one after the fact.
    enum Origin: UInt8, Sendable {
        /// Redeemed against the relay. The only value a Release build can ever hold.
        case serverIssued = 1
        /// Minted locally in a DEBUG build so the UI is reachable before a server exists.
        /// `SessionStore` refuses to store or return one outside DEBUG.
        case development = 2
    }

    /// Opaque bytes. Treated as a bearer secret even though nothing verifies it yet.
    let token: Data
    let issuedAt: Date
    let origin: Origin
}

// MARK: - Storage

/// The Keychain item behind `SessionCredential`.
///
/// ## Why this does not reuse `CipherCrypto`'s Keychain wrapper
///
/// That one is `internal` to the crypto module, and it should stay that way — but the real
/// reason is that the two items want **different accessibility**, and a shared code path
/// would have to encode one of them:
///
/// - The crypto module's identity key is `AfterFirstUnlock` because a notification-service
///   extension has to decrypt while the device is locked (AUDIT 2.1). That is a documented,
///   argued weakening.
/// - This credential is `WhenUnlockedThisDeviceOnly`, the strictest option, because nothing
///   needs it while the device is locked. Inheriting the weaker class here would have
///   widened the window for no benefit at all.
///
/// `ThisDeviceOnly` and `kSecAttrSynchronizable = false` are non-negotiable for the same
/// reason they are on the identity key: a session credential that restores onto another
/// device is a session someone else can resume.
struct SessionStore {

    /// Distinct from the crypto module's service string, so `removeAll` on either is exact
    /// and neither can delete the other's items by accident.
    static let service = "cz.janrichtermoc.Cipher.session"
    private static let account = "session-credential"

    /// ```text
    ///  offset  size  field
    ///       0     1  version    always 0x01
    ///       1     1  origin     1 = server-issued, 2 = development
    ///       2     8  issuedAt   UInt64, milliseconds since the Unix epoch, big-endian
    ///      10     N  token
    /// ```
    private static let version: UInt8 = 1
    private static let headerSize = 10

    private let service: String

    init(service: String = SessionStore.service) {
        self.service = service
    }

    // MARK: Queries

    private func baseQuery() -> [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: Self.account,
            kSecAttrSynchronizable: false,
            kSecUseDataProtectionKeychain: true,
        ]
    }

    // MARK: Reading

    /// The stored credential, or `nil` when signed out.
    ///
    /// Returns `nil` rather than throwing on a malformed or unreadable item. Signed-out is
    /// the safe interpretation of "cannot establish that a session exists", and it is the
    /// one state the app can always recover from — the user signs in again. Throwing would
    /// leave the UI with no defined destination.
    func current() -> SessionCredential? {
        var query = baseQuery()
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne

        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
            let stored = result as? Data,
            let credential = Self.decode(stored)
        else { return nil }

        #if !DEBUG
            // A development credential must never authenticate a shipping build, even if one
            // somehow reached the Keychain — a device that ran a DEBUG build and then a
            // Release one over the top is the realistic path.
            guard credential.origin != .development else { return nil }
        #endif

        return credential
    }

    // MARK: Writing

    /// Stores `credential`, replacing any existing one.
    ///
    /// Delete-then-add rather than `SecItemUpdate`: the accessibility attribute is set on
    /// add, and an update to an item created under a different class would silently keep the
    /// old one.
    func store(_ credential: SessionCredential) throws {
        #if !DEBUG
            guard credential.origin != .development else {
                throw SessionStoreError.developmentCredentialInReleaseBuild
            }
        #endif

        try clear()

        var query = baseQuery()
        query[kSecValueData] = Self.encode(credential)
        query[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw SessionStoreError.keychainFailure(operation: "store", status: status)
        }
    }

    /// Signs out. Succeeds whether or not anything was stored.
    func clear() throws {
        let status = SecItemDelete(baseQuery() as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SessionStoreError.keychainFailure(operation: "clear", status: status)
        }
    }

    // MARK: Coding

    private static func encode(_ credential: SessionCredential) -> Data {
        var out = Data(capacity: headerSize + credential.token.count)
        out.append(version)
        out.append(credential.origin.rawValue)
        let millis = UInt64(credential.issuedAt.timeIntervalSince1970 * 1000)
        withUnsafeBytes(of: millis.bigEndian) { out.append(contentsOf: $0) }
        out.append(credential.token)
        return out
    }

    /// Strict: an unknown version or origin is refused rather than guessed at, for the same
    /// reason `PeerIdentityRecord` refuses unknown flag bits — a value this build cannot
    /// fully understand must never be partially believed, least of all one that decides
    /// whether someone is signed in.
    private static func decode(_ bytes: Data) -> SessionCredential? {
        guard bytes.count > headerSize else { return nil }
        let base = bytes.startIndex

        guard bytes[base] == version,
            let origin = SessionCredential.Origin(rawValue: bytes[base + 1])
        else { return nil }

        var millis: UInt64 = 0
        for offset in 0..<8 { millis = (millis << 8) | UInt64(bytes[base + 2 + offset]) }

        return SessionCredential(
            token: Data(bytes[(base + headerSize)...]),
            issuedAt: Date(timeIntervalSince1970: TimeInterval(millis) / 1000),
            origin: origin)
    }
}

enum SessionStoreError: Error, Equatable {
    case keychainFailure(operation: String, status: OSStatus)
    /// A development credential was offered to a Release build. Refused rather than stored:
    /// the point of the origin field is that it cannot be laundered.
    case developmentCredentialInReleaseBuild
}

#if DEBUG
    extension SessionCredential {
        /// A credential for working on the UI before the relay exists.
        ///
        /// DEBUG-only, and marked `.development` in the stored bytes so a Release build
        /// rejects it on read even if the Keychain item survives an install over the top.
        /// This is not a fake token standing in for a real one — it is a distinct kind that
        /// production refuses.
        static func development() -> SessionCredential {
            var token = Data(count: 32)
            token.withUnsafeMutableBytes { buffer in
                guard let base = buffer.baseAddress else { return }
                _ = SecRandomCopyBytes(kSecRandomDefault, buffer.count, base)
            }
            return SessionCredential(token: token, issuedAt: Date(), origin: .development)
        }
    }
#endif
