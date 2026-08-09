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
/// ## The stored phase and expiry are the authentication state
///
/// There is no persisted `isAuthenticated` boolean anywhere. Being signed in means an active,
/// unexpired, structurally valid credential is in the Keychain. That is the point of this type:
/// the previous design kept `isAuthenticated` in `UserDefaults`, which is a plist in the
/// app container that any jailbroken device — or anyone with a file-write primitive — can
/// edit. Flipping one boolean there used to grant a signed-in app. It cannot now, because
/// nothing reads a boolean; `SessionStore.current` reads the Keychain, and the Keychain is
/// not a file the app's own sandbox lets you rewrite.
///
/// ## Production credentials only come from the relay
///
/// Invite redemption is the only production constructor path. A Release build never mints a
/// `.serverIssued` credential locally; the DEBUG-only development origin remains separately
/// encoded and is refused by Release.
///
/// ## Deliberately outside the main actor
///
/// The project compiles with `MainActor` as its default isolation, which is right for view
/// state and wrong for this: the messaging actor reads the bearer token on every relay call,
/// and routing those reads through the main actor would put Keychain I/O on the thread that
/// draws the UI. This type holds immutable bytes, `SessionStore` holds a service name, and the
/// only shared mutable state involved is the Keychain itself — which `SecItem` serialises. So
/// both are `nonisolated`, and the isolation argument is that there is nothing to isolate.
nonisolated struct SessionCredential: Equatable, Sendable {

    /// Where the credential came from. Stored, not inferred, so `origin` survives a relaunch
    /// and a development credential can never be mistaken for a real one after the fact.
    enum Origin: UInt8, Sendable {
        /// Redeemed against the relay. The only value a Release build can ever hold.
        case serverIssued = 1
        /// Minted locally in a DEBUG build so the UI is reachable before a server exists.
        /// `SessionStore` refuses to store or return one outside DEBUG.
        case development = 2
    }

    /// Registration and destruction are persisted states, not transient UI
    /// booleans. A crash therefore resumes behind the same gate instead of
    /// exposing history from an account whose setup or erasure was incomplete.
    enum Phase: UInt8, Sendable {
        case registering = 1
        case profileSetup = 2
        case active = 3
        case destroying = 4
    }

    /// Opaque bearer bytes. Server-issued values are 32 random bytes encoded as
    /// 43 unpadded base64url characters.
    let token: Data
    /// The account this token authenticates. It is also the only local address
    /// the credential may be used with.
    let aci: UUID
    let issuedAt: Date
    let expiresAt: Date
    let origin: Origin
    let phase: Phase

    static let maximumLifetime: TimeInterval = 31 * 24 * 60 * 60
    private static let zeroACI = UUID(
        uuidString: "00000000-0000-0000-0000-000000000000")!

    func replacing(phase: Phase) -> SessionCredential {
        SessionCredential(token: token, aci: aci, issuedAt: issuedAt,
                          expiresAt: expiresAt, origin: origin, phase: phase)
    }

    func isExpired(at date: Date) -> Bool { expiresAt <= date }

    var bearerToken: String? {
        guard origin == .serverIssued,
              let raw = String(data: token, encoding: .utf8),
              Self.isValidServerToken(raw) else { return nil }
        return raw
    }

    var isStructurallyValid: Bool {
        guard aci != Self.zeroACI,
              issuedAt.timeIntervalSince1970.isFinite,
              expiresAt.timeIntervalSince1970.isFinite,
              issuedAt.timeIntervalSince1970 >= 0,
              expiresAt > issuedAt,
              expiresAt.timeIntervalSince(issuedAt) <= Self.maximumLifetime
        else { return false }

        switch origin {
        case .serverIssued:
            return bearerToken != nil
        case .development:
            return token.count == 32
        }
    }

    static func isValidServerToken(_ raw: String) -> Bool {
        guard raw.utf8.count == 43,
              raw.utf8.allSatisfy({
                  (48...57).contains(Int($0)) || (65...90).contains(Int($0)) ||
                      (97...122).contains(Int($0)) || $0 == 45 || $0 == 95
              })
        else { return false }

        let base64 = raw.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/") + "="
        guard let decoded = Data(base64Encoded: base64), decoded.count == 32 else { return false }
        let canonical = decoded.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return canonical == raw
    }
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
/// - The crypto module's identity key is `AfterFirstUnlock` because **wake-only push** has to
///   decrypt while the device is locked — a silent push wakes the app, which fetches,
///   decrypts and posts a local notification, in its own process (AUDIT 2.1). That is a
///   documented, argued weakening. *Corrected 2026-08-09: this named a notification-service
///   extension, and P8.S04 decided there will not be one (AUDIT 4.4).*
/// - This credential is `WhenUnlockedThisDeviceOnly`, the strictest option, because nothing
///   needs it while the device is locked. Inheriting the weaker class here would have
///   widened the window for no benefit at all.
///
/// `ThisDeviceOnly` and `kSecAttrSynchronizable = false` are non-negotiable for the same
/// reason they are on the identity key: a session credential that restores onto another
/// device is a session someone else can resume.
nonisolated struct SessionStore: Sendable {

    /// Distinct from the crypto module's service string, so `removeAll` on either is exact
    /// and neither can delete the other's items by accident.
    static let service = "cz.janrichtermoc.Cipher.session"
    private static let account = "session-credential"

    /// ```text
    ///  offset  size  field
    ///       0     1  version    always 0x02
    ///       1     1  origin     1 = server-issued, 2 = development
    ///       2     1  phase      registering/profile/active/destroying
    ///       3     8  issuedAt   UInt64 milliseconds, big-endian
    ///      11     8  expiresAt  UInt64 milliseconds, big-endian
    ///      19    16  aci        UUID bytes
    ///      35     N  token
    /// ```
    private static let version: UInt8 = 2
    private static let headerSize = 35

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

    /// The stored credential, or `nil` when absent or not safely decodable.
    ///
    /// AppSession separately checks whether the slot exists: an unreadable value enters the
    /// cleanup gate rather than exposing a new invite to prior-account state. The visible
    /// cleanup screen re-reads once before erasure because a prewarmed process may have queried
    /// a valid `WhenUnlocked` value before first unlock.
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

    /// Whether the Keychain slot exists even if this build refuses its bytes.
    /// Used only to force account cleanup before another invite can be redeemed;
    /// treating an old/future credential as simply absent could mix a new account
    /// with protocol state and history belonging to the prior one.
    func hasStoredItem() -> Bool {
        // Only the definitive "not found" result opens registration. A locked
        // or otherwise unavailable Keychain must fail closed; the cleanup view
        // re-reads the protected value once the app is visible before erasing.
        SecItemCopyMatching(baseQuery() as CFDictionary, nil) != errSecItemNotFound
    }

    // MARK: Writing

    /// Stores `credential`, replacing any existing one.
    ///
    /// Uses an atomic update when the item exists, avoiding a delete/add gap in
    /// which a crash could turn token rotation into sign-out.
    func store(_ credential: SessionCredential) throws {
        #if !DEBUG
            guard credential.origin != .development else {
                throw SessionStoreError.developmentCredentialInReleaseBuild
            }
        #endif

        guard credential.isStructurallyValid else {
            throw SessionStoreError.malformedCredential
        }

        let values: [CFString: Any] = [
            kSecValueData: Self.encode(credential),
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let update = SecItemUpdate(baseQuery() as CFDictionary, values as CFDictionary)
        if update == errSecSuccess { return }
        guard update == errSecItemNotFound else {
            throw SessionStoreError.keychainFailure(operation: "update", status: update)
        }

        var query = baseQuery()
        values.forEach { query[$0.key] = $0.value }
        let add = SecItemAdd(query as CFDictionary, nil)
        guard add == errSecSuccess else {
            throw SessionStoreError.keychainFailure(operation: "store", status: add)
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
        out.append(credential.phase.rawValue)
        for date in [credential.issuedAt, credential.expiresAt] {
            let millis = UInt64(date.timeIntervalSince1970 * 1000)
            withUnsafeBytes(of: millis.bigEndian) { out.append(contentsOf: $0) }
        }
        var uuid = credential.aci.uuid
        withUnsafeBytes(of: &uuid) { out.append(contentsOf: $0) }
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
            let origin = SessionCredential.Origin(rawValue: bytes[base + 1]),
            let phase = SessionCredential.Phase(rawValue: bytes[base + 2])
        else { return nil }

        func milliseconds(at start: Int) -> UInt64 {
            var value: UInt64 = 0
            for offset in 0..<8 { value = (value << 8) | UInt64(bytes[base + start + offset]) }
            return value
        }

        let uuidBytes = Array(bytes[(base + 19)..<(base + 35)])
        let aci = uuidBytes.withUnsafeBufferPointer { buffer in
            UUID(uuidString: NSUUID(uuidBytes: buffer.baseAddress!).uuidString)
        }
        guard let aci else { return nil }

        let credential = SessionCredential(
            token: Data(bytes[(base + headerSize)...]),
            aci: aci,
            issuedAt: Date(timeIntervalSince1970: TimeInterval(milliseconds(at: 3)) / 1000),
            expiresAt: Date(timeIntervalSince1970: TimeInterval(milliseconds(at: 11)) / 1000),
            origin: origin,
            phase: phase)
        return credential.isStructurallyValid ? credential : nil
    }
}

nonisolated enum SessionStoreError: Error, Equatable {
    case keychainFailure(operation: String, status: OSStatus)
    /// A development credential was offered to a Release build. Refused rather than stored:
    /// the point of the origin field is that it cannot be laundered.
    case developmentCredentialInReleaseBuild
    case malformedCredential
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
            let issuedAt = Date()
            return SessionCredential(token: token, aci: UUID(), issuedAt: issuedAt,
                                     expiresAt: issuedAt.addingTimeInterval(maximumLifetime),
                                     origin: .development, phase: .active)
        }
    }
#endif
