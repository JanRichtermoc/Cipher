//
//  SecretStorage.swift
//  CipherCrypto
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import Security

/// The narrow interface this module needs from the platform's secret store.
///
/// It exists so the two callers that hold root secrets — `DeviceIdentity` and the record
/// store's encryption key — depend on an interface with four operations rather than on
/// `SecItem*` directly. That keeps every Keychain attribute decision in exactly one file
/// (`Keychain`), which is the file an auditor reads, and lets tests run against an
/// in-memory double instead of mutating the shared simulator Keychain.
///
/// Deliberately synchronous: libsignal's store callbacks are synchronous and must not
/// suspend, and everything downstream of this protocol runs inside `@CryptoActor`.
internal protocol SecretStorage: AnyObject {

    /// Returns the stored bytes, or `nil` if nothing is stored under `key`.
    func load(_ key: String) throws -> Data?

    /// Stores `value` under `key` **only if the key is currently empty**, and returns
    /// whatever is stored afterwards.
    ///
    /// This is the module's load-or-create primitive and it must be atomic: a `load`-then-`store`
    /// pair lets two creators each generate an identity key and lets the second overwrite the
    /// first, silently destroying every session established in between.
    ///
    /// *Premise corrected 2026-08-09.* This named the app and "a future notification-service
    /// extension" as the two creators, and P8.S04 decided there will not be one (AUDIT 4.4).
    /// The primitive stays because create-or-adopt is what this operation means and the
    /// Keychain is the only place it can be made atomic — see `DeviceIdentity` for why that is
    /// stated rather than left to be rediscovered.
    ///
    /// - Returns: `value` if this call created the entry, or the pre-existing bytes if
    ///   another writer got there first. Callers must use the returned value, never the one
    ///   they passed in.
    func addOrLoad(_ value: Data, forKey key: String) throws -> Data

    /// Removes the entry. Succeeds whether or not anything was stored.
    func remove(_ key: String) throws

    /// Removes every entry this storage owns.
    ///
    /// This is the cryptographic-erase primitive: the record store's contents are
    /// unreadable once its key is gone, so destroying the secrets here destroys the
    /// database without having to overwrite it.
    func removeAll() throws
}

// MARK: - Errors

internal enum SecretStorageError: Error, Equatable {
    /// A `SecItem*` call failed. The `OSStatus` is safe to log: it describes the failure
    /// mode, never the secret.
    case keychainFailure(operation: String, status: OSStatus)
    /// The Keychain returned an item whose value was not data — it should be impossible,
    /// and it is treated as corruption rather than papered over.
    case malformedItem(String)
}

// MARK: - Keychain

/// The real `SecretStorage`, backed by the iOS data-protection Keychain.
///
/// ## Attribute choices, and why each one is what it is
///
/// - **`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.**
///   `ThisDeviceOnly` is the load-bearing half: it keeps the identity private key out of
///   encrypted iTunes/Finder backups and stops it migrating to a restored device. An
///   identity key that can be restored elsewhere is an identity that can be impersonated,
///   and the safety number would not change to warn anyone.
///
///   `AfterFirstUnlock` rather than `WhenUnlocked` is a deliberate, documented weakening.
///   **Wake-only push** has to decrypt an incoming message while the device is locked: a
///   silent push wakes the app, which fetches, decrypts and posts a local notification, in
///   its own process. Under `WhenUnlocked` it could not, and the product would have to fall
///   back to server-visible notification content, which is a far larger leak than the one
///   this trades away. The residual risk is that after the first unlock following a boot,
///   the key is reachable by any code that achieves execution on the device — the same
///   class of attacker that could read the plaintext database anyway.
///
///   *Corrected 2026-08-09.* This said "a notification-service extension has to decrypt",
///   and P8.S04 decided there will not be one (AUDIT 4.4). Left as it was, the weakening
///   would read as justified by something that does not exist, which invites exactly the
///   tightening to `WhenUnlocked` that AUDIT 2.1 forbids — and which silently breaks
///   notifications. Same requirement, no second process.
///
/// - **`kSecAttrSynchronizable = false`.** Never iCloud Keychain. Syncing a Signal identity
///   key would place it in Apple's custody and on every paired device.
///
/// - **`kSecUseDataProtectionKeychain = true`.** Already the only behaviour on iOS; stated
///   explicitly so the code keeps meaning the same thing if it is ever built for macOS or
///   Mac Catalyst, where the default is the *file-based* keychain with different semantics.
///
/// - **No `kSecAttrAccessGroup`.** The default group is the app's own. A shared group is
///   only added when an extension genuinely needs one, and that is a change worth reviewing.
internal final class Keychain: SecretStorage, Sendable {

    /// Everything this module stores lives under one service string, so `removeAll` can be
    /// exact and a test instance can be fully isolated from the real one.
    internal let service: String

    /// The service a shipped build uses, and the only one that ever holds a real account.
    internal static let productionService = "cz.janrichtermoc.Cipher.crypto"

    #if DEBUG
    /// Where a test run's keys go instead (AUDIT 6.18).
    ///
    /// A different service string, not a prefix or a suffix convention: `kSecAttrService`
    /// matches exactly, so `removeAll` under this value cannot reach an item stored under the
    /// production one no matter what it deletes.
    internal static let testService = "cz.janrichtermoc.Cipher.crypto.xctest"

    /// The process-wide handle, redirected away from the real account while tests are running.
    ///
    /// ## Why this is here and not in a fixture
    ///
    /// AUDIT 6.17 put an account-destruction refusal in `verify-all.sh`, which is the right
    /// place for the run someone starts and walks away from — but the hazard lives in the
    /// *tests*, so a direct `xcodebuild test -only-testing:…` walked straight past it. AUDIT
    /// 6.18 recorded that, and recorded it as observed rather than hypothesised: it destroyed
    /// the simulator installation the P5.S13 field test was using.
    ///
    /// The fix could have gone in `MessagingFixture`, which is the fixture that did the damage.
    /// It is here instead because a fixture protects the tests someone has already written.
    /// Every path into this module's storage goes through `Keychain.shared` — including
    /// `CryptoEngine.open`, which is the public entry point an app-side test naturally reaches
    /// for — so redirecting it once covers the fixtures nobody has written yet.
    ///
    /// ## Why the detection is what it is
    ///
    /// `XCTestCase` being loadable means the XCTest framework is in this process, which for an
    /// app-hosted suite (AUDIT 6.6) is the host app itself. The environment variable is the
    /// signal `xcodebuild` sets and is checked as well, so neither mechanism alone is load
    /// bearing. A developer running the app in Debug by hand matches neither and keeps their
    /// account, which is the behaviour to preserve — this must protect real state from tests,
    /// not make Debug a second, quieter account.
    ///
    /// Fenced out of Release entirely. A shipping binary contains neither the branch nor the
    /// string, which is the rule 5.6 and 5.11 exist to enforce: `#if DEBUG` fences code, and
    /// gate 16 greps the whole Release bundle for what leaks past it anyway.
    internal static let shared: Keychain = {
        let environment = ProcessInfo.processInfo.environment
        let underTest = NSClassFromString("XCTestCase") != nil
            || environment["XCTestConfigurationFilePath"] != nil
            || environment["XCTestBundlePath"] != nil
        return Keychain(service: underTest ? testService : productionService)
    }()
    #else
    internal static let shared = Keychain(service: productionService)
    #endif

    internal init(service: String) {
        self.service = service
    }

    /// Attributes shared by every query. `kSecAttrAccessible` is deliberately **not** here:
    /// it is an attribute of stored items, and including it in a lookup query would make
    /// matching depend on it.
    private func baseQuery(_ key: String) -> [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: key,
            kSecAttrSynchronizable: false,
            kSecUseDataProtectionKeychain: true,
        ]
    }

    internal func load(_ key: String) throws -> Data? {
        var query = baseQuery(key)
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            guard let data = result as? Data else {
                throw SecretStorageError.malformedItem(key)
            }
            return data
        case errSecItemNotFound:
            return nil
        default:
            throw SecretStorageError.keychainFailure(operation: "load", status: status)
        }
    }

    internal func addOrLoad(_ value: Data, forKey key: String) throws -> Data {
        var query = baseQuery(key)
        query[kSecValueData] = value
        query[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

        let status = SecItemAdd(query as CFDictionary, nil)

        switch status {
        case errSecSuccess:
            return value

        case errSecDuplicateItem:
            // Someone else won the race. Their value is authoritative: it may already have
            // sessions built on it. A `nil` here would mean the item vanished between the
            // add and the read, which is not a state this module can reason about.
            guard let existing = try load(key) else {
                throw SecretStorageError.keychainFailure(operation: "addOrLoad", status: status)
            }
            return existing

        default:
            throw SecretStorageError.keychainFailure(operation: "addOrLoad", status: status)
        }
    }

    internal func remove(_ key: String) throws {
        let status = SecItemDelete(baseQuery(key) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SecretStorageError.keychainFailure(operation: "remove", status: status)
        }
    }

    internal func removeAll() throws {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrSynchronizable: false,
            kSecUseDataProtectionKeychain: true,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SecretStorageError.keychainFailure(operation: "removeAll", status: status)
        }
    }
}
