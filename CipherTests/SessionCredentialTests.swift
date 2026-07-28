//
//  SessionCredentialTests.swift
//  CipherTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//
//  P3.S01 — the authentication gate is the Keychain, not a UserDefaults boolean.
//
//  App-hosted for the same reason the crypto suite is: a host-less bundle has no keychain
//  access group, so every SecItem call fails with errSecMissingEntitlement (AUDIT 6.6).
//

import Foundation
import XCTest

@testable import Cipher

/// `@MainActor` because `AppSession` is: it is `@Observable` state SwiftUI reads, and the
/// app target defaults to main-actor isolation. Hopping deliberately rather than making the
/// session nonisolated — the isolation is real, and a test that opts out of it would be
/// exercising a configuration the app never runs in.
@MainActor
final class SessionCredentialTests: XCTestCase {

    /// A store on a service string unique to this call.
    ///
    /// Per test rather than in `setUp`: XCTest's overrides are nonisolated and this suite is
    /// `@MainActor`, but the better reason is that it leaves no shared mutable state between
    /// tests and no way for one to observe another's Keychain item — or the real one.
    private func makeStore() -> (store: SessionStore, service: String) {
        let service = "cz.janrichtermoc.Cipher.session.test.\(UUID().uuidString)"
        return (SessionStore(service: service), service)
    }

    /// A scratch `UserDefaults` suite, so nothing here touches the process-wide one. Tests
    /// that shared it leaked onboarding state into each other and passed or failed on run
    /// order — caught by this suite's own first run.
    private func makeDefaults() -> UserDefaults {
        let name = "cipher.tests.\(UUID().uuidString)"
        guard let suite = UserDefaults(suiteName: name) else {
            fatalError("could not create a scratch defaults suite")
        }
        return suite
    }

    // MARK: - The claim P3.S01 exists to make

    /// **Editing `UserDefaults` cannot produce an authenticated state.**
    ///
    /// The old design kept `isAuthenticated` in `UserDefaults` — a plist inside the app
    /// container, editable on a jailbroken device or by anything with a file-write primitive,
    /// with no code execution required. This writes every key that ever meant "signed in",
    /// plus some plausible guesses, and asserts the session is still signed out.
    func testWritingUserDefaultsCannotAuthenticate() throws {
        let (store, _) = makeStore()
        defer { try? store.clear() }
        let defaults = makeDefaults()

        let session = AppSession(sessions: store, defaults: defaults)
        XCTAssertFalse(session.isAuthenticated, "a fresh install starts signed out")

        let planted = [
            "cipher.isAuthenticated",  // the actual old key
            "isAuthenticated",
            "cipher.auth",
            "cipher.session",
            "cipher.credential",
        ]
        for key in planted { defaults.set(true, forKey: key) }
        defer { planted.forEach { defaults.removeObject(forKey: $0) } }

        let reopened = AppSession(sessions: store, defaults: defaults)
        XCTAssertFalse(reopened.isAuthenticated,
                       "a UserDefaults write must not produce a signed-in app")
        XCTAssertEqual(reopened.destination, .onboarding,
                       "and it must not move the app past any gate")
    }

    /// The old key is not merely ignored — it is removed, so it cannot sit in the container
    /// looking meaningful to the next reader.
    func testTheRetiredUserDefaultsKeyIsCleared() {
        let (store, _) = makeStore()
        defer { try? store.clear() }
        let defaults = makeDefaults()

        defaults.set(true, forKey: "cipher.isAuthenticated")
        _ = AppSession(sessions: store, defaults: defaults)
        XCTAssertNil(defaults.object(forKey: "cipher.isAuthenticated"))
    }

    // MARK: - Presence is the state

    func testCredentialPresenceIsTheAuthenticationState() throws {
        let (store, _) = makeStore()
        defer { try? store.clear() }
        let defaults = makeDefaults()
        let session = AppSession(sessions: store, defaults: defaults)
        session.hasCompletedOnboarding = true
        XCTAssertEqual(session.destination, .authentication)

        try session.signIn(with: Self.sample())
        XCTAssertTrue(session.isAuthenticated)
        XCTAssertEqual(session.destination, .main)

        try session.signOut()
        XCTAssertFalse(session.isAuthenticated)
        XCTAssertEqual(session.destination, .authentication)
    }

    func testACredentialSurvivesRelaunch() throws {
        let (store, _) = makeStore()
        defer { try? store.clear() }
        let defaults = makeDefaults()
        let first = AppSession(sessions: store, defaults: defaults)
        try first.signIn(with: Self.sample())

        let relaunched = AppSession(sessions: store, defaults: defaults)
        XCTAssertTrue(relaunched.isAuthenticated,
                      "sign-in must outlive the process, or the Keychain is pointless")
        XCTAssertEqual(relaunched.credential?.token, first.credential?.token)
    }

    func testSignOutRemovesTheItemRatherThanBlankingIt() throws {
        let (store, _) = makeStore()
        defer { try? store.clear() }
        let defaults = makeDefaults()
        let session = AppSession(sessions: store, defaults: defaults)
        try session.signIn(with: Self.sample())
        try session.signOut()

        XCTAssertNil(store.current(), "the item must be gone, not emptied")
        XCTAssertFalse(AppSession(sessions: store, defaults: defaults).isAuthenticated)
    }

    // MARK: - Stored bytes

    /// Round-trips through the real Keychain, so the coding and the item attributes are both
    /// exercised rather than only the struct.
    func testCredentialRoundTripsThroughTheKeychain() throws {
        let (store, _) = makeStore()
        defer { try? store.clear() }
        let original = SessionCredential(
            token: Data((0..<64).map { UInt8($0) }),
            issuedAt: Date(timeIntervalSince1970: 1_700_000_000),
            origin: .serverIssued)

        try store.store(original)
        let read = try XCTUnwrap(store.current())

        XCTAssertEqual(read.token, original.token)
        XCTAssertEqual(read.origin, .serverIssued)
        XCTAssertEqual(read.issuedAt.timeIntervalSince1970,
                       original.issuedAt.timeIntervalSince1970, accuracy: 0.001)
    }

    func testStoringReplacesRatherThanAccumulates() throws {
        let (store, _) = makeStore()
        defer { try? store.clear() }
        try store.store(Self.sample(token: Data(repeating: 0xAA, count: 32)))
        try store.store(Self.sample(token: Data(repeating: 0xBB, count: 32)))

        XCTAssertEqual(store.current()?.token, Data(repeating: 0xBB, count: 32))
    }

    /// A stored blob this build cannot fully understand must read as signed out, never as a
    /// partially believed session. Same rule as `PeerIdentityRecord`'s unknown flag bits.
    func testAMalformedOrFutureItemReadsAsSignedOut() throws {
        let (store, service) = makeStore()
        defer { try? store.clear() }
        try store.store(Self.sample())
        XCTAssertNotNil(store.current(), "positive control")

        for corruption in [
            Data([0x02, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF]),  // future version
            Data([0x01, 0x09, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF]),  // unknown origin
            Data([0x01, 0x01]),  // truncated header
            Data(),  // empty
        ] {
            try Self.writeRaw(corruption, service: service)
            XCTAssertNil(store.current(), "malformed item must read as signed out")
        }
    }

    // MARK: - Development credentials

    #if DEBUG
        /// The development credential is a *distinct kind*, not a stand-in for a real one:
        /// it is marked in the stored bytes so a Release build rejects it on read. This
        /// asserts the marking, which is the part a Release build depends on.
        func testDevelopmentCredentialIsMarkedAsSuch() throws {
        let (store, _) = makeStore()
        defer { try? store.clear() }
            let credential = SessionCredential.development()
            XCTAssertEqual(credential.origin, .development)
            XCTAssertEqual(credential.token.count, 32)

            try store.store(credential)
            XCTAssertEqual(store.current()?.origin, .development,
                           "the origin must survive storage — Release reads it to refuse")
        }

        func testTwoDevelopmentCredentialsDiffer() {
            XCTAssertNotEqual(SessionCredential.development().token,
                              SessionCredential.development().token,
                              "a constant token would be a shared secret in every build")
        }
    #endif

    // MARK: - Helpers

    private static func sample(token: Data = Data(repeating: 0x5A, count: 32)) -> SessionCredential {
        SessionCredential(token: token, issuedAt: Date(), origin: .serverIssued)
    }

    /// Plants raw bytes in the slot, bypassing the encoder — the only way to test what the
    /// decoder does with something it did not write.
    private static func writeRaw(_ bytes: Data, service: String) throws {
        let base: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: "session-credential",
            kSecAttrSynchronizable: false,
            kSecUseDataProtectionKeychain: true,
        ]
        SecItemDelete(base as CFDictionary)

        var add = base
        add[kSecValueData] = bytes
        add[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(add as CFDictionary, nil)
        XCTAssertEqual(status, errSecSuccess, "could not plant the test item")
    }
}
