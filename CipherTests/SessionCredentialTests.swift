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

    private final class TestClock: @unchecked Sendable {
        private let lock = NSLock()
        private var value: Date

        init(_ value: Date) { self.value = value }

        func now() -> Date {
            lock.lock()
            defer { lock.unlock() }
            return value
        }

        func advance(by interval: TimeInterval) {
            lock.lock()
            value = value.addingTimeInterval(interval)
            lock.unlock()
        }
    }

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

    func testTheRetiredNotificationPreviewPreferenceIsCleared() {
        let (store, _) = makeStore()
        defer { try? store.clear() }
        let defaults = makeDefaults()

        defaults.set(true, forKey: "cipher.notificationPreviews")
        _ = AppSession(sessions: store, defaults: defaults)
        XCTAssertNil(defaults.object(forKey: "cipher.notificationPreviews"),
                     "an inert preference must not survive as apparently meaningful state")
    }

    // MARK: - Presence is the state

    func testCredentialPresenceIsTheAuthenticationState() throws {
        let (store, _) = makeStore()
        defer { try? store.clear() }
        let defaults = makeDefaults()
        try store.store(Self.sample())
        let session = AppSession(sessions: store, defaults: defaults)
        session.hasCompletedOnboarding = true
        XCTAssertTrue(session.isAuthenticated)
        XCTAssertEqual(session.destination, .main)

        try session.signOut()
        XCTAssertFalse(session.isAuthenticated)
        XCTAssertEqual(session.destination, .accountCleanup,
                       "history must be erased before another account can authenticate")
        XCTAssertEqual(store.current()?.phase, .destroying,
                       "the destructive gate must survive a crash")

        try session.completeAccountCleanup()
        XCTAssertEqual(session.destination, .authentication)
    }

    func testACredentialSurvivesRelaunch() throws {
        let (store, _) = makeStore()
        defer { try? store.clear() }
        let defaults = makeDefaults()
        try store.store(Self.sample())
        let first = AppSession(sessions: store, defaults: defaults)

        let relaunched = AppSession(sessions: store, defaults: defaults)
        XCTAssertTrue(relaunched.isAuthenticated,
                      "sign-in must outlive the process, or the Keychain is pointless")
        XCTAssertEqual(relaunched.credential?.token, first.credential?.token)
    }

    func testSignOutRemovesTheItemRatherThanBlankingIt() throws {
        let (store, _) = makeStore()
        defer { try? store.clear() }
        let defaults = makeDefaults()
        try store.store(Self.sample())
        let session = AppSession(sessions: store, defaults: defaults)
        try session.signOut()

        XCTAssertNotNil(store.current(), "the gate must remain until local erasure succeeds")
        try session.completeAccountCleanup()
        XCTAssertNil(store.current(), "cleanup removes the item rather than blanking it")
        XCTAssertFalse(AppSession(sessions: store, defaults: defaults).isAuthenticated)
    }

    func testPendingRegistrationSurvivesRelaunchWithoutExposingMain() throws {
        let (store, _) = makeStore()
        defer { try? store.clear() }
        let defaults = makeDefaults()
        defaults.set(true, forKey: "cipher.hasCompletedOnboarding")

        let first = AppSession(sessions: store, defaults: defaults)
        try first.beginRegistration(with: Self.sample(phase: .registering))
        XCTAssertEqual(first.destination, .registration)
        XCTAssertFalse(first.isAuthenticated)

        let relaunched = AppSession(sessions: store, defaults: defaults)
        XCTAssertEqual(relaunched.destination, .registration)
        XCTAssertEqual(relaunched.credential?.aci, first.credential?.aci)
        XCTAssertFalse(relaunched.isAuthenticated)

        try relaunched.completeRegistration()
        XCTAssertEqual(relaunched.destination, .profileSetup,
                       "profile setup is a persisted gate, not an unreachable screen")
    }

    func testExpiredCredentialRequiresErasureBeforeAnotherInvite() throws {
        let (store, _) = makeStore()
        defer { try? store.clear() }
        let defaults = makeDefaults()
        defaults.set(true, forKey: "cipher.hasCompletedOnboarding")
        let issuedAt = Date(timeIntervalSince1970: 1_700_000_000)
        try store.store(Self.sample(
            issuedAt: issuedAt,
            expiresAt: issuedAt.addingTimeInterval(30 * 24 * 60 * 60)))

        let session = AppSession(
            sessions: store, defaults: defaults,
            now: { issuedAt.addingTimeInterval(31 * 24 * 60 * 60) })
        XCTAssertFalse(session.isAuthenticated)
        XCTAssertEqual(session.destination, .accountCleanup)
    }

    func testForegroundExpiryPersistsTheDestructiveGate() throws {
        let (store, _) = makeStore()
        defer { try? store.clear() }
        let defaults = makeDefaults()
        defaults.set(true, forKey: "cipher.hasCompletedOnboarding")
        let issuedAt = Date(timeIntervalSince1970: 1_800_000_000)
        let clock = TestClock(issuedAt.addingTimeInterval(30))
        try store.store(Self.sample(
            issuedAt: issuedAt, expiresAt: issuedAt.addingTimeInterval(60)))
        let session = AppSession(
            sessions: store, defaults: defaults, now: { clock.now() })

        XCTAssertEqual(session.destination, .main, "positive control: token starts live")
        clock.advance(by: 31)
        try session.enforceCredentialExpiry()

        XCTAssertEqual(session.destination, .accountCleanup)
        XCTAssertEqual(store.current()?.phase, .destroying,
                       "expiry while foregrounded must survive a process restart")
        XCTAssertEqual(
            AppSession(sessions: store, defaults: defaults, now: { clock.now() }).destination,
            .accountCleanup)
    }

    func testCleanupRechecksATemporarilyUnreadableCredentialBeforeErasing() throws {
        let (store, service) = makeStore()
        defer { try? store.clear() }
        let defaults = makeDefaults()
        defaults.set(true, forKey: "cipher.hasCompletedOnboarding")

        // Models a prewarmed launch: the slot is visible but its protected value
        // cannot be decoded yet. Once the UI is visible, the same slot reads normally.
        try Self.writeRaw(Data([0x02, 0x01]), service: service)
        let session = AppSession(sessions: store, defaults: defaults)
        XCTAssertEqual(session.destination, .accountCleanup, "positive control")

        let credential = Self.sample()
        try store.store(credential)
        XCTAssertTrue(session.recoverReadableCredentialBeforeCleanup())
        XCTAssertEqual(session.credential?.aci, credential.aci)
        XCTAssertEqual(session.credential?.token, credential.token)
        XCTAssertEqual(session.credential?.phase, .active)
        XCTAssertEqual(session.destination, .main,
                       "a recovered valid credential must cancel destructive cleanup")
    }

    // MARK: - Stored bytes

    /// Round-trips through the real Keychain, so the coding and the item attributes are both
    /// exercised rather than only the struct.
    func testCredentialRoundTripsThroughTheKeychain() throws {
        let (store, _) = makeStore()
        defer { try? store.clear() }
        let original = SessionCredential(
            token: Data((String(repeating: "E", count: 42) + "A").utf8),
            aci: UUID(uuidString: "3f2b1c4d-0000-4000-8000-000000000001")!,
            issuedAt: Date(timeIntervalSince1970: 1_700_000_000),
            expiresAt: Date(timeIntervalSince1970: 1_702_000_000),
            origin: .serverIssued,
            phase: .profileSetup)

        try store.store(original)
        let read = try XCTUnwrap(store.current())

        XCTAssertEqual(read.token, original.token)
        XCTAssertEqual(read.origin, .serverIssued)
        XCTAssertEqual(read.aci, original.aci)
        XCTAssertEqual(read.phase, .profileSetup)
        XCTAssertEqual(read.expiresAt.timeIntervalSince1970,
                       original.expiresAt.timeIntervalSince1970, accuracy: 0.001)
        XCTAssertEqual(read.issuedAt.timeIntervalSince1970,
                       original.issuedAt.timeIntervalSince1970, accuracy: 0.001)
    }

    func testStoringReplacesRatherThanAccumulates() throws {
        let (store, _) = makeStore()
        defer { try? store.clear() }
        try store.store(Self.sample(tokenCharacter: "F"))
        try store.store(Self.sample(tokenCharacter: "G"))

        XCTAssertEqual(store.current()?.token,
                       Data((String(repeating: "G", count: 42) + "A").utf8))
    }

    /// A stored blob this build cannot fully understand must read as signed out, never as a
    /// partially believed session. Same rule as `PeerIdentityRecord`'s unknown flag bits.
    func testAMalformedOrFutureItemReadsAsSignedOut() throws {
        let (store, service) = makeStore()
        defer { try? store.clear() }
        try store.store(Self.sample())
        XCTAssertNotNil(store.current(), "positive control")

        for corruption in [
            Data([0x03, 0x01, 0x03] + Array(repeating: 0, count: 40)),  // future version
            Data([0x02, 0x09, 0x03] + Array(repeating: 0, count: 40)),  // unknown origin
            Data([0x02, 0x01, 0x09] + Array(repeating: 0, count: 40)),  // unknown phase
            Data([0x02, 0x01]),  // truncated header
            Data(),  // empty
        ] {
            try Self.writeRaw(corruption, service: service)
            XCTAssertNil(store.current(), "malformed item must read as signed out")
        }
    }

    func testUnreadableLegacyCredentialForcesCleanupRatherThanNewRegistration() throws {
        let (store, service) = makeStore()
        defer { try? store.clear() }
        let defaults = makeDefaults()
        defaults.set(true, forKey: "cipher.hasCompletedOnboarding")

        // Version 1 is the pre-account-bound credential layout.
        try Self.writeRaw(Data([0x01, 0x01] + Array(repeating: 0, count: 40)), service: service)
        XCTAssertNil(store.current(), "the old credential must not be partially believed")

        let session = AppSession(sessions: store, defaults: defaults)
        XCTAssertEqual(session.destination, .accountCleanup,
                       "a new invite must not meet crypto/history from the old account")
    }

    func testMalformedServerTokenCannotBeStored() throws {
        let (store, _) = makeStore()
        defer { try? store.clear() }
        let issuedAt = Date()
        let malformed = SessionCredential(
            token: Data("not-a-server-token".utf8), aci: UUID(), issuedAt: issuedAt,
            expiresAt: issuedAt.addingTimeInterval(60),
            origin: .serverIssued, phase: .active)
        XCTAssertThrowsError(try store.store(malformed)) { error in
            XCTAssertEqual(error as? SessionStoreError, .malformedCredential)
        }
    }

    func testRotationIsSingleFlightAndCannotChangeAccounts() throws {
        let (store, _) = makeStore()
        defer { try? store.clear() }
        let defaults = makeDefaults()
        defaults.set(true, forKey: "cipher.hasCompletedOnboarding")
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let aci = UUID()
        let current = Self.sample(
            tokenCharacter: "K", aci: aci,
            issuedAt: now.addingTimeInterval(-24 * 60 * 60),
            expiresAt: now.addingTimeInterval(6 * 24 * 60 * 60))
        try store.store(current)
        let session = AppSession(sessions: store, defaults: defaults, now: { now })

        XCTAssertEqual(session.beginCredentialRotationIfNeeded(), current)
        XCTAssertNil(session.beginCredentialRotationIfNeeded(),
                     "two foreground tasks must not rotate one token concurrently")
        XCTAssertTrue(session.credentialRotationIsInFlight,
                      "a second sync must wait instead of using the consumed old token")
        session.endCredentialRotation()
        XCTAssertFalse(session.credentialRotationIsInFlight)
        XCTAssertEqual(session.beginCredentialRotationIfNeeded(), current)
        session.endCredentialRotation()

        let wrongAccount = SessionCredential(
            token: Data((String(repeating: "L", count: 42) + "A").utf8), aci: UUID(),
            issuedAt: now,
            expiresAt: now.addingTimeInterval(30 * 24 * 60 * 60),
            origin: .serverIssued, phase: .active)
        XCTAssertThrowsError(try session.adoptRotatedCredential(wrongAccount))
        XCTAssertEqual(store.current(), current,
                       "a hostile rotation response must not rewrite the account binding")
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

    private static func sample(
        tokenCharacter: Character = "H",
        aci: UUID = UUID(),
        phase: SessionCredential.Phase = .active,
        issuedAt: Date = Date(),
        expiresAt: Date? = nil
    ) -> SessionCredential {
        SessionCredential(
            token: Data((String(repeating: tokenCharacter, count: 42) + "A").utf8),
            aci: aci, issuedAt: issuedAt,
            expiresAt: expiresAt ?? issuedAt.addingTimeInterval(30 * 24 * 60 * 60),
            origin: .serverIssued, phase: phase)
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
