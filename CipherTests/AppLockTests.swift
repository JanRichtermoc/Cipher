//
//  AppLockTests.swift
//  CipherTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//
//  P3.S02 — the app lock, and the two things about it that were wrong.
//
//  `LAContext` cannot be driven from a unit test: there is no way to simulate a successful
//  Face ID match, and a test that could would be testing the simulator. So the real
//  authenticator is swapped for a double, and what is pinned here is the *policy* around it
//  — which is where both historical defects lived. Neither was a cryptography mistake:
//
//    C-03     `unlock()` set `isAppLocked = false` unconditionally while the screen
//             promised Face ID. Nothing was ever asked.
//    AUDIT 5.8 `lockIfNeeded()` had exactly one caller, a manual button, so the lock
//             engaged on cold launch and never again.
//

import Foundation
import XCTest

@testable import Cipher

/// Records what it was asked and answers as instructed. `@unchecked Sendable` via a lock
/// because `DeviceAuthenticator` is `Sendable` and this is mutable test state.
private final class StubAuthenticator: DeviceAuthenticator, @unchecked Sendable {
    private let mutex = NSLock()
    private var _result: Result<Void, DeviceAuthenticationError>
    private var _calls = 0
    private var _reasons: [String] = []

    let isAvailable: Bool

    init(available: Bool = true, result: Result<Void, DeviceAuthenticationError> = .success(())) {
        self.isAvailable = available
        self._result = result
    }

    var calls: Int { mutex.withLock { _calls } }
    var reasons: [String] { mutex.withLock { _reasons } }

    func set(_ result: Result<Void, DeviceAuthenticationError>) {
        mutex.withLock { _result = result }
    }

    func authenticate(reason: String) async throws {
        let outcome: Result<Void, DeviceAuthenticationError> = mutex.withLock {
            _calls += 1
            _reasons.append(reason)
            return _result
        }
        try outcome.get()
    }
}

@MainActor
final class AppLockTests: XCTestCase {

    private func activeCredential(byte: Character = "B") -> SessionCredential {
        let issuedAt = Date()
        return SessionCredential(
            token: Data((String(repeating: byte, count: 42) + "A").utf8), aci: UUID(),
            issuedAt: issuedAt,
            expiresAt: issuedAt.addingTimeInterval(30 * 24 * 60 * 60),
            origin: .serverIssued, phase: .active)
    }

    private func makeSession(
        authenticator: DeviceAuthenticator
    ) -> (session: AppSession, store: SessionStore) {
        let store = SessionStore(service: "cz.janrichtermoc.Cipher.session.test.\(UUID())")
        let defaults = UserDefaults(suiteName: "cipher.tests.\(UUID().uuidString)")!
        return (AppSession(sessions: store, defaults: defaults, authenticator: authenticator),
                store)
    }

    /// Signed in with the lock on, so `destination` is `.locked`.
    private func lockedSession(
        _ authenticator: DeviceAuthenticator
    ) throws -> (session: AppSession, store: SessionStore) {
        let store = SessionStore(service: "cz.janrichtermoc.Cipher.session.test.\(UUID())")
        let defaults = UserDefaults(suiteName: "cipher.tests.\(UUID().uuidString)")!
        defaults.set(true, forKey: "cipher.hasCompletedOnboarding")
        defaults.set(true, forKey: "cipher.appLockEnabled")
        try store.store(activeCredential())
        let session = AppSession(
            sessions: store,
            defaults: defaults,
            authenticator: authenticator)
        XCTAssertEqual(session.destination, .locked, "signing in with the lock on starts locked")
        return (session, store)
    }

    // MARK: - C-03: nothing unlocks without a successful check

    func testUnlockRequiresASuccessfulDeviceOwnerCheck() async throws {
        let stub = StubAuthenticator()
        let (session, store) = try lockedSession(stub)
        defer { try? store.clear() }

        try await session.unlock(reason: "Unlock Cipher")

        XCTAssertEqual(stub.calls, 1, "the check must actually be performed, not assumed")
        XCTAssertEqual(stub.reasons, ["Unlock Cipher"])
        XCTAssertEqual(session.destination, .main)
    }

    /// **A cancelled prompt is not consent.**
    ///
    /// This is the classic form of the bug, and it is invisible in manual testing because
    /// the happy path looks identical — you only see it when someone dismisses the sheet.
    func testCancellingLeavesTheAppLocked() async throws {
        let stub = StubAuthenticator(result: .failure(.cancelled))
        let (session, store) = try lockedSession(stub)
        defer { try? store.clear() }

        do {
            try await session.unlock(reason: "Unlock Cipher")
            XCTFail("a cancelled check must not unlock")
        } catch {
            XCTAssertEqual(error as? DeviceAuthenticationError, .cancelled)
        }

        XCTAssertTrue(session.isAppLocked)
        XCTAssertEqual(session.destination, .locked)
    }

    func testEveryNonSuccessLeavesTheAppLocked() async throws {
        for outcome in [DeviceAuthenticationError.cancelled, .failed, .unavailable] {
            let stub = StubAuthenticator(result: .failure(outcome))
            let (session, store) = try lockedSession(stub)
            defer { try? store.clear() }

            _ = try? await session.unlock(reason: "Unlock Cipher")

            XCTAssertTrue(session.isAppLocked, "\(outcome) must not unlock")
            XCTAssertEqual(session.destination, .locked)
        }
    }

    /// A failed attempt must not leave the lock in a state a *later* success can skip.
    func testRetryAfterAFailureStillRequiresTheCheck() async throws {
        let stub = StubAuthenticator(result: .failure(.failed))
        let (session, store) = try lockedSession(stub)
        defer { try? store.clear() }

        _ = try? await session.unlock(reason: "Unlock Cipher")
        XCTAssertTrue(session.isAppLocked)

        stub.set(.success(()))
        try await session.unlock(reason: "Unlock Cipher")

        XCTAssertFalse(session.isAppLocked)
        XCTAssertEqual(stub.calls, 2, "the second attempt must ask again, not reuse the first")
    }

    // MARK: - AUDIT 5.8: the lock re-engages

    /// `RootView` calls `lockIfNeeded()` on every `scenePhase` away from `.active`. This
    /// asserts the session half of that: leaving the foreground re-locks.
    func testLeavingTheForegroundRelocks() async throws {
        let stub = StubAuthenticator()
        let (session, store) = try lockedSession(stub)
        defer { try? store.clear() }

        try await session.unlock(reason: "Unlock Cipher")
        XCTAssertEqual(session.destination, .main)

        session.lockIfNeeded()  // what the scenePhase observer does

        XCTAssertTrue(session.isAppLocked, "backgrounding must re-lock; it used not to")
        XCTAssertEqual(session.destination, .locked)
    }

    func testTheLockDoesNotEngageWhenTheFeatureIsOff() async throws {
        let stub = StubAuthenticator()
        let (session, store) = makeSession(authenticator: stub)
        defer { try? store.clear() }

        session.hasCompletedOnboarding = true
        session.appLockEnabled = false
        try store.store(activeCredential(byte: "C"))
        let signedIn = AppSession(
            sessions: store,
            defaults: UserDefaults(suiteName: "cipher.tests.\(UUID().uuidString)")!,
            authenticator: stub)
        signedIn.hasCompletedOnboarding = true

        XCTAssertEqual(signedIn.destination, .main)
        signedIn.lockIfNeeded()
        XCTAssertEqual(signedIn.destination, .main, "a disabled lock must not engage")
        XCTAssertEqual(stub.calls, 0)
    }

    /// Turning the feature off clears an engaged lock. Otherwise the user is left on a lock
    /// screen for a feature they just disabled — a lockout, not a control.
    func testDisablingTheLockClearsIt() async throws {
        let stub = StubAuthenticator()
        let (session, store) = try lockedSession(stub)
        defer { try? store.clear() }

        session.appLockEnabled = false

        XCTAssertFalse(session.isAppLocked)
        XCTAssertEqual(session.destination, .main)
        XCTAssertEqual(stub.calls, 0, "disabling must not require a device check")
    }

    // MARK: - Availability

    /// A device with no passcode cannot enforce the lock, so the setting is not offered.
    func testTheLockIsNotOfferedWhenTheDeviceCannotEnforceIt() {
        let (session, store) = makeSession(authenticator: StubAuthenticator(available: false))
        defer { try? store.clear() }
        XCTAssertFalse(session.canUseAppLock)
    }

    func testTheLockIsOfferedWhenTheDeviceCanEnforceIt() {
        let (session, store) = makeSession(authenticator: StubAuthenticator(available: true))
        defer { try? store.clear() }
        XCTAssertTrue(session.canUseAppLock)
    }

    // MARK: - Sign-in interaction

    func testSigningInStartsLockedWhenTheLockIsOn() throws {
        let (session, store) = makeSession(authenticator: StubAuthenticator())
        defer { try? store.clear() }

        session.hasCompletedOnboarding = true
        session.appLockEnabled = true
        try store.store(activeCredential(byte: "D"))
        let signedIn = AppSession(
            sessions: store,
            defaults: UserDefaults(suiteName: "cipher.tests.\(UUID().uuidString)")!,
            authenticator: StubAuthenticator())
        signedIn.hasCompletedOnboarding = true
        signedIn.appLockEnabled = true
        signedIn.lockIfNeeded()

        XCTAssertTrue(signedIn.isAppLocked)
    }
}
