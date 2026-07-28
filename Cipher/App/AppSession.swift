//
//  AppSession.swift
//  Cipher
//

import Foundation
import SwiftUI

@Observable
final class AppSession {
    var hasCompletedOnboarding: Bool {
        didSet { defaults.set(hasCompletedOnboarding, forKey: Keys.onboarding) }
    }
    /// Signed in **iff** a credential is in the Keychain.
    ///
    /// Not stored here and not settable. This used to be a `UserDefaults` bool, which meant
    /// the authentication gate was a plist entry in the app container — editable on a
    /// jailbroken device, or by anything with a file-write primitive, with no code execution
    /// needed at all. `SessionCredentialTests` proves that writing to `UserDefaults` can no
    /// longer produce a signed-in app.
    private(set) var credential: SessionCredential?

    var isAuthenticated: Bool { credential != nil }
    var isAppLocked: Bool
    var appLockEnabled: Bool {
        didSet { defaults.set(appLockEnabled, forKey: Keys.appLock) }
    }
    var screenshotWarningEnabled: Bool {
        didSet { defaults.set(screenshotWarningEnabled, forKey: Keys.screenshot) }
    }
    var defaultDisappearingSeconds: Int {
        didSet { defaults.set(defaultDisappearingSeconds, forKey: Keys.disappearing) }
    }
    var notificationPreviewsEnabled: Bool {
        didSet { defaults.set(notificationPreviewsEnabled, forKey: Keys.previews) }
    }
    var displayName: String {
        didSet { defaults.set(displayName, forKey: Keys.displayName) }
    }
    var username: String {
        didSet { defaults.set(username, forKey: Keys.username) }
    }
    var about: String {
        didSet { defaults.set(about, forKey: Keys.about) }
    }

    #if DEBUG
    /// Skips every gate and lands on the main tabs.
    ///
    /// Fenced together with the two places that *read* it. Fencing only the buttons that set
    /// it — which is how this started — still ships the switch: a Release binary then carries
    /// a single boolean that bypasses onboarding, authentication, and the app lock at once,
    /// needing only one careless line or a runtime write to flip. A debug affordance that
    /// exists in a shipping build is not a debug affordance.
    var debugSkipToMain: Bool = false
    #endif

    private enum Keys {
        static let onboarding = "cipher.hasCompletedOnboarding"
        static let appLock = "cipher.appLockEnabled"
        static let screenshot = "cipher.screenshotWarning"
        static let disappearing = "cipher.defaultDisappearing"
        static let previews = "cipher.notificationPreviews"
        static let displayName = "cipher.displayName"
        static let username = "cipher.username"
        static let about = "cipher.about"
    }

    private let sessions: SessionStore
    /// Injected so a test can use a scratch suite. `UserDefaults.standard` is process-wide,
    /// so tests that shared it leaked onboarding state into each other and passed or failed
    /// on run order — which is how a suite starts being re-run until it goes green.
    private let defaults: UserDefaults

    init(sessions: SessionStore = SessionStore(), defaults: UserDefaults = .standard) {
        self.sessions = sessions
        self.defaults = defaults

        // A build that predates this carries `cipher.isAuthenticated` in UserDefaults. It is
        // no longer read, but leaving it would be a stale flag that looks meaningful to the
        // next person to open the plist — and to anyone reasoning about what an attacker
        // could reach. Removed on first launch of any build that has this line.
        defaults.removeObject(forKey: "cipher.isAuthenticated")

        let lockEnabled = defaults.object(forKey: Keys.appLock) as? Bool ?? false
        self.hasCompletedOnboarding = defaults.bool(forKey: Keys.onboarding)
        self.appLockEnabled = lockEnabled
        self.screenshotWarningEnabled = defaults.object(forKey: Keys.screenshot) as? Bool ?? true
        self.defaultDisappearingSeconds = defaults.object(forKey: Keys.disappearing) as? Int ?? 0
        self.notificationPreviewsEnabled = defaults.object(forKey: Keys.previews) as? Bool ?? true
        self.displayName = defaults.string(forKey: Keys.displayName) ?? "You"
        self.username = defaults.string(forKey: Keys.username) ?? "you"
        self.about = defaults.string(forKey: Keys.about) ?? "Available"
        self.isAppLocked = lockEnabled
        self.credential = sessions.current()
    }

    /// Which gate the app is currently behind.
    ///
    /// **The only definition of that decision.** It used to be written twice — here and again
    /// in `RootView.body` — which meant tightening one left the other live, and `RootView`
    /// is the one that actually decides what renders. A security condition with two homes is
    /// a security condition that will eventually disagree with itself.
    enum Destination: Equatable {
        case onboarding
        case authentication
        case locked
        case main
    }

    var destination: Destination {
        #if DEBUG
        if debugSkipToMain { return .main }
        #endif
        guard hasCompletedOnboarding else { return .onboarding }
        guard isAuthenticated else { return .authentication }
        return isAppLocked ? .locked : .main
    }

    var showsMainApp: Bool { destination == .main }

    func completeOnboarding() {
        hasCompletedOnboarding = true
    }

    /// Adopts a credential and, if the app lock is on, starts locked.
    ///
    /// Throwing on a Keychain failure is deliberate: silently continuing would leave the app
    /// showing a signed-in UI that the next launch would not reproduce, and "signed in until
    /// you close it" is the kind of state that gets mistaken for a bug in the crypto.
    func signIn(with credential: SessionCredential) throws {
        try sessions.store(credential)
        self.credential = credential
        isAppLocked = appLockEnabled
    }

    #if DEBUG
    /// Signs in with a locally minted development credential.
    ///
    /// DEBUG only, and the credential it mints is marked `.development` in its stored bytes,
    /// so a Release build refuses it on read. There is deliberately no Release counterpart:
    /// a real credential comes from redeeming an invite code against the relay (P5.S09), and
    /// until that exists a shipping build genuinely cannot authenticate. Minting something
    /// locally that *looked* like a session would be exactly the fake token the plan forbids.
    func signInForDevelopment() throws {
        try signIn(with: .development())
    }
    #endif

    /// Signs out and destroys the credential.
    func signOut() throws {
        try sessions.clear()
        credential = nil
        isAppLocked = false
    }

    func unlock() {
        isAppLocked = false
    }

    func lockIfNeeded() {
        if appLockEnabled {
            isAppLocked = true
        }
    }

    #if DEBUG
    /// Returns the app to first-launch state. Development only — a shipping build has no
    /// business carrying a one-tap wipe of the authentication state.
    func resetDemoState() {
        hasCompletedOnboarding = false
        try? sessions.clear()
        credential = nil
        isAppLocked = false
        debugSkipToMain = false
    }
    #endif
}
