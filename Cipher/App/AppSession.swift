//
//  AppSession.swift
//  Cipher
//

import Foundation
import SwiftUI

@Observable
final class AppSession {
    var hasCompletedOnboarding: Bool {
        didSet { UserDefaults.standard.set(hasCompletedOnboarding, forKey: Keys.onboarding) }
    }
    var isAuthenticated: Bool {
        didSet { UserDefaults.standard.set(isAuthenticated, forKey: Keys.auth) }
    }
    var isAppLocked: Bool
    var appLockEnabled: Bool {
        didSet { UserDefaults.standard.set(appLockEnabled, forKey: Keys.appLock) }
    }
    var screenshotWarningEnabled: Bool {
        didSet { UserDefaults.standard.set(screenshotWarningEnabled, forKey: Keys.screenshot) }
    }
    var defaultDisappearingSeconds: Int {
        didSet { UserDefaults.standard.set(defaultDisappearingSeconds, forKey: Keys.disappearing) }
    }
    var notificationPreviewsEnabled: Bool {
        didSet { UserDefaults.standard.set(notificationPreviewsEnabled, forKey: Keys.previews) }
    }
    var displayName: String {
        didSet { UserDefaults.standard.set(displayName, forKey: Keys.displayName) }
    }
    var username: String {
        didSet { UserDefaults.standard.set(username, forKey: Keys.username) }
    }
    var about: String {
        didSet { UserDefaults.standard.set(about, forKey: Keys.about) }
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
        static let auth = "cipher.isAuthenticated"
        static let appLock = "cipher.appLockEnabled"
        static let screenshot = "cipher.screenshotWarning"
        static let disappearing = "cipher.defaultDisappearing"
        static let previews = "cipher.notificationPreviews"
        static let displayName = "cipher.displayName"
        static let username = "cipher.username"
        static let about = "cipher.about"
    }

    init() {
        let defaults = UserDefaults.standard
        let lockEnabled = defaults.object(forKey: Keys.appLock) as? Bool ?? false
        self.hasCompletedOnboarding = defaults.bool(forKey: Keys.onboarding)
        self.isAuthenticated = defaults.bool(forKey: Keys.auth)
        self.appLockEnabled = lockEnabled
        self.screenshotWarningEnabled = defaults.object(forKey: Keys.screenshot) as? Bool ?? true
        self.defaultDisappearingSeconds = defaults.object(forKey: Keys.disappearing) as? Int ?? 0
        self.notificationPreviewsEnabled = defaults.object(forKey: Keys.previews) as? Bool ?? true
        self.displayName = defaults.string(forKey: Keys.displayName) ?? "You"
        self.username = defaults.string(forKey: Keys.username) ?? "you"
        self.about = defaults.string(forKey: Keys.about) ?? "Available"
        self.isAppLocked = lockEnabled
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

    func signIn() {
        isAuthenticated = true
        isAppLocked = appLockEnabled
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
        isAuthenticated = false
        isAppLocked = false
        debugSkipToMain = false
    }
    #endif
}
