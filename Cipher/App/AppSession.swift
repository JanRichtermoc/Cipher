//
//  AppSession.swift
//  Cipher
//

import CipherCrypto
import Foundation
import os
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
    /// `private(set)`: the lock is cleared by `unlock(reason:)` after a successful
    /// device-owner check, and by nothing else in a shipping build. It used to be a plain
    /// `var`, so four call sites set it directly — the lock's only real authority was that
    /// nobody happened to write that line.
    private(set) var isAppLocked: Bool

    var appLockEnabled: Bool {
        didSet {
            defaults.set(appLockEnabled, forKey: Keys.appLock)
            // Turning the lock off clears it. The alternative is a locked screen with the
            // feature disabled and no way through, which is a lockout, not a control.
            if !appLockEnabled { isAppLocked = false }
        }
    }
    var defaultDisappearingSeconds: Int {
        didSet { defaults.set(defaultDisappearingSeconds, forKey: Keys.disappearing) }
    }
    var notificationPreviewsEnabled: Bool {
        didSet { defaults.set(notificationPreviewsEnabled, forKey: Keys.previews) }
    }
    /// The local user's own profile fields.
    ///
    /// **Sealed, not in `UserDefaults`** since P5.S11 — see `ProfileArchive` and AUDIT 4.7. They
    /// persist through `profiles`, which is attached once the engine is open; before that they
    /// hold the placeholders below and writing to them persists nothing, which is why
    /// `adoptProfileStorage` loads before anything can render an editor.
    var displayName: String {
        didSet { persistProfile() }
    }
    var username: String {
        didSet { persistProfile() }
    }
    var about: String {
        didSet { persistProfile() }
    }

    /// Shown until the sealed profile has been read, and used for a fresh installation.
    ///
    /// Deliberately not "" — an empty display name renders as a blank row rather than as
    /// something the user recognises as not-yet-set.
    private enum ProfileDefault {
        static let displayName = "You"
        static let username = "you"
        static let about = "Available"
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
        static let disappearing = "cipher.defaultDisappearing"
        static let previews = "cipher.notificationPreviews"
        static let displayName = "cipher.displayName"
        static let username = "cipher.username"
        static let about = "cipher.about"
    }

    private let sessions: SessionStore
    private let authenticator: DeviceAuthenticator
    /// Injected so a test can use a scratch suite. `UserDefaults.standard` is process-wide,
    /// so tests that shared it leaked onboarding state into each other and passed or failed
    /// on run order — which is how a suite starts being re-run until it goes green.
    private let defaults: UserDefaults

    init(
        sessions: SessionStore = SessionStore(),
        defaults: UserDefaults = .standard,
        authenticator: DeviceAuthenticator = SystemDeviceAuthenticator()
    ) {
        self.sessions = sessions
        self.authenticator = authenticator
        self.defaults = defaults

        // A build that predates this carries `cipher.isAuthenticated` in UserDefaults. It is
        // no longer read, but leaving it would be a stale flag that looks meaningful to the
        // next person to open the plist — and to anyone reasoning about what an attacker
        // could reach. Removed on first launch of any build that has this line.
        defaults.removeObject(forKey: "cipher.isAuthenticated")

        // The screenshot-warning toggle was removed outright rather than implemented: iOS
        // can report that a screenshot was taken, but cannot prevent one, so the control
        // could only ever have told a user something had already happened. A setting whose
        // honest description is "this does nothing you can act on" is worse than no setting.
        // Its stored value goes too, so it cannot look meaningful to a future reader.
        defaults.removeObject(forKey: "cipher.screenshotWarning")

        let lockEnabled = defaults.object(forKey: Keys.appLock) as? Bool ?? false
        self.hasCompletedOnboarding = defaults.bool(forKey: Keys.onboarding)
        self.appLockEnabled = lockEnabled
        self.defaultDisappearingSeconds = defaults.object(forKey: Keys.disappearing) as? Int ?? 0
        self.notificationPreviewsEnabled = defaults.object(forKey: Keys.previews) as? Bool ?? true
        // Placeholders. The real values are sealed in the container and arrive via
        // `adoptProfileStorage`, which also moves anything a pre-P5.S11 build left in the plist
        // and then deletes it. They are not read from `defaults` here even as a fallback: doing
        // so would keep the plist as a live source and the migration would never be the only
        // reader, which is how a retired store stays alive indefinitely.
        self.displayName = ProfileDefault.displayName
        self.username = ProfileDefault.username
        self.about = ProfileDefault.about
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

    #if DEBUG
    /// Unlocks without a device-owner check.
    ///
    /// DEBUG only. The simulator can be configured for biometry but a unit test cannot drive
    /// it, and a UI spike should not require a passcode on every launch. Fenced with the
    /// mechanism, not just the button — P1.S07 exists because fencing only the caller still
    /// ships the switch.
    func debugUnlockWithoutAuthentication() {
        isAppLocked = false
    }
    #endif

    /// Signs out and destroys the credential.
    func signOut() throws {
        try sessions.clear()
        credential = nil
        isAppLocked = false

        // Profile fields go too: leaving a display name and an "about" behind after sign-out
        // means the device still says who used it. Sealed since P5.S11 (AUDIT 4.7), so this
        // deletes the sealed row rather than blanking a plist entry.
        //
        // The in-memory values are reset first and the row is deleted after, without waiting:
        // `signOut` is synchronous because it must not be able to fail half way and leave a
        // signed-out app holding a credential. The row's deletion is not load-bearing for that
        // — the record is sealed under a key this device still holds either way, and a
        // subsequent sign-in overwrites it — so making it a `Task` is a latency decision, not a
        // security one.
        displayName = ProfileDefault.displayName
        username = ProfileDefault.username
        about = ProfileDefault.about
        if let profiles {
            Task {
                do {
                    try await profiles.clear()
                } catch {
                    AppLog.session.error("clearing the stored profile on sign-out failed")
                }
            }
        }
    }

    // MARK: - Profile storage

    /// The sealed store for the three profile fields. `nil` until the engine is open.
    private var profiles: ProfileArchive?

    /// Suppresses the `didSet` writes while `adoptProfileStorage` populates the fields, so
    /// loading a profile does not immediately write it back.
    private var isLoadingProfile = false

    /// Attaches sealed storage, loads the profile, and retires the `UserDefaults` copy.
    ///
    /// Called once the engine is open. Migration is part of the same pass on purpose: reading
    /// the plist and deleting it must not be separable, or a build that crashed between them
    /// would leave the fields in both places, with the unencrypted one still authoritative for
    /// anyone reading the container.
    func adoptProfileStorage(engine: CryptoEngine) async {
        guard profiles == nil else { return }
        let archive = ProfileArchive(engine: engine)

        do {
            let stored = try await archive.load()
            let legacy = legacyProfileFromDefaults()

            isLoadingProfile = true
            if let stored {
                displayName = stored.displayName
                username = stored.username
                about = stored.about
            } else if let legacy {
                displayName = legacy.displayName
                username = legacy.username
                about = legacy.about
            }
            isLoadingProfile = false

            // A pre-P5.S11 build's values are written into the sealed store before the plist
            // keys are removed, so an interruption leaves them readable rather than gone.
            if stored == nil, let legacy {
                try await archive.save(legacy)
            }
            removeLegacyProfileFromDefaults()

            profiles = archive
        } catch {
            // Deliberately not fatal and deliberately not silent. The fields keep their
            // placeholders and nothing persists, which is visibly wrong in the profile editor
            // rather than quietly wrong on disk.
            isLoadingProfile = false
            AppLog.session.error("opening the sealed profile store failed")
        }
    }

    private func persistProfile() {
        guard !isLoadingProfile, let profiles else { return }
        let snapshot = ProfileArchive.StoredProfile(
            displayName: displayName, username: username, about: about)
        Task {
            do {
                try await profiles.save(snapshot)
            } catch {
                AppLog.session.error("persisting the profile failed")
            }
        }
    }

    /// The three fields as a pre-P5.S11 build left them, or `nil` if it never wrote any.
    private func legacyProfileFromDefaults() -> ProfileArchive.StoredProfile? {
        let name = defaults.string(forKey: Keys.displayName)
        let user = defaults.string(forKey: Keys.username)
        let about = defaults.string(forKey: Keys.about)
        guard name != nil || user != nil || about != nil else { return nil }
        return ProfileArchive.StoredProfile(
            displayName: name ?? ProfileDefault.displayName,
            username: user ?? ProfileDefault.username,
            about: about ?? ProfileDefault.about)
    }

    private func removeLegacyProfileFromDefaults() {
        defaults.removeObject(forKey: Keys.displayName)
        defaults.removeObject(forKey: Keys.username)
        defaults.removeObject(forKey: Keys.about)
    }

    /// Whether the device can perform the owner check at all.
    ///
    /// A device with no passcode cannot, and the setting is disabled rather than offered —
    /// a lock the device cannot enforce is the deceptive-UI case P1.S05 was about.
    var canUseAppLock: Bool { authenticator.isAvailable }

    /// Unlocks **only** on a successful device-owner check.
    ///
    /// There is no non-throwing variant and no caller-supplied override. The previous
    /// `unlock()` set `isAppLocked = false` unconditionally, so the "Unlock" button *was*
    /// the lock's only authority — the `LAContext` it advertised never existed (AUDIT 5.8,
    /// C-03).
    ///
    /// Cancel and error both leave the app locked. That is the whole point: the classic
    /// version of this bug is treating a dismissed prompt as consent, and it is invisible
    /// in manual testing because the happy path looks identical.
    func unlock(reason: String) async throws {
        try await authenticator.authenticate(reason: reason)
        isAppLocked = false
    }

    /// Engages the lock if it is enabled.
    ///
    /// Called on every move out of the foreground, not only from a button. Until P3.S02 it
    /// had exactly one caller — a manual "Lock Now" — so the lock engaged on cold launch and
    /// never again: backgrounding the app and returning left it unlocked (AUDIT 5.8).
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
