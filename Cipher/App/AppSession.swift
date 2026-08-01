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
    /// The account-bound credential loaded from the Keychain.
    ///
    /// Not stored here and not settable. This used to be a `UserDefaults` bool, which meant
    /// the authentication gate was a plist entry in the app container — editable on a
    /// jailbroken device, or by anything with a file-write primitive, with no code execution
    /// needed at all. `SessionCredentialTests` proves that writing to `UserDefaults` can no
    /// longer produce a signed-in app.
    private(set) var credential: SessionCredential?

    var isAuthenticated: Bool {
        guard let credential else { return false }
        return credential.phase == .active && !credential.isExpired(at: now())
    }
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
    private let now: @Sendable () -> Date
    /// True when the Keychain contains bytes this build cannot safely bind to
    /// an account. Another invite stays unreachable until local state is erased.
    private var requiresAccountCleanup: Bool

    init(
        sessions: SessionStore = SessionStore(),
        defaults: UserDefaults = .standard,
        authenticator: DeviceAuthenticator = SystemDeviceAuthenticator(),
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.sessions = sessions
        self.authenticator = authenticator
        self.defaults = defaults
        self.now = now

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
        let storedCredential = sessions.current()
        self.credential = storedCredential
        self.requiresAccountCleanup =
            storedCredential == nil && sessions.hasStoredItem()
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
        case registration
        case profileSetup
        case accountCleanup
        case locked
        case main
    }

    var destination: Destination {
        if requiresAccountCleanup { return .accountCleanup }
        if let credential {
            if credential.isExpired(at: now()) || credential.phase == .destroying {
                return .accountCleanup
            }
            switch credential.phase {
            case .registering: return .registration
            case .profileSetup: return .profileSetup
            case .active: break
            case .destroying: return .accountCleanup
            }
        }
        #if DEBUG
        if debugSkipToMain { return .main }
        #endif
        guard hasCompletedOnboarding else { return .onboarding }
        guard credential != nil else { return .authentication }
        return isAppLocked ? .locked : .main
    }

    var showsMainApp: Bool { destination == .main }

    func completeOnboarding() {
        hasCompletedOnboarding = true
    }

    /// Persists the relay result before address adoption or publication begins.
    /// The UI remains behind `.registration`; a crash resumes there with the ACI
    /// and expiry needed to finish instead of discarding a single-use invite.
    func beginRegistration(with credential: SessionCredential) throws {
        guard !requiresAccountCleanup,
              self.credential == nil,
              credential.origin == .serverIssued,
              credential.phase == .registering,
              !credential.isExpired(at: now())
        else { throw SessionLifecycleError.invalidTransition }
        try sessions.store(credential)
        self.credential = credential
        isAppLocked = true
    }

    /// Records that address adoption and key publication both succeeded. Profile
    /// setup remains a real gate and is recoverable after a relaunch.
    func completeRegistration() throws {
        try transition(from: .registering, to: .profileSetup)
    }

    /// The only transition to an authenticated main UI.
    func completeProfileSetup(displayName: String, username: String) async throws {
        guard let profiles else { throw SessionLifecycleError.profileStorageUnavailable }
        let snapshot = ProfileArchive.StoredProfile(
            displayName: displayName, username: username, about: about)
        try await profiles.save(snapshot)
        isLoadingProfile = true
        self.displayName = snapshot.displayName
        self.username = snapshot.username
        isLoadingProfile = false
        try transition(from: .profileSetup, to: .active)
        isAppLocked = appLockEnabled
    }

    /// Replaces an active token after the server atomically rotated it.
    func adoptRotatedCredential(_ replacement: SessionCredential) throws {
        guard let current = credential,
              current.phase == .active,
              !current.isExpired(at: now()),
              replacement.origin == .serverIssued,
              replacement.phase == .active,
              replacement.aci == current.aci,
              replacement.expiresAt > current.expiresAt,
              !replacement.isExpired(at: now())
        else { throw SessionLifecycleError.invalidTransition }
        try sessions.store(replacement)
        credential = replacement
    }

    /// Rotate before the hard server expiry, while failure can still leave the
    /// existing credential usable. Rotation itself is never retried.
    private var isCredentialRotationInFlight = false
    var credentialRotationIsInFlight: Bool { isCredentialRotationInFlight }

    func beginCredentialRotationIfNeeded() -> SessionCredential? {
        guard !isCredentialRotationInFlight else { return nil }
        guard let credential,
              credential.phase == .active,
              !credential.isExpired(at: now()),
              credential.expiresAt.timeIntervalSince(now()) <= 7 * 24 * 60 * 60
        else { return nil }
        isCredentialRotationInFlight = true
        return credential
    }

    func endCredentialRotation() {
        isCredentialRotationInFlight = false
    }

    /// The delay used by RootView's expiry task. Reading the injected clock here
    /// keeps the timer and the authentication decision on the same time source.
    var credentialExpiryDelay: TimeInterval? {
        guard let credential, credential.phase != .destroying else { return nil }
        return max(0, credential.expiresAt.timeIntervalSince(now()))
    }

    /// Persists the destructive gate when a credential crosses its local
    /// expiry while the process remains foregrounded. Merely computing
    /// `destination` from `Date()` would not cause SwiftUI to re-evaluate it.
    func enforceCredentialExpiry() throws {
        guard let credential,
              credential.phase != .destroying,
              credential.isExpired(at: now()) else { return }
        try signOut()
    }

    private func transition(from expected: SessionCredential.Phase,
                            to next: SessionCredential.Phase) throws {
        guard let credential,
              credential.phase == expected,
              !credential.isExpired(at: now())
        else { throw SessionLifecycleError.invalidTransition }
        let replacement = credential.replacing(phase: next)
        try sessions.store(replacement)
        self.credential = replacement
    }

    #if DEBUG
    /// Signs in with a locally minted development credential.
    ///
    /// DEBUG only, and the credential it mints is marked `.development` in its stored bytes,
    /// so a Release build refuses it on read. There is deliberately no Release counterpart:
    /// a real credential comes only from redeeming an invite code against the relay (P5.S09).
    /// Minting something locally that *looked* like a production session would be exactly the
    /// fake token the plan forbids.
    func signInForDevelopment() throws {
        let credential = SessionCredential.development()
        try sessions.store(credential)
        self.credential = credential
        isAppLocked = appLockEnabled
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

    /// Starts sign-out by persisting the destructive gate before anything is
    /// erased. RootView then destroys protocol state, history and profile data;
    /// only after that succeeds is the credential removed.
    func signOut() throws {
        guard let credential else {
            if requiresAccountCleanup { return }
            return
        }
        guard credential.phase != .destroying else { return }
        // Hide the old account before touching the Keychain. If that write
        // fails, this process still remains behind the destructive gate.
        requiresAccountCleanup = true
        detachProfileStorage()
        let replacement = credential.replacing(phase: .destroying)
        try sessions.store(replacement)
        self.credential = replacement
        isAppLocked = true
    }

    /// A `WhenUnlocked` Keychain value can be temporarily unreadable if iOS
    /// prewarms the process before first unlock. Before treating undecodable
    /// bytes as legacy account state and erasing them, try once more from the
    /// visible cleanup screen. A genuinely malformed value remains unreadable
    /// and proceeds to cleanup.
    func recoverReadableCredentialBeforeCleanup() -> Bool {
        guard requiresAccountCleanup, credential == nil,
              let recovered = sessions.current() else { return false }
        credential = recovered
        requiresAccountCleanup = false
        return destination != .accountCleanup
    }

    /// Finishes erasure after ConversationStore has destroyed all account-bound
    /// state. Clearing first would make a new invite reachable while old history
    /// and ratchets were still present.
    func completeAccountCleanup() throws {
        try sessions.clear()
        credential = nil
        requiresAccountCleanup = false
        isAppLocked = false
        isCredentialRotationInFlight = false
        detachProfileStorage()
        isLoadingProfile = true
        displayName = ProfileDefault.displayName
        username = ProfileDefault.username
        about = ProfileDefault.about
        isLoadingProfile = false
    }

    // MARK: - Profile storage

    /// The sealed store for the three profile fields. `nil` until the engine is open.
    private var profiles: (any ProfileStoring)?
    var isProfileStorageReady: Bool { profiles != nil }

    /// One writer drains the latest pending snapshot. Separate `Task { save(...) }` calls are
    /// unordered at both actor hops and can let an older edit overwrite a newer one.
    private var pendingProfile: ProfileArchive.StoredProfile?
    private var profilePersistenceTask: Task<Void, Never>?
    /// Prevents a cancelled task from one account resuming after an `await` and touching the
    /// next account's queue. Incremented whenever profile storage is attached or detached.
    private var profilePersistenceGeneration: UInt64 = 0

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
        await adoptProfileStorage(ProfileArchive(engine: engine))
    }

    /// Internal dependency seam for the ordering test; production always calls the engine form.
    func adoptProfileStorage(_ archive: any ProfileStoring) async {
        guard profiles == nil else { return }

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
            profilePersistenceGeneration &+= 1
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
        pendingProfile = ProfileArchive.StoredProfile(
            displayName: displayName, username: username, about: about)
        guard profilePersistenceTask == nil else { return }

        let generation = profilePersistenceGeneration
        profilePersistenceTask = Task { [weak self, profiles] in
            guard let self else { return }
            await self.drainProfilePersistence(using: profiles, generation: generation)
        }
    }

    private func drainProfilePersistence(
        using profiles: any ProfileStoring, generation: UInt64
    ) async {
        while !Task.isCancelled, generation == profilePersistenceGeneration,
              let snapshot = pendingProfile
        {
            // New edits arriving while the save suspends replace this with one newer snapshot;
            // intermediate UI states need not become durable, but the final state must.
            pendingProfile = nil
            do {
                try await profiles.save(snapshot)
            } catch {
                AppLog.session.error("persisting the profile failed")
            }
        }

        guard generation == profilePersistenceGeneration else { return }
        profilePersistenceTask = nil
    }

    /// Waits until every profile mutation observed so far is durable. Internal so tests and
    /// lifecycle code can prove completion without timing sleeps.
    func flushProfilePersistence() async {
        while let task = profilePersistenceTask {
            await task.value
        }
    }

    private func detachProfileStorage() {
        profilePersistenceGeneration &+= 1
        pendingProfile = nil
        profilePersistenceTask?.cancel()
        profilePersistenceTask = nil
        profiles = nil
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
        requiresAccountCleanup = false
        isAppLocked = false
        debugSkipToMain = false
    }
    #endif
}

enum SessionLifecycleError: Error, Equatable {
    case invalidTransition
    case profileStorageUnavailable
}
