//
//  RootView.swift
//  Cipher
//

import SwiftUI

struct RootView: View {
    @Environment(AppSession.self) private var session
    @Environment(ConversationStore.self) private var store
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        // Switches on `AppSession.destination` rather than restating the condition. This
        // view is what actually decides whether the main app renders, so it must not hold a
        // second copy of the gate that can drift from the first.
        Group {
            switch session.destination {
            case .main:
                MainTabView()
            case .locked:
                AppLockView()
            case .authentication:
                AuthFlowView()
            case .registration:
                RegistrationRecoveryView()
            case .profileSetup:
                NavigationStack { ProfileSetupView() }
            case .accountCleanup:
                AccountCleanupView()
            case .onboarding:
                OnboardingFlowView()
            }
        }
        // P3.S04 — cover the UI whenever the app is not frontmost.
        //
        // iOS photographs the window to build the app-switcher card, and that image is
        // written to disk in the app's own container. Without this the card — and the file
        // — is whatever conversation was open. It is the one screenshot of your messages
        // that the system takes for you, on every switch away, with no user action.
        //
        // Separate from the app lock on purpose. The lock is opt-in and only re-locks when
        // enabled; this runs unconditionally, because the snapshot happens either way.
        .overlay {
            if scenePhase != .active {
                SnapshotRedaction()
                    .transition(.opacity)
            }
        }
        .animation(.smooth, value: session.destination)
        // Hand the session its sealed profile storage as soon as the engine is open (P5.S11,
        // AUDIT 4.7). Here rather than in `CipherApp` because the store owns the engine and
        // opening it is async and throwing; here rather than in `SettingsView` because the
        // migration off `UserDefaults` must run whether or not the user visits that screen.
        //
        // A failure is not surfaced: `adoptProfileStorage` logs and leaves the placeholder
        // values in place, and a device that cannot open its own container has a larger problem
        // that the messaging path reports for real.
        .task(id: session.destination) {
            guard session.destination == .profileSetup ||
                    session.destination == .main ||
                    session.destination == .locked else { return }
            guard let engine = try? await store.engine() else { return }
            await session.adoptProfileStorage(engine: engine)
        }
        // The other half of the app lock, and the half that was missing.
        //
        // `lockIfNeeded()` used to have exactly one caller — a "Lock Now" button in Settings
        // — so with the lock enabled the app locked on cold launch and never again:
        // background it, come back, still unlocked (AUDIT 5.8). Re-locking has to be driven
        // by the system's own notion of leaving the foreground, not by the user remembering.
        //
        // On `.inactive`, not `.background`. `.inactive` is what the app enters while the
        // switcher snapshot is taken, so locking here means the snapshot is of the lock
        // screen. Waiting for `.background` would put the last visible screen — a
        // conversation — into the switcher and into the snapshot on disk.
        //
        // Returning to the foreground is also the only "new mail" signal this build has. Push
        // notifications are P7.S03; until then a conversation left open does not update on its
        // own, which is a real limitation and not one worth papering over with a timer polling a
        // rate-limited endpoint. Both halves live in one `onChange` so the lock and the fetch
        // cannot end up reading different notions of "not frontmost".
        .onChange(of: scenePhase) { _, phase in
            if phase != .active {
                session.lockIfNeeded()
            } else {
                try? session.enforceCredentialExpiry()
                if session.destination == .main {
                    Task { await synchronize() }
                }
            }
        }
        .onChange(of: store.failure) { _, failure in
            // A revoked/expired token is not a transient messaging error. Move
            // behind the persisted destructive gate so no prior-account history
            // remains visible while the user is asked to authenticate again.
            if failure == .sessionRejected {
                try? session.signOut()
            }
        }
        // The messaging path is started here rather than in `ChatsListView`, because it has to
        // run whether or not that screen is on top: an installation whose prekey publication
        // failed cannot receive a first message from anyone, and the only symptom is other
        // people's session setup failing. `id:` restarts it when the gate opens, so nothing
        // touches the relay while the app is behind the lock or the invite screen.
        .task(id: session.destination) {
            guard session.destination == .main else { return }
            await synchronize()
        }
        // `Date()` is not observable. Wake exactly when the current credential
        // expires so an app left foregrounded cannot keep rendering account data
        // until some unrelated state change happens to rebuild this view.
        .task(id: session.credential?.expiresAt) {
            guard let delay = session.credentialExpiryDelay else { return }
            if delay > 0 {
                try? await Task.sleep(for: .seconds(delay))
            }
            guard !Task.isCancelled else { return }
            try? session.enforceCredentialExpiry()
        }
    }

    private func synchronize() async {
        if let current = session.beginCredentialRotationIfNeeded() {
            defer { session.endCredentialRotation() }
            do {
                let replacement = try await SessionLifecycle().rotate(current)
                try session.adoptRotatedCredential(replacement)
            } catch SessionLifecycle.Failure.rejected {
                try? session.signOut()
                return
            } catch {
                // The old token remains valid and stored. Rotation will be
                // attempted again on the next foreground transition.
            }
        } else if session.credentialRotationIsInFlight {
            // Another root task is consuming the old token. Using it for a
            // mailbox fetch in parallel could receive a legitimate 401 after
            // rotation commits and incorrectly trigger account destruction.
            return
        }
        guard session.destination == .main else { return }
        await store.start()
    }
}

/// What the app-switcher card shows instead of your messages.
///
/// Deliberately opaque and deliberately not a blur: a blur of legible text at switcher size
/// can still be read, and `UIBlurEffect` renders from the very content being hidden.
private struct SnapshotRedaction: View {
    var body: some View {
        ZStack {
            Rectangle()
                .fill(.background)
            Image(systemName: "lock.circle.fill")
                .font(.system(size: 56))
                .foregroundStyle(CipherTheme.accent)
        }
        .ignoresSafeArea()
    }
}

#if DEBUG
#Preview {
    RootView()
        .environment(AppSession())
        .environment(ConversationStore.preview())
}
#endif
