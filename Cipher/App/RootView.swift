//
//  RootView.swift
//  Cipher
//

import SwiftUI

struct RootView: View {
    @Environment(AppSession.self) private var session
    @Environment(MockStore.self) private var store
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
        .onChange(of: scenePhase) { _, phase in
            if phase != .active { session.lockIfNeeded() }
        }
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

#Preview {
    RootView()
        .environment(AppSession())
        .environment(MockStore())
}
