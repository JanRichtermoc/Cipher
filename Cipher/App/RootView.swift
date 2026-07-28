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

#Preview {
    RootView()
        .environment(AppSession())
        .environment(MockStore())
}
