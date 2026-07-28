//
//  RootView.swift
//  Cipher
//

import SwiftUI

struct RootView: View {
    @Environment(AppSession.self) private var session
    @Environment(MockStore.self) private var store

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
    }
}

#Preview {
    RootView()
        .environment(AppSession())
        .environment(MockStore())
}
