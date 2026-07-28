//
//  UICatalogView.swift
//  Cipher
//

import SwiftUI

#if DEBUG
struct UICatalogView: View {
    @Environment(MockStore.self) private var store
    @Environment(AppSession.self) private var session

    var body: some View {
        List {
            Section("Flows") {
                NavigationLink("Welcome") { WelcomeView(onContinue: {}) }
                NavigationLink("Privacy Carousel") { PrivacyCarouselView(onContinue: {}) }
                NavigationLink("App Lock") { AppLockView() }
                NavigationLink("Incoming Call") {
                    if let c = store.contacts.first {
                        IncomingCallView(contact: c) { _ in }
                    }
                }
            }

            Section("Chats") {
                ForEach(store.chats.prefix(3)) { chat in
                    NavigationLink(chat.title) {
                        ConversationView(chatID: chat.id)
                    }
                }
            }

            Section("Components") {
                HStack {
                    AvatarView(initials: "AC", color: .teal, size: 48, isOnline: true, isVerified: true)
                    UnreadBadge(count: 3)
                    VerifiedBadge()
                    DisappearingTimerBadge(seconds: 3600)
                }
                PrimaryGlassButton(title: "Glass Button") {}
                SecondaryGlassButton(title: "Secondary Glass") {}
                TypingIndicatorView()
            }

            Section("Demo Controls") {
                Button("Unlock & Show Main") {
                    session.debugSkipToMain = true
                    session.hasCompletedOnboarding = true
                    try? session.signInForDevelopment()
                    session.debugUnlockWithoutAuthentication()
                }
                Button("Reset Onboarding", role: .destructive) {
                    session.resetDemoState()
                }
            }
        }
        .navigationTitle("UI Catalog")
    }
}
#endif
