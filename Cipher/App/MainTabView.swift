//
//  MainTabView.swift
//  Cipher
//

import SwiftUI

struct MainTabView: View {
    @State private var selectedTab: MainTab = .chats

    enum MainTab: Hashable {
        case chats
        case calls
        case settings
    }

    var body: some View {
        TabView(selection: $selectedTab) {
            Tab("Chats", systemImage: "bubble.left.and.bubble.right.fill", value: MainTab.chats) {
                ChatsListView()
            }

            // Calls are DEBUG-only, on the same grounds as group creation (AUDIT 5.5): there is
            // no call implementation at all — no signalling, no media path, nothing in
            // `Envelope` that could carry one — so a Calls tab in a shipping build offers a
            // control that cannot work and, until P5.S10, showed fabricated call history to
            // make it look like it could. The screens stay for the phase that builds calls.
            #if DEBUG
            Tab("Calls", systemImage: "phone.fill", value: MainTab.calls) {
                CallsListView()
            }
            #endif

            Tab("Settings", systemImage: "gearshape.fill", value: MainTab.settings) {
                SettingsHubView()
            }
        }
        .tint(CipherTheme.accent)
    }
}

#if DEBUG
#Preview {
    MainTabView()
        .environment(AppSession())
        .environment(ConversationStore.preview())
}
#endif
