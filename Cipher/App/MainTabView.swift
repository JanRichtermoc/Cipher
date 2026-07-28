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

            Tab("Calls", systemImage: "phone.fill", value: MainTab.calls) {
                CallsListView()
            }

            Tab("Settings", systemImage: "gearshape.fill", value: MainTab.settings) {
                SettingsHubView()
            }
        }
        .tint(CipherTheme.accent)
    }
}

#Preview {
    MainTabView()
        .environment(AppSession())
        .environment(MockStore())
}
