//
//  CipherApp.swift
//  Cipher
//

import SwiftUI

@main
struct CipherApp: App {
    @State private var session = AppSession()
    @State private var store = ConversationStore()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(session)
                .environment(store)
                .tint(CipherTheme.accent)
        }
    }
}
