//
//  ContentView.swift
//  Cipher
//

import SwiftUI

/// Kept for Xcode template compatibility; app entry uses `RootView` via `CipherApp`.
struct ContentView: View {
    var body: some View {
        RootView()
    }
}

#if DEBUG
#Preview {
    ContentView()
        .environment(AppSession())
        .environment(ConversationStore.preview())
}
#endif
