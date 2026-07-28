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

#Preview {
    ContentView()
        .environment(AppSession())
        .environment(MockStore())
}
