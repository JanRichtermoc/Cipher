//
//  MediaViewer.swift
//  Cipher
//

import SwiftUI

struct MediaViewer: View {
    let message: Message
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ZStack {
                Color.black.ignoresSafeArea()

                VStack(spacing: CipherTheme.spacingL) {
                    Spacer()
                    if case .image(let name, _) = message.kind {
                        Image(systemName: name)
                            .font(.system(size: 120))
                            .foregroundStyle(.white.opacity(0.9))
                            .symbolRenderingMode(.hierarchical)
                    }
                    if case .image(_, let caption) = message.kind, let caption {
                        Text(caption)
                            .foregroundStyle(.white)
                            .font(.headline)
                    }
                    Text(CipherDateFormatting.messageTime(message.date))
                        .foregroundStyle(.white.opacity(0.6))
                        .font(.caption)
                    Spacer()
                }
            }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") { dismiss() }
                        .foregroundStyle(.white)
                }
                ToolbarItemGroup(placement: .topBarTrailing) {
                    Button {} label: { Image(systemName: "square.and.arrow.up") }
                    Button {} label: { Image(systemName: "arrowshape.turn.up.forward") }
                }
            }
            .toolbarBackground(.hidden, for: .navigationBar)
        }
    }
}
