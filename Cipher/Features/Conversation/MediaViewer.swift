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
                    if case .photo = message.kind {
                        AttachmentImageView(message: message, thumbnailSize: nil)
                            .padding(.horizontal, CipherTheme.spacingM)
                    }
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
                // A share sheet and a forward button used to sit here with empty actions. They
                // were reachable only from DEBUG fixtures until P6.S04 made this screen show a
                // real decrypted photo, at which point two controls that do nothing would be
                // shipping — and sharing a decrypted attachment out of the app is a decision
                // that needs a design, not a button (plan §0.6: fix deceptive UI first).
            }
            .toolbarBackground(.hidden, for: .navigationBar)
        }
    }
}
