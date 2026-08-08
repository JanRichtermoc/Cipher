//
//  AttachmentImageView.swift
//  Cipher
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import SwiftUI

/// Decrypts and shows one attachment, fetching the blob the first time it is needed (P6.S04).
///
/// ## The plaintext lives here and nowhere else
///
/// The bytes are decrypted into this view's state and released when it goes away. Nothing above
/// it — not `Message`, not `ConversationStore` — ever holds a decoded photo, so scrolling past a
/// conversation does not accumulate plaintext images for the life of the process. The cost is
/// re-decrypting when a bubble comes back on screen, which is AES-GCM over a few megabytes and
/// is not what makes a list feel slow.
///
/// ## Failure is shown, never hidden
///
/// A blob that has expired on the relay, or one whose bytes did not match the digest the sender
/// authenticated, renders as a refusal rather than as a permanent spinner. `ConversationStore`
/// has already recorded the failure for the banner; this is the part of it that is attached to
/// the message it belongs to.
struct AttachmentImageView: View {
    @Environment(ConversationStore.self) private var store

    let message: Message
    /// Size of the rendered thumbnail. The full-screen viewer passes nil and fills instead.
    var thumbnailSize: CGSize?

    @State private var image: UIImage?
    @State private var didFail = false

    var body: some View {
        Group {
            if let image {
                Image(uiImage: image)
                    .resizable()
                    .aspectRatio(contentMode: thumbnailSize == nil ? .fit : .fill)
                    .frame(width: thumbnailSize?.width, height: thumbnailSize?.height)
                    .clipShape(RoundedRectangle(cornerRadius: thumbnailSize == nil ? 0 : 14,
                                                style: .continuous))
                    .accessibilityLabel("Photo")
            } else {
                placeholder
            }
        }
        // Keyed by the message so a recycled bubble cannot show the previous one's photo while
        // the new one is still decrypting.
        .task(id: message.id) {
            guard image == nil, !didFail else { return }
            let bytes = await store.attachmentBytes(for: message.id, in: message.chatID)
            guard let bytes, let decoded = UIImage(data: bytes) else {
                didFail = true
                return
            }
            image = decoded
        }
    }

    @ViewBuilder
    private var placeholder: some View {
        RoundedRectangle(cornerRadius: 14, style: .continuous)
            .fill(Color.black.opacity(0.12))
            .frame(width: thumbnailSize?.width ?? 200, height: thumbnailSize?.height ?? 140)
            .overlay {
                if didFail {
                    Image(systemName: "photo.badge.exclamationmark")
                        .font(.largeTitle)
                        .symbolRenderingMode(.hierarchical)
                        .foregroundStyle(.secondary)
                        .accessibilityLabel("Photo unavailable")
                } else {
                    ProgressView()
                        .accessibilityLabel("Decrypting photo")
                }
            }
    }
}
