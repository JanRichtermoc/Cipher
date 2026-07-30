//
//  ForwardMessageView.swift
//  Cipher
//

import SwiftUI

struct ForwardMessageView: View {
    @Environment(ConversationStore.self) private var store
    @Environment(\.dismiss) private var dismiss
    var message: Message?
    var onDone: () -> Void

    @State private var selected: Set<UUID> = []

    var body: some View {
        NavigationStack {
            List {
                ForEach(store.chats) { chat in
                    Button {
                        if selected.contains(chat.id) {
                            selected.remove(chat.id)
                        } else {
                            selected.insert(chat.id)
                        }
                    } label: {
                        HStack {
                            AvatarView(
                                initials: chat.avatarInitials,
                                color: chat.accentColor,
                                size: CipherTheme.avatarS
                            )
                            Text(chat.title).foregroundStyle(.primary)
                            Spacer()
                            Image(systemName: selected.contains(chat.id) ? "checkmark.circle.fill" : "circle")
                                .foregroundStyle(selected.contains(chat.id) ? CipherTheme.accent : .secondary)
                        }
                    }
                }
            }
            .navigationTitle("Forward")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Send") {
                        // Forwarding is just sending the same text again — a fresh encryption to
                        // each recipient, which is what the ratchet requires anyway. There is no
                        // "forwarded" marker on the wire and none is invented here.
                        //
                        // Only text is forwardable, because text is the only payload type that
                        // exists. The previous version substituted a label like "Forwarded
                        // photo" for other kinds, which sent a sentence *about* a message
                        // instead of the message.
                        if let message, let text = Self.forwardableText(message) {
                            let targets = selected
                            Task {
                                for id in targets { await store.send(text, to: id) }
                            }
                        }
                        onDone()
                        dismiss()
                    }
                    .disabled(selected.isEmpty || Self.forwardableText(message) == nil)
                }
            }
        }
    }

    /// The text a message can be forwarded as, or nil if it is not forwardable.
    ///
    /// A system note is excluded deliberately: it was written by this device about the
    /// conversation, so forwarding it would present local UI copy as something the user said.
    private static func forwardableText(_ message: Message?) -> String? {
        switch message?.kind {
        case .text(let value), .emoji(let value): return value
        default: return nil
        }
    }
}
