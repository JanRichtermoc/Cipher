//
//  ForwardMessageView.swift
//  Cipher
//

import SwiftUI

struct ForwardMessageView: View {
    @Environment(MockStore.self) private var store
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
                        if let message, case .text(let text) = message.kind {
                            for id in selected {
                                store.sendText(text, to: id)
                            }
                        } else if let message {
                            for id in selected {
                                store.sendText(forwardLabel(for: message), to: id)
                            }
                        }
                        onDone()
                        dismiss()
                    }
                    .disabled(selected.isEmpty)
                }
            }
        }
    }

    private func forwardLabel(for message: Message) -> String {
        switch message.kind {
        case .text(let t): return t
        case .emoji(let e): return e
        case .image: return String(localized: "Forwarded photo")
        case .voice: return String(localized: "Forwarded voice message")
        case .file(let n, _): return String(localized: "Forwarded file: \(n)")
        case .link(_, let title, _): return String(localized: "Forwarded link: \(title)")
        case .system(let s): return s
        }
    }
}
