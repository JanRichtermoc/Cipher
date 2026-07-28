//
//  ChatInfoViews.swift
//  Cipher
//

import SwiftUI

struct ChatInfoView: View {
    @Environment(MockStore.self) private var store
    @Environment(\.dismiss) private var dismiss
    let chatID: UUID

    @State private var showSafety = false
    @State private var confirmBlock = false
    @State private var confirmClear = false
    @State private var disappearing: Int = 0

    var body: some View {
        Group {
            if let chat = store.chat(id: chatID),
               let contact = store.otherParticipant(in: chat) {
                content(chat: chat, contact: contact)
            } else {
                EmptyStateView(systemImage: "person", title: "Unavailable", message: "Contact not found.")
            }
        }
    }

    @ViewBuilder
    private func content(chat: Chat, contact: Contact) -> some View {
        List {
            Section {
                VStack(spacing: 12) {
                    AvatarView(
                        initials: contact.initials,
                        color: contact.accentColor,
                        size: CipherTheme.avatarXL,
                        isOnline: contact.isOnline,
                        isVerified: contact.isVerified
                    )
                    Text(contact.name).font(.title2.bold())
                    Text("@\(contact.username)").foregroundStyle(.secondary)
                    Text(contact.about).font(.subheadline).foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity)
                .listRowBackground(Color.clear)
            }

            Section("Media") {
                MediaGalleryGrid(chatID: chatID)
            }

            Section("Options") {
                Toggle(isOn: muteBinding(chat)) {
                    Label("Mute", systemImage: "bell.slash")
                }
                Picker(selection: disappearingBinding(chat)) {
                    Text("Off").tag(0)
                    Text("1 hour").tag(3600)
                    Text("1 day").tag(86_400)
                    Text("1 week").tag(604_800)
                } label: {
                    Label("Disappearing Messages", systemImage: "timer")
                }
            }

            Section("Security") {
                Button {
                    showSafety = true
                } label: {
                    Label("Verify Safety Number", systemImage: "qrcode")
                }
            }

            Section {
                Button("Clear Chat", role: .destructive) { confirmClear = true }
                Button(store.blockedContactIDs.contains(contact.id) ? "Unblock" : "Block", role: .destructive) {
                    confirmBlock = true
                }
            }
        }
        .navigationTitle("Info")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Done") { dismiss() }
            }
        }
        .sheet(isPresented: $showSafety) {
            SafetyNumberView(contact: contact)
        }
        .confirmationDialog("Block \(contact.name)?", isPresented: $confirmBlock) {
            Button(store.blockedContactIDs.contains(contact.id) ? "Unblock" : "Block", role: .destructive) {
                store.toggleBlock(contact.id)
            }
        }
        .confirmationDialog("Clear all messages?", isPresented: $confirmClear) {
            Button("Clear", role: .destructive) {
                store.messages.removeAll { $0.chatID == chatID }
            }
        }
    }

    private func muteBinding(_ chat: Chat) -> Binding<Bool> {
        Binding(
            get: { chat.isMuted },
            set: { _ in store.toggleMute(chatID: chat.id) }
        )
    }

    private func disappearingBinding(_ chat: Chat) -> Binding<Int> {
        Binding(
            get: { chat.disappearingSeconds ?? 0 },
            set: { value in
                if let i = store.chats.firstIndex(where: { $0.id == chat.id }) {
                    store.chats[i].disappearingSeconds = value == 0 ? nil : value
                }
            }
        )
    }
}

struct GroupInfoView: View {
    @Environment(MockStore.self) private var store
    @Environment(\.dismiss) private var dismiss
    let chatID: UUID
    @State private var confirmLeave = false

    var body: some View {
        Group {
            if let chat = store.chat(id: chatID) {
                List {
                    Section {
                        VStack(spacing: 12) {
                            AvatarView(
                                initials: chat.avatarInitials,
                                color: chat.accentColor,
                                size: CipherTheme.avatarXL
                            )
                            Text(chat.title).font(.title2.bold())
                            Text("\(chat.participantIDs.count) members")
                                .foregroundStyle(.secondary)
                        }
                        .frame(maxWidth: .infinity)
                        .listRowBackground(Color.clear)
                    }

                    Section("Media") {
                        MediaGalleryGrid(chatID: chatID)
                    }

                    Section("Members") {
                        ForEach(members(of: chat)) { contact in
                            HStack {
                                AvatarView(
                                    initials: contact.initials,
                                    color: contact.accentColor,
                                    size: CipherTheme.avatarS,
                                    isOnline: contact.isOnline,
                                    isVerified: contact.isVerified
                                )
                                VStack(alignment: .leading) {
                                    Text(contact.name)
                                    Text("@\(contact.username)").font(.caption).foregroundStyle(.secondary)
                                }
                            }
                        }
                    }

                    Section {
                        Toggle(isOn: Binding(
                            get: { chat.isMuted },
                            set: { _ in store.toggleMute(chatID: chat.id) }
                        )) {
                            Label("Mute", systemImage: "bell.slash")
                        }
                    }

                    Section {
                        Button("Leave Group", role: .destructive) { confirmLeave = true }
                    }
                }
                .navigationTitle("Group Info")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Done") { dismiss() }
                    }
                }
                .confirmationDialog("Leave this group?", isPresented: $confirmLeave) {
                    Button("Leave", role: .destructive) {
                        store.deleteChat(chatID: chatID)
                        dismiss()
                    }
                }
            }
        }
    }

    private func members(of chat: Chat) -> [Contact] {
        chat.participantIDs.compactMap { id in
            if id == store.currentUserID {
                return Contact(
                    id: id,
                    name: String(localized: "You"),
                    username: "you",
                    initials: "YO",
                    accentHue: 0.5,
                    isVerified: true,
                    isOnline: true,
                    about: ""
                )
            }
            return store.contact(id: id)
        }
    }
}

struct MediaGalleryGrid: View {
    @Environment(MockStore.self) private var store
    let chatID: UUID

    private var media: [Message] {
        store.messages(for: chatID).filter {
            if case .image = $0.kind { return true }
            return false
        }
    }

    var body: some View {
        if media.isEmpty {
            Text("No media yet")
                .foregroundStyle(.secondary)
        } else {
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 72), spacing: 8)], spacing: 8) {
                ForEach(media) { message in
                    if case .image(let name, _) = message.kind {
                        RoundedRectangle(cornerRadius: 10, style: .continuous)
                            .fill(Color(.tertiarySystemFill))
                            .frame(height: 72)
                            .overlay {
                                Image(systemName: name)
                                    .font(.title2)
                                    .foregroundStyle(.secondary)
                            }
                    }
                }
            }
            .padding(.vertical, 4)
        }
    }
}

struct SafetyNumberView: View {
    let contact: Contact
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: CipherTheme.spacingXL) {
                    AvatarView(
                        initials: contact.initials,
                        color: contact.accentColor,
                        size: CipherTheme.avatarL,
                        isVerified: contact.isVerified
                    )

                    Text("Safety number with \(contact.name)")
                        .font(.title3.bold())
                        .multilineTextAlignment(.center)

                    // No QR code, no digits, and no "Mark as Verified" until these are
                    // derived from real identity keys (P5.S12).
                    //
                    // What stood here was a hardcoded array of twelve digit blocks under the
                    // words "If these numbers match on both devices, your connection is
                    // secure". Because the constants were the same on every install, two
                    // users comparing them would always match — the screen did not fail to
                    // verify, it actively certified an unverified connection, and it would
                    // have passed a careful user's check. An empty state is strictly safer
                    // than a confident wrong answer.
                    RoundedRectangle(cornerRadius: 16, style: .continuous)
                        .fill(Color(.secondarySystemBackground))
                        .frame(width: 200, height: 200)
                        .overlay {
                            Image(systemName: "qrcode.viewfinder")
                                .font(.system(size: 72))
                                .foregroundStyle(.tertiary)
                        }
                        .accessibilityHidden(true)

                    UnimplementedNotice(
                        "Safety numbers are not implemented yet. Nothing on this screen is derived from your keys, so there is nothing here to compare — do not treat this conversation as verified."
                    )
                    .padding(.horizontal)
                }
                .padding(.vertical)
            }
            .navigationTitle("Safety Number")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") { dismiss() }
                }
            }
        }
    }
}
