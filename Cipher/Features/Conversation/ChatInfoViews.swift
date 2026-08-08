//
//  ChatInfoViews.swift
//  Cipher
//

import SwiftUI

struct ChatInfoView: View {
    @Environment(ConversationStore.self) private var store
    @Environment(\.dismiss) private var dismiss
    let chatID: UUID

    @State private var confirmBlock = false
    @State private var confirmClear = false
    @State private var nickname = ""
    @State private var showSafetyNumber = false

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
                    Text(chat.title).font(.title2.bold())
                }
                .frame(maxWidth: .infinity)
                .listRowBackground(Color.clear)
            }

            // The identifier, in full, with no attempt to dress it up as a profile. It is the
            // only thing about this peer that is a fact rather than a local label — the relay
            // stores no name, no username and no "about" for anyone (`BACKEND.md` §2.1).
            Section {
                LabeledContent("Cipher ID") {
                    Text(chat.id.uuidString.lowercased())
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                }
                Button("Copy Cipher ID", systemImage: "doc.on.doc") {
                    SecurePasteboard.copy(chat.id.uuidString.lowercased())
                }
            }

            // The safety number sits directly under the Cipher ID, because the two answer
            // adjacent questions: which account this is, and whether the key behind it is
            // the one the person actually holds. A verified badge elsewhere in the app is
            // only meaningful if this screen is one tap away from wherever it appears.
            Section {
                Button {
                    showSafetyNumber = true
                } label: {
                    LabeledContent("Safety number") {
                        if contact.isVerified {
                            Label("Verified", systemImage: "checkmark.seal.fill")
                                .labelStyle(.titleAndIcon)
                                .foregroundStyle(CipherTheme.accent)
                        } else {
                            Text("Not verified")
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                .tint(.primary)
            } footer: {
                Text("Compare the number with this contact to confirm no one is intercepting your messages.")
            }

            Section {
                TextField("Name (only on this device)", text: $nickname)
                    .textInputAutocapitalization(.words)
                    .onSubmit { Task { await store.rename(chatID: chatID, to: nickname) } }
            } footer: {
                Text("Names are stored only on this device, inside the encrypted container. Nothing is sent to the server.")
            }

            // Attachments have no client path, so a media gallery could only ever be empty.
            #if DEBUG
            Section("Media") {
                MediaGalleryGrid(chatID: chatID)
            }
            #endif

            Section {
                Toggle(isOn: muteBinding(chat)) {
                    Label("Mute", systemImage: "bell.slash")
                }
                Picker(selection: disappearingBinding(chat)) {
                    Text("Off").tag(Int?.none)
                    ForEach(ConversationStore.disappearingOptions, id: \.self) { seconds in
                        Text(Self.disappearingLabel(seconds)).tag(Int?.some(seconds))
                    }
                } label: {
                    Label("Disappearing Messages", systemImage: "timer")
                }
            } header: {
                Text("Options")
            } footer: {
                // Precise about who it governs and what it cannot promise, because both halves
                // are load-bearing. The timer travels with each message this device sends, so
                // the recipient's copy goes too — but nothing here changes what *they* send,
                // and nothing anywhere can stop someone screenshotting what they were given.
                // `THREAT_MODEL.md` §1.5 calls this a courtesy rather than a control, and this
                // is where the app has to say so.
                Text(
                    "Applies to messages you send. Both copies are deleted when the timer ends. "
                        + "It cannot stop someone saving a message another way.")
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
        .onAppear { nickname = chat.title }
        .sheet(isPresented: $showSafetyNumber) {
            SafetyNumberView(peer: contact.id, peerName: contact.name)
        }
        .confirmationDialog("Block \(contact.name)?", isPresented: $confirmBlock) {
            Button(store.blockedContactIDs.contains(contact.id) ? "Unblock" : "Block", role: .destructive) {
                Task { await store.toggleBlock(contact.id) }
            }
        }
        .confirmationDialog("Clear all messages?", isPresented: $confirmClear) {
            Button("Clear", role: .destructive) {
                Task { await store.clearMessages(chatID: chatID) }
            }
        }
    }

    private func muteBinding(_ chat: Chat) -> Binding<Bool> {
        Binding(
            get: { chat.isMuted },
            set: { _ in Task { await store.toggleMute(chatID: chat.id) } }
        )
    }

    private func disappearingBinding(_ chat: Chat) -> Binding<Int?> {
        Binding(
            get: { chat.disappearingSeconds },
            set: { seconds in
                Task { await store.setDisappearing(seconds: seconds, chatID: chat.id) }
            }
        )
    }

    /// The duration, spelled out by `DateComponentsFormatter` rather than by a hand-written
    /// literal, so the units follow the reader's locale instead of an English assumption. One
    /// unit only: "1 day" reads as a choice, "1 day, 0 hours" reads as a bug.
    private static func disappearingLabel(_ seconds: Int) -> String {
        let formatter = DateComponentsFormatter()
        formatter.allowedUnits = [.day, .hour, .minute, .second]
        formatter.unitsStyle = .full
        formatter.maximumUnitCount = 1
        return formatter.string(from: TimeInterval(seconds)) ?? "\(seconds)s"
    }

}

// Groups do not exist cryptographically (AUDIT 3.7) and no production conversation is a group,
// so this screen is unreachable in a shipping build. DEBUG-only rather than deleted: P10.S02
// builds groups properly and this is the interface it will need.
#if DEBUG
struct GroupInfoView: View {
    @Environment(ConversationStore.self) private var store
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
                            set: { _ in Task { await store.toggleMute(chatID: chat.id) } }
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
                        Task { await store.deleteChat(chatID: chatID) }
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
                    isVerified: false,
                    isOnline: false,
                    about: ""
                )
            }
            return store.contact(id: id)
        }
    }
}

struct MediaGalleryGrid: View {
    @Environment(ConversationStore.self) private var store
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

#endif
