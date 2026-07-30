//
//  NewMessageView.swift
//  Cipher
//

import SwiftUI

/// Starting a conversation: paste the other person's Cipher ID.
///
/// ## There is no contact list to pick from, and that is the design
///
/// Server-side contact discovery is a standing prohibition (`THREAT_MODEL.md` §4.3) — it is
/// historically the largest metadata leak in messengers that have it, and the relay deliberately
/// holds no username, no phone number, and no profile of any kind (`BACKEND.md` §2.1). So there
/// is nothing to search: a peer is reachable only if someone gave you their identifier out of
/// band, which is the same trust step as comparing a safety number in person.
///
/// The "Contacts" list below is therefore just the conversations that already exist. It is not a
/// directory and does not pretend to be one.
struct NewMessageView: View {
    @Environment(ConversationStore.self) private var store
    @Environment(\.dismiss) private var dismiss
    @State private var identifier = ""
    @State private var nickname = ""
    @State private var isStarting = false

    var onCreated: (Chat) -> Void

    /// Whether the field holds something that could be an identifier. Nothing here judges
    /// whether the account *exists* — only the relay can answer that, and it deliberately
    /// answers "no bundle available" the same way for an unknown account as for an empty prekey
    /// pool, so there is no enumeration oracle to build a "check this ID" button on.
    private var parsedIdentifier: UUID? {
        UUID(uuidString: identifier.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    var body: some View {
        NavigationStack {
            List {
                // See ChatsListView: group creation is DEBUG-only until groups have an
                // encryption path (plan §0.2.2, P10.S02).
                #if DEBUG
                Section {
                    NavigationLink {
                        Text("Use New Group from the compose menu.")
                            .foregroundStyle(.secondary)
                    } label: {
                        Label("New Group", systemImage: "person.3.fill")
                    }
                }
                #endif

                Section {
                    TextField("Cipher ID", text: $identifier)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .font(.body.monospaced())
                    TextField("Name (only on this device)", text: $nickname)
                        .textInputAutocapitalization(.words)
                    Button(isStarting ? "Starting…" : "Start Conversation") {
                        start()
                    }
                    .disabled(parsedIdentifier == nil || isStarting)
                } header: {
                    Text("New conversation")
                } footer: {
                    Text("Cipher has no contact directory — the server stores no names. Ask the other person for their Cipher ID from Settings, and give them yours.")
                }

                if !store.contacts.isEmpty {
                    Section("Contacts") {
                        ForEach(store.contacts) { contact in
                            Button {
                                if let chat = store.chat(id: contact.id) { onCreated(chat) }
                            } label: {
                                HStack(spacing: CipherTheme.spacingM) {
                                    AvatarView(
                                        initials: contact.initials,
                                        color: contact.accentColor,
                                        size: CipherTheme.avatarS,
                                        isOnline: contact.isOnline,
                                        isVerified: contact.isVerified
                                    )
                                    VStack(alignment: .leading) {
                                        Text(contact.name)
                                            .foregroundStyle(.primary)
                                        Text(contact.username)
                                            .font(.caption.monospaced())
                                            .foregroundStyle(.secondary)
                                    }
                                }
                            }
                        }
                    }
                }
            }
            .navigationTitle("New Message")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
    }

    private func start() {
        guard let peer = parsedIdentifier else { return }
        isStarting = true
        Task {
            defer { isStarting = false }
            // No prekey fetch happens here: the bundle is fetched on the first send, because a
            // fetch consumes one of the peer's one-time prekeys and spends this device's
            // rate-limit budget (AUDIT 3.1). Opening a conversation must not do that.
            if let chat = await store.startConversation(with: peer, nickname: nickname) {
                onCreated(chat)
            }
        }
    }
}

// Group creation has no encryption path (plan §0.2.2, AUDIT 3.7). Kept intact for P10.S02
// rather than deleted, but unreachable in a shipping build.
#if DEBUG
struct NewGroupView: View {
    @Environment(ConversationStore.self) private var store
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var selected: Set<UUID> = []
    @State private var search = ""

    var onCreated: (Chat) -> Void

    var body: some View {
        NavigationStack {
            Form {
                Section("Group Name") {
                    TextField("Name", text: $name)
                    HStack {
                        Spacer()
                        AvatarView(
                            initials: String(name.prefix(2)).uppercased().nilIfEmpty ?? "GR",
                            color: CipherTheme.accent,
                            size: CipherTheme.avatarL
                        )
                        Spacer()
                    }
                    .listRowBackground(Color.clear)
                }

                Section("Members") {
                    ForEach(filteredContacts) { contact in
                        Button {
                            if selected.contains(contact.id) {
                                selected.remove(contact.id)
                            } else {
                                selected.insert(contact.id)
                            }
                        } label: {
                            HStack {
                                AvatarView(
                                    initials: contact.initials,
                                    color: contact.accentColor,
                                    size: CipherTheme.avatarS,
                                    isVerified: contact.isVerified
                                )
                                Text(contact.name)
                                    .foregroundStyle(.primary)
                                Spacer()
                                Image(systemName: selected.contains(contact.id) ? "checkmark.circle.fill" : "circle")
                                    .foregroundStyle(selected.contains(contact.id) ? CipherTheme.accent : .secondary)
                            }
                        }
                    }
                }
            }
            .searchable(text: $search, prompt: "Search")
            .navigationTitle("New Group")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    // DEBUG-only, and now genuinely inert: there is no group creation on the
                    // store because there is no sender-key path to create one with (AUDIT 3.7).
                    // The screen survives for P10.S02; the button dismisses.
                    Button("Create") { dismiss() }
                        .disabled(
                            name.trimmingCharacters(in: .whitespaces).isEmpty || selected.isEmpty)
                }
            }
        }
    }

    private var filteredContacts: [Contact] {
        if search.isEmpty { return store.contacts }
        return store.contacts.filter { $0.name.localizedCaseInsensitiveContains(search) }
    }
}

#endif

private extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}

#if DEBUG
#Preview {
    NewMessageView { _ in }
        .environment(ConversationStore.preview())
}
#endif
