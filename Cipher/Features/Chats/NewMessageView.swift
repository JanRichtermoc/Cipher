//
//  NewMessageView.swift
//  Cipher
//

import SwiftUI

struct NewMessageView: View {
    @Environment(MockStore.self) private var store
    @Environment(\.dismiss) private var dismiss
    @State private var search = ""

    var onCreated: (Chat) -> Void

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

                Section("Contacts") {
                    ForEach(filteredContacts) { contact in
                        Button {
                            let chat = store.createDirectChat(with: contact)
                            onCreated(chat)
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
                                    Text("@\(contact.username)")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                }
            }
            .searchable(text: $search, prompt: "Search contacts")
            .navigationTitle("New Message")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
    }

    private var filteredContacts: [Contact] {
        if search.isEmpty { return store.contacts }
        return store.contacts.filter {
            $0.name.localizedCaseInsensitiveContains(search)
                || $0.username.localizedCaseInsensitiveContains(search)
        }
    }
}

// Group creation has no encryption path (plan §0.2.2, AUDIT 3.7). Kept intact for P10.S02
// rather than deleted, but unreachable in a shipping build.
#if DEBUG
struct NewGroupView: View {
    @Environment(MockStore.self) private var store
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
                    Button("Create") {
                        let members = store.contacts.filter { selected.contains($0.id) }
                        let chat = store.createGroup(name: name.trimmingCharacters(in: .whitespaces), members: members)
                        onCreated(chat)
                    }
                    .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty || selected.isEmpty)
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

#Preview {
    NewMessageView { _ in }
        .environment(MockStore())
}
