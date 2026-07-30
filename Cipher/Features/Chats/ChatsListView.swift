//
//  ChatsListView.swift
//  Cipher
//

import SwiftUI

struct ChatsListView: View {
    @Environment(ConversationStore.self) private var store
    @State private var filter: ChatFilter = .all
    @State private var path = NavigationPath()
    @State private var showNewMessage = false
    @State private var showNewGroup = false
    @State private var showGlobalSearch = false

    enum ChatFilter: CaseIterable, Identifiable {
        case all
        case unread
        case groups
        var id: Self { self }

        var title: LocalizedStringKey {
            switch self {
            case .all: "All"
            case .unread: "Unread"
            case .groups: "Groups"
            }
        }
    }

    var body: some View {
        NavigationStack(path: $path) {
            Group {
                if filteredChats.isEmpty {
                    EmptyStateView(
                        systemImage: "bubble.left.and.bubble.right",
                        title: emptyTitle,
                        message: emptyMessage,
                        actionTitle: "New Message",
                        action: { showNewMessage = true }
                    )
                } else {
                    ScrollView {
                        LazyVStack(spacing: 0) {
                            ForEach(Array(filteredChats.enumerated()), id: \.element.id) { index, chat in
                                Button {
                                    path.append(chat.id)
                                } label: {
                                    ChatRowView(chat: chat)
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                        .padding(.horizontal, 16)
                                        .padding(.vertical, 10)
                                        .contentShape(Rectangle())
                                }
                                .buttonStyle(.plain)
                                .contextMenu {
                                    Button(chat.isPinned ? "Unpin" : "Pin", systemImage: chat.isPinned ? "pin.slash" : "pin") {
                                        Task { await store.togglePin(chatID: chat.id) }
                                    }
                                    Button(chat.isMuted ? "Unmute" : "Mute", systemImage: chat.isMuted ? "bell" : "bell.slash") {
                                        Task { await store.toggleMute(chatID: chat.id) }
                                    }
                                    Button("Mark Unread", systemImage: "message.badge") {
                                        Task { await store.markUnread(chatID: chat.id) }
                                    }
                                    // Deletes this device's copy and nothing else. The peer keeps
                                    // theirs, and the relay has already forgotten anything that
                                    // was delivered — there is no "delete for everyone".
                                    Button("Delete", systemImage: "trash", role: .destructive) {
                                        Task { await store.deleteChat(chatID: chat.id) }
                                    }
                                }
                                if index < filteredChats.count - 1 {
                                    Divider()
                                        .padding(.leading, 16 + CipherTheme.avatarM + CipherTheme.spacingM)
                                }
                            }
                        }
                        .padding(.top, 4)
                    }
                }
            }
            .safeAreaInset(edge: .top) { MessagingFailureBanner() }
            .refreshable { await store.receive() }
            .navigationTitle("Chats")
            .navigationDestination(for: UUID.self) { chatID in
                if store.chat(id: chatID) != nil {
                    ConversationView(chatID: chatID)
                }
            }
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Menu {
                        Picker("Filter", selection: $filter) {
                            ForEach(ChatFilter.allCases) { item in
                                Text(item.title).tag(item)
                            }
                        }
                    } label: {
                        Image(systemName: "line.3.horizontal.decrease")
                    }
                    .accessibilityLabel("Filter chats")
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        showGlobalSearch = true
                    } label: {
                        Image(systemName: "magnifyingglass")
                    }
                    .accessibilityLabel("Search messages")
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button("New Message", systemImage: "square.and.pencil") {
                            showNewMessage = true
                        }
                        // Group messaging has no encryption path: SenderKeyStore is
                        // deliberately unimplemented and sender-key payloads are rejected at
                        // the wire boundary (plan §0.2.2, AUDIT 3.7). Offering group creation
                        // invites a future wiring that would have nothing to encrypt with.
                        // The screens survive for P10, where groups get built properly.
                        #if DEBUG
                        Button("New Group", systemImage: "person.3") {
                            showNewGroup = true
                        }
                        #endif
                    } label: {
                        Image(systemName: "square.and.pencil")
                    }
                    .accessibilityLabel("Compose")
                }
            }
            .sheet(isPresented: $showNewMessage) {
                NewMessageView { chat in
                    showNewMessage = false
                    path.append(chat.id)
                }
            }
            #if DEBUG
            .sheet(isPresented: $showNewGroup) {
                NewGroupView { chat in
                    showNewGroup = false
                    path.append(chat.id)
                }
            }
            #endif
            .sheet(isPresented: $showGlobalSearch) {
                GlobalSearchView { chatID in
                    showGlobalSearch = false
                    path.append(chatID)
                }
            }
        }
    }

    private var filteredChats: [Chat] {
        store.chats.filter { chat in
            switch filter {
            case .all: break
            case .unread: if chat.unreadCount == 0 { return false }
            case .groups: if !chat.isGroup { return false }
            }
            return true
        }
    }

    private var emptyTitle: LocalizedStringKey {
        switch filter {
        case .all: "No Chats Yet"
        case .unread: "No Unread Chats"
        case .groups: "No Groups"
        }
    }

    private var emptyMessage: LocalizedStringKey {
        switch filter {
        case .all: "Start a private conversation with someone you trust."
        case .unread: "You're all caught up."
        case .groups: "Create a group for your circle."
        }
    }
}

struct ChatRowView: View {
    let chat: Chat

    var body: some View {
        HStack(spacing: CipherTheme.spacingM) {
            AvatarView(
                initials: chat.avatarInitials,
                color: chat.accentColor,
                size: CipherTheme.avatarM,
                isVerified: chat.isVerified && !chat.isGroup
            )

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(chat.title)
                        .font(.headline)
                        .lineLimit(1)
                    if chat.isPinned {
                        Image(systemName: "pin.fill")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    if chat.isMuted {
                        Image(systemName: "bell.slash.fill")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    if chat.disappearingSeconds != nil {
                        Image(systemName: "timer")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    Spacer(minLength: 8)
                    Text(CipherDateFormatting.chatList(chat.lastMessageDate))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                HStack(alignment: .center, spacing: 8) {
                    Text(chat.lastMessagePreview)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                    Spacer(minLength: 8)
                    UnreadBadge(count: chat.unreadCount)
                }
            }
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
    }
}

#if DEBUG
#Preview("Chats Light") {
    ChatsListView()
        .environment(AppSession())
        .environment(ConversationStore.preview())
        .preferredColorScheme(.light)
}

#Preview("Chats Dark") {
    ChatsListView()
        .environment(AppSession())
        .environment(ConversationStore.preview())
        .preferredColorScheme(.dark)
}
#endif
