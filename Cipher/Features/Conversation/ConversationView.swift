//
//  ConversationView.swift
//  Cipher
//

import SwiftUI

struct ConversationView: View {
    @Environment(MockStore.self) private var store
    let chatID: UUID

    @State private var draft = ""
    @State private var replyTo: Message?
    @State private var showAttach = false
    @State private var showInfo = false
    @State private var showForward = false
    @State private var forwardingMessage: Message?
    @State private var mediaMessage: Message?
    @State private var showCall = false
    @State private var callKind: CallRecord.CallKind = .audio

    var body: some View {
        Group {
            if let chat = store.chat(id: chatID) {
                conversationBody(chat: chat)
            } else {
                EmptyStateView(
                    systemImage: "bubble.left",
                    title: "Chat Unavailable",
                    message: "This conversation was deleted."
                )
            }
        }
    }

    @ViewBuilder
    private func conversationBody(chat: Chat) -> some View {
        let messages = store.messages(for: chatID)

        ScrollViewReader { proxy in
            ZStack(alignment: .bottom) {
                // Soft backdrop so Liquid Glass has something to refract
                LinearGradient(
                    colors: [
                        Color(.systemBackground),
                        CipherTheme.accent.opacity(0.06),
                        Color(.systemBackground),
                    ],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                )
                .ignoresSafeArea()

                ScrollView {
                    LazyVStack(spacing: 10) {
                        ForEach(grouped(messages), id: \.day) { group in
                            DaySeparatorView(date: group.day)
                            ForEach(group.messages) { message in
                                MessageBubbleView(
                                    message: message,
                                    replyPreview: replyText(for: message),
                                    onReply: { replyTo = message },
                                    onReact: { emoji in
                                        store.addReaction(emoji, to: message.id)
                                        UIImpactFeedbackGenerator(style: .light).impactOccurred()
                                    },
                                    onForward: {
                                        forwardingMessage = message
                                        showForward = true
                                    },
                                    onDelete: { store.deleteMessage(message.id) },
                                    onOpenMedia: {
                                        mediaMessage = message
                                    }
                                )
                                .id(message.id)
                                .padding(.horizontal, CipherTheme.spacingM)
                            }
                        }

                        if store.typingChatIDs.contains(chatID) {
                            HStack {
                                TypingIndicatorView()
                                Spacer()
                            }
                            .padding(.horizontal, CipherTheme.spacingM)
                            .id("typing")
                        }

                        Color.clear
                            .frame(height: 72)
                            .id("bottom")
                    }
                    .padding(.vertical, CipherTheme.spacingS)
                }
                .scrollContentBackground(.hidden)
                .background(.clear)
                .scrollDismissesKeyboard(.interactively)
                .onAppear {
                    store.markRead(chatID: chatID)
                    proxy.scrollTo("bottom", anchor: .bottom)
                }
                .onChange(of: messages.count) { _, _ in
                    withAnimation {
                        proxy.scrollTo("bottom", anchor: .bottom)
                    }
                }

                ComposerBar(
                    text: $draft,
                    replyPreview: replyTo.flatMap { preview(for: $0) },
                    onClearReply: { replyTo = nil },
                    onSend: send,
                    onAttach: { showAttach = true }
                )
            }
        }
        .navigationBarTitleDisplayMode(.inline)
        .toolbar(.hidden, for: .tabBar)
        .toolbar {
            ToolbarItem(placement: .principal) {
                VStack(spacing: 2) {
                    HStack(spacing: 4) {
                        Text(chat.title).font(.headline)
                        if chat.isVerified { VerifiedBadge(compact: true) }
                    }
                    if let seconds = chat.disappearingSeconds {
                        DisappearingTimerBadge(seconds: seconds)
                    } else if let contact = store.otherParticipant(in: chat), contact.isOnline {
                        Text("Online").font(.caption2).foregroundStyle(.secondary)
                    }
                }
            }
            ToolbarItemGroup(placement: .topBarTrailing) {
                Button {
                    callKind = .audio
                    showCall = true
                } label: {
                    Image(systemName: "phone")
                }
                .accessibilityLabel("Audio call")

                Button {
                    callKind = .video
                    showCall = true
                } label: {
                    Image(systemName: "video")
                }
                .accessibilityLabel("Video call")

                Button {
                    showInfo = true
                } label: {
                    Image(systemName: "info.circle")
                }
                .accessibilityLabel("Chat info")
            }
        }
        .sheet(isPresented: $showInfo) {
            NavigationStack {
                if chat.isGroup {
                    GroupInfoView(chatID: chatID)
                } else {
                    ChatInfoView(chatID: chatID)
                }
            }
        }
        .sheet(isPresented: $showAttach) {
            AttachmentSheet()
                .presentationDetents([.medium])
        }
        .sheet(isPresented: $showForward) {
            ForwardMessageView(message: forwardingMessage) {
                showForward = false
            }
        }
        .fullScreenCover(item: $mediaMessage) { message in
            MediaViewer(message: message)
        }
        .fullScreenCover(isPresented: $showCall) {
            if let contact = store.otherParticipant(in: chat) ?? store.contacts.first {
                ActiveCallView(contact: contact, kind: callKind, mode: .outgoing) {
                    showCall = false
                }
            }
        }
    }

    private func send() {
        store.sendText(draft, to: chatID, replyTo: replyTo?.id)
        draft = ""
        replyTo = nil
        UIImpactFeedbackGenerator(style: .medium).impactOccurred()
    }

    private func preview(for message: Message) -> String {
        switch message.kind {
        case .text(let t): return t
        case .emoji(let e): return e
        case .image(_, let c): return c ?? String(localized: "Photo")
        case .voice: return String(localized: "Voice message")
        case .file(let n, _): return n
        case .link(_, let title, _): return title
        case .system(let s): return s
        }
    }

    private func replyText(for message: Message) -> String? {
        guard let replyID = message.replyToID,
              let original = store.messages.first(where: { $0.id == replyID }) else { return nil }
        return preview(for: original)
    }

    private struct DayGroup {
        let day: Date
        let messages: [Message]
    }

    private func grouped(_ messages: [Message]) -> [DayGroup] {
        let calendar = Calendar.current
        let dict = Dictionary(grouping: messages) { msg in
            calendar.startOfDay(for: msg.date)
        }
        return dict.keys.sorted().map { DayGroup(day: $0, messages: dict[$0]!.sorted { $0.date < $1.date }) }
    }
}

struct AttachmentSheet: View {
    @Environment(\.dismiss) private var dismiss

    private var items: [(LocalizedStringKey, String)] {
        [
            ("Photo Library", "photo.on.rectangle"),
            ("Camera", "camera"),
            ("File", "doc"),
            ("Location", "location"),
            ("Contact", "person.crop.circle"),
        ]
    }

    var body: some View {
        NavigationStack {
            List {
                ForEach(Array(items.enumerated()), id: \.offset) { _, item in
                    Button {
                        dismiss()
                    } label: {
                        Label(item.0, systemImage: item.1)
                    }
                }
            }
            .navigationTitle("Attach")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") { dismiss() }
                }
            }
        }
    }
}

#Preview {
    NavigationStack {
        ConversationView(chatID: UUID(uuidString: "10000000-0000-0000-0000-000000000001")!)
    }
    .environment(MockStore())
}
