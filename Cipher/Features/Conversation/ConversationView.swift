//
//  ConversationView.swift
//  Cipher
//

import SwiftUI

struct ConversationView: View {
    @Environment(ConversationStore.self) private var store
    let chatID: UUID

    @State private var draft = ""
    @State private var replyTo: Message?
    @State private var showAttach = false
    @State private var showInfo = false
    @State private var showForward = false
    @State private var forwardingMessage: Message?
    @State private var mediaMessage: Message?
    #if DEBUG
    @State private var showCall = false
    @State private var callKind: CallRecord.CallKind = .audio
    #endif

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
                                    onReact: { _ in
                                        // Reactions have no wire representation; the picker that
                                        // calls this is DEBUG-only. See MessageBubbleView.
                                    },
                                    onForward: {
                                        forwardingMessage = message
                                        showForward = true
                                    },
                                    onDelete: {
                                        Task { await store.deleteMessage(message.id, in: chatID) }
                                    },
                                    onOpenMedia: {
                                        mediaMessage = message
                                    }
                                )
                                .id(message.id)
                                .padding(.horizontal, CipherTheme.spacingM)
                            }
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
                    proxy.scrollTo("bottom", anchor: .bottom)
                }
                .task(id: chatID) { await store.markRead(chatID: chatID) }
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
        .safeAreaInset(edge: .top) { MessagingFailureBanner() }
        .navigationBarTitleDisplayMode(.inline)
        .toolbar(.hidden, for: .tabBar)
        .toolbar {
            ToolbarItem(placement: .principal) {
                VStack(spacing: 2) {
                    HStack(spacing: 4) {
                        Text(chat.title).font(.headline)
                        if chat.isVerified { VerifiedBadge(compact: true) }
                    }
                    // No presence: nothing on the wire reports whether a peer is online, so
                    // there is nothing here but the disappearing-message timer when it is set.
                    if let seconds = chat.disappearingSeconds {
                        DisappearingTimerBadge(seconds: seconds)
                    }
                }
            }
            ToolbarItemGroup(placement: .topBarTrailing) {
                // Calls are DEBUG-only: there is no signalling and no media path, so a phone
                // button in a shipping build is a control that cannot do what it depicts.
                #if DEBUG
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
                #endif

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
                // No production conversation is a group (AUDIT 3.7), so the group screen exists
                // only where the DEBUG fixtures can reach it.
                #if DEBUG
                if chat.isGroup {
                    GroupInfoView(chatID: chatID)
                } else {
                    ChatInfoView(chatID: chatID)
                }
                #else
                ChatInfoView(chatID: chatID)
                #endif
            }
        }
        #if DEBUG
        .sheet(isPresented: $showAttach) {
            AttachmentSheet()
                .presentationDetents([.medium])
        }
        #endif
        .sheet(isPresented: $showForward) {
            ForwardMessageView(message: forwardingMessage) {
                showForward = false
            }
        }
        .fullScreenCover(item: $mediaMessage) { message in
            MediaViewer(message: message)
        }
        #if DEBUG
        .fullScreenCover(isPresented: $showCall) {
            if let contact = store.otherParticipant(in: chat) ?? store.contacts.first {
                ActiveCallView(contact: contact, kind: callKind, mode: .outgoing) {
                    showCall = false
                }
            }
        }
        #endif
    }

    private func send() {
        let outgoing = draft
        // Cleared before the await, so the composer empties immediately and a second tap cannot
        // send the same text twice while the first attempt is in flight.
        draft = ""
        replyTo = nil
        UIImpactFeedbackGenerator(style: .medium).impactOccurred()
        Task { await store.send(outgoing, to: chatID) }
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
              let original = store.message(id: replyID, in: chatID) else { return nil }
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

// Attachments have no client path: the relay's blob endpoints exist (P4.S08) but nothing here
// uploads, encrypts, or references one, and `MessagePayload` carries text only. The sheet listed
// five sources and dismissed — five controls that did nothing — so it is DEBUG-only until the
// payload type and the upload exist.
#if DEBUG
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
#endif

#if DEBUG
#Preview {
    NavigationStack {
        ConversationView(chatID: ConversationStore.previewChatID)
    }
    .environment(ConversationStore.preview())
}
#endif
