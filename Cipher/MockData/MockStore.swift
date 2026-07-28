//
//  MockStore.swift
//  Cipher
//

import Foundation
import SwiftUI

@Observable
final class MockStore {
    var currentUserID: UUID
    var contacts: [Contact]
    var chats: [Chat]
    var messages: [Message]
    var calls: [CallRecord]
    var linkedDevices: [LinkedDevice]
    var blockedContactIDs: Set<UUID>
    var typingChatIDs: Set<UUID>

    init() {
        let me = UUID(uuidString: "00000000-0000-0000-0000-000000000001")!
        currentUserID = me

        let alice = Contact(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000002")!,
            name: "Alice Chen",
            username: "alice",
            initials: "AC",
            accentHue: 0.55,
            isVerified: true,
            isOnline: true,
            about: "Building quietly"
        )
        let bob = Contact(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000003")!,
            name: "Bob Novak",
            username: "bobn",
            initials: "BN",
            accentHue: 0.08,
            isVerified: true,
            isOnline: false,
            about: "Coffee first"
        )
        let cara = Contact(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000004")!,
            name: "Cara Wells",
            username: "cara",
            initials: "CW",
            accentHue: 0.78,
            isVerified: false,
            isOnline: true,
            about: "Design & film"
        )
        let diego = Contact(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000005")!,
            name: "Diego Ruiz",
            username: "diego",
            initials: "DR",
            accentHue: 0.33,
            isVerified: true,
            isOnline: false,
            about: "On a hike"
        )
        let emma = Contact(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000006")!,
            name: "Emma Park",
            username: "emmap",
            initials: "EP",
            accentHue: 0.92,
            isVerified: false,
            isOnline: true,
            about: "Say hi"
        )
        let farah = Contact(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000007")!,
            name: "Farah Ali",
            username: "farah",
            initials: "FA",
            accentHue: 0.15,
            isVerified: true,
            isOnline: false,
            about: "Encrypted always"
        )

        contacts = [alice, bob, cara, diego, emma, farah]

        let chatAlice = UUID(uuidString: "10000000-0000-0000-0000-000000000001")!
        let chatBob = UUID(uuidString: "10000000-0000-0000-0000-000000000002")!
        let chatGroup = UUID(uuidString: "10000000-0000-0000-0000-000000000003")!
        let chatCara = UUID(uuidString: "10000000-0000-0000-0000-000000000004")!
        let chatDiego = UUID(uuidString: "10000000-0000-0000-0000-000000000005")!
        let chatEmma = UUID(uuidString: "10000000-0000-0000-0000-000000000006")!

        let now = Date()
        chats = [
            Chat(
                id: chatAlice,
                title: alice.name,
                isGroup: false,
                participantIDs: [me, alice.id],
                lastMessagePreview: "Meet at 6? Keys rotated 🔐",
                lastMessageDate: now.addingTimeInterval(-120),
                unreadCount: 2,
                isPinned: true,
                isMuted: false,
                isVerified: true,
                disappearingSeconds: 60 * 60 * 24,
                avatarInitials: alice.initials,
                accentHue: alice.accentHue
            ),
            Chat(
                id: chatGroup,
                title: "Weekend Crew",
                isGroup: true,
                participantIDs: [me, alice.id, bob.id, cara.id, diego.id],
                lastMessagePreview: "Bob: Bringing the projector",
                lastMessageDate: now.addingTimeInterval(-1800),
                unreadCount: 5,
                isPinned: true,
                isMuted: false,
                isVerified: false,
                disappearingSeconds: nil,
                avatarInitials: "WC",
                accentHue: 0.48
            ),
            Chat(
                id: chatBob,
                title: bob.name,
                isGroup: false,
                participantIDs: [me, bob.id],
                lastMessagePreview: "Voice message",
                lastMessageDate: now.addingTimeInterval(-7200),
                unreadCount: 0,
                isPinned: false,
                isMuted: false,
                isVerified: true,
                disappearingSeconds: nil,
                avatarInitials: bob.initials,
                accentHue: bob.accentHue
            ),
            Chat(
                id: chatCara,
                title: cara.name,
                isGroup: false,
                participantIDs: [me, cara.id],
                lastMessagePreview: "Loved the draft — sending notes",
                lastMessageDate: now.addingTimeInterval(-20_000),
                unreadCount: 0,
                isPinned: false,
                isMuted: true,
                isVerified: false,
                disappearingSeconds: 60 * 60 * 7,
                avatarInitials: cara.initials,
                accentHue: cara.accentHue
            ),
            Chat(
                id: chatDiego,
                title: diego.name,
                isGroup: false,
                participantIDs: [me, diego.id],
                lastMessagePreview: "Photo",
                lastMessageDate: now.addingTimeInterval(-86_400),
                unreadCount: 1,
                isPinned: false,
                isMuted: false,
                isVerified: true,
                disappearingSeconds: nil,
                avatarInitials: diego.initials,
                accentHue: diego.accentHue
            ),
            Chat(
                id: chatEmma,
                title: emma.name,
                isGroup: false,
                participantIDs: [me, emma.id],
                lastMessagePreview: "You: See you tomorrow!",
                lastMessageDate: now.addingTimeInterval(-172_800),
                unreadCount: 0,
                isPinned: false,
                isMuted: false,
                isVerified: false,
                disappearingSeconds: nil,
                avatarInitials: emma.initials,
                accentHue: emma.accentHue
            ),
        ]

        messages = Self.seedMessages(
            me: me,
            alice: alice,
            bob: bob,
            cara: cara,
            diego: diego,
            chatAlice: chatAlice,
            chatBob: chatBob,
            chatGroup: chatGroup,
            chatCara: chatCara,
            chatDiego: chatDiego,
            chatEmma: chatEmma,
            now: now
        )

        calls = [
            CallRecord(id: UUID(), contactID: alice.id, contactName: alice.name, initials: alice.initials, accentHue: alice.accentHue, direction: .outgoing, kind: .video, date: now.addingTimeInterval(-3600), durationSeconds: 842),
            CallRecord(id: UUID(), contactID: bob.id, contactName: bob.name, initials: bob.initials, accentHue: bob.accentHue, direction: .missed, kind: .audio, date: now.addingTimeInterval(-10_000), durationSeconds: nil),
            CallRecord(id: UUID(), contactID: cara.id, contactName: cara.name, initials: cara.initials, accentHue: cara.accentHue, direction: .incoming, kind: .audio, date: now.addingTimeInterval(-50_000), durationSeconds: 312),
            CallRecord(id: UUID(), contactID: diego.id, contactName: diego.name, initials: diego.initials, accentHue: diego.accentHue, direction: .outgoing, kind: .audio, date: now.addingTimeInterval(-100_000), durationSeconds: 95),
            CallRecord(id: UUID(), contactID: farah.id, contactName: farah.name, initials: farah.initials, accentHue: farah.accentHue, direction: .missed, kind: .video, date: now.addingTimeInterval(-200_000), durationSeconds: nil),
        ]

        linkedDevices = [
            LinkedDevice(id: UUID(), name: String(localized: "This iPhone"), lastActiveLabel: String(localized: "Active now"), isCurrent: true),
            LinkedDevice(id: UUID(), name: "iPad Pro", lastActiveLabel: String(localized: "2 hours ago"), isCurrent: false),
            LinkedDevice(id: UUID(), name: "MacBook Air", lastActiveLabel: String(localized: "Yesterday"), isCurrent: false),
        ]

        blockedContactIDs = []
        typingChatIDs = []
    }

    func contact(id: UUID) -> Contact? {
        contacts.first { $0.id == id }
    }

    func chat(id: UUID) -> Chat? {
        chats.first { $0.id == id }
    }

    func messages(for chatID: UUID) -> [Message] {
        messages
            .filter { $0.chatID == chatID }
            .sorted { $0.date < $1.date }
    }

    func otherParticipant(in chat: Chat) -> Contact? {
        guard !chat.isGroup else { return nil }
        guard let otherID = chat.participantIDs.first(where: { $0 != currentUserID }) else { return nil }
        return contact(id: otherID)
    }

    func togglePin(chatID: UUID) {
        guard let i = chats.firstIndex(where: { $0.id == chatID }) else { return }
        chats[i].isPinned.toggle()
        sortChats()
    }

    func toggleMute(chatID: UUID) {
        guard let i = chats.firstIndex(where: { $0.id == chatID }) else { return }
        chats[i].isMuted.toggle()
    }

    func markUnread(chatID: UUID) {
        guard let i = chats.firstIndex(where: { $0.id == chatID }) else { return }
        chats[i].unreadCount = max(1, chats[i].unreadCount)
    }

    func markRead(chatID: UUID) {
        guard let i = chats.firstIndex(where: { $0.id == chatID }) else { return }
        chats[i].unreadCount = 0
    }

    func deleteChat(chatID: UUID) {
        chats.removeAll { $0.id == chatID }
        messages.removeAll { $0.chatID == chatID }
    }

    func sendText(_ text: String, to chatID: UUID, replyTo: UUID? = nil) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        let kind: MessageKind = trimmed.count <= 3 && trimmed.unicodeScalars.allSatisfy { $0.properties.isEmoji } ? .emoji(trimmed) : .text(trimmed)
        let message = Message(
            id: UUID(),
            chatID: chatID,
            senderID: currentUserID,
            kind: kind,
            date: Date(),
            status: .sent,
            isFromCurrentUser: true,
            replyToID: replyTo,
            reactions: [:]
        )
        messages.append(message)
        if let i = chats.firstIndex(where: { $0.id == chatID }) {
            chats[i].lastMessagePreview = trimmed
            chats[i].lastMessageDate = message.date
        }
        sortChats()
    }

    func addReaction(_ emoji: String, to messageID: UUID) {
        guard let i = messages.firstIndex(where: { $0.id == messageID }) else { return }
        messages[i].reactions[emoji, default: 0] += 1
    }

    func deleteMessage(_ messageID: UUID) {
        messages.removeAll { $0.id == messageID }
    }

    func createDirectChat(with contact: Contact) -> Chat {
        if let existing = chats.first(where: { !$0.isGroup && $0.participantIDs.contains(contact.id) }) {
            return existing
        }
        let chat = Chat(
            id: UUID(),
            title: contact.name,
            isGroup: false,
            participantIDs: [currentUserID, contact.id],
            lastMessagePreview: String(localized: "No messages yet"),
            lastMessageDate: Date(),
            unreadCount: 0,
            isPinned: false,
            isMuted: false,
            isVerified: contact.isVerified,
            disappearingSeconds: nil,
            avatarInitials: contact.initials,
            accentHue: contact.accentHue
        )
        chats.insert(chat, at: 0)
        return chat
    }

    func createGroup(name: String, members: [Contact]) -> Chat {
        let chat = Chat(
            id: UUID(),
            title: name,
            isGroup: true,
            participantIDs: [currentUserID] + members.map(\.id),
            lastMessagePreview: String(localized: "You created this group"),
            lastMessageDate: Date(),
            unreadCount: 0,
            isPinned: false,
            isMuted: false,
            isVerified: false,
            disappearingSeconds: nil,
            avatarInitials: String(name.prefix(2)).uppercased(),
            accentHue: 0.5
        )
        chats.insert(chat, at: 0)
        messages.append(
            Message(
                id: UUID(),
                chatID: chat.id,
                senderID: nil,
                kind: .system(String(localized: "You created “\(name)”")),
                date: Date(),
                status: .sent,
                isFromCurrentUser: false,
                replyToID: nil,
                reactions: [:]
            )
        )
        return chat
    }

    func searchMessages(query: String) -> [SearchHit] {
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !q.isEmpty else { return [] }
        return messages.compactMap { message in
            let text: String?
            switch message.kind {
            case .text(let t): text = t
            case .emoji(let e): text = e
            case .link(_, let title, let subtitle): text = "\(title) \(subtitle)"
            case .file(let name, _): text = name
            case .image(_, let caption): text = caption
            default: text = nil
            }
            guard let text, text.lowercased().contains(q),
                  let chat = chat(id: message.chatID) else { return nil }
            return SearchHit(id: message.id, chatID: chat.id, chatTitle: chat.title, snippet: text, date: message.date)
        }
        .sorted { $0.date > $1.date }
    }

    func toggleBlock(_ contactID: UUID) {
        if blockedContactIDs.contains(contactID) {
            blockedContactIDs.remove(contactID)
        } else {
            blockedContactIDs.insert(contactID)
        }
    }

    func revokeDevice(_ id: UUID) {
        linkedDevices.removeAll { $0.id == id && !$0.isCurrent }
    }

    private func sortChats() {
        chats.sort {
            if $0.isPinned != $1.isPinned { return $0.isPinned && !$1.isPinned }
            return $0.lastMessageDate > $1.lastMessageDate
        }
    }

    private static func seedMessages(
        me: UUID,
        alice: Contact,
        bob: Contact,
        cara: Contact,
        diego: Contact,
        chatAlice: UUID,
        chatBob: UUID,
        chatGroup: UUID,
        chatCara: UUID,
        chatDiego: UUID,
        chatEmma: UUID,
        now: Date
    ) -> [Message] {
        var list: [Message] = []

        func add(
            _ chatID: UUID,
            _ sender: UUID?,
            _ kind: MessageKind,
            offset: TimeInterval,
            fromMe: Bool,
            status: MessageStatus = .read,
            reactions: [String: Int] = [:],
            replyTo: UUID? = nil
        ) -> UUID {
            let id = UUID()
            list.append(
                Message(
                    id: id,
                    chatID: chatID,
                    senderID: sender,
                    kind: kind,
                    date: now.addingTimeInterval(offset),
                    status: status,
                    isFromCurrentUser: fromMe,
                    replyToID: replyTo,
                    reactions: reactions
                )
            )
            return id
        }

        _ = add(chatAlice, nil, .system("Disappearing messages are on. New messages disappear after 24 hours."), offset: -50_000, fromMe: false)
        _ = add(chatAlice, alice.id, .text("Hey — did the invite codes land?"), offset: -40_000, fromMe: false)
        let a2 = add(chatAlice, me, .text("Yes, five left. Sending one over."), offset: -39_000, fromMe: true)
        _ = add(chatAlice, alice.id, .text("Perfect. Also verify my safety number when you can."), offset: -38_000, fromMe: false, reactions: ["👍": 1])
        _ = add(chatAlice, me, .link(url: "https://cipher.app/safety", title: "Safety numbers", subtitle: "cipher.app/safety"), offset: -37_000, fromMe: true, replyTo: a2)
        _ = add(chatAlice, alice.id, .text("Meet at 6? Keys rotated 🔐"), offset: -120, fromMe: false, status: .delivered)
        _ = add(chatAlice, alice.id, .emoji("🙌"), offset: -90, fromMe: false, status: .delivered)

        _ = add(chatBob, bob.id, .voice(duration: 18), offset: -8_000, fromMe: false)
        _ = add(chatBob, me, .text("Got it — will call later."), offset: -7_200, fromMe: true)
        _ = add(chatBob, bob.id, .file(name: "itinerary.pdf", sizeLabel: "240 KB"), offset: -7_000, fromMe: false)

        _ = add(chatGroup, nil, .system("You created “Weekend Crew”"), offset: -200_000, fromMe: false)
        _ = add(chatGroup, alice.id, .text("Cabin is booked for Friday."), offset: -90_000, fromMe: false)
        _ = add(chatGroup, me, .text("I'll handle groceries."), offset: -80_000, fromMe: true)
        _ = add(chatGroup, cara.id, .image(systemName: "photo", caption: "Mood board"), offset: -60_000, fromMe: false)
        _ = add(chatGroup, bob.id, .text("Bringing the projector"), offset: -1_800, fromMe: false, status: .delivered)

        _ = add(chatCara, cara.id, .text("Loved the draft — sending notes"), offset: -20_000, fromMe: false)
        _ = add(chatDiego, diego.id, .image(systemName: "mountain.2.fill", caption: "Summit view"), offset: -86_400, fromMe: false)
        _ = add(chatEmma, me, .text("See you tomorrow!"), offset: -172_800, fromMe: true)

        return list
    }
}
