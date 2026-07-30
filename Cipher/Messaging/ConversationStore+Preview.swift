//
//  ConversationStore+Preview.swift
//  Cipher
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

#if DEBUG

import Foundation
import SwiftUI

/// Fixtures for SwiftUI previews and the DEBUG UI catalog.
///
/// This is what is left of `MockStore`, and the difference is the point. `MockStore` was the
/// *production* store: `CipherApp` instantiated it, every screen read it, and it shipped in
/// Release with six invented contacts, a fabricated call history, hardcoded `isVerified` flags,
/// and a `sendText` that appended a struct to an array (AUDIT 5.3). The data has not changed
/// much; what changed is that it is now behind `#if DEBUG`, reachable only through
/// `ConversationStore.preview()`, and that the store it populates has no engine and no relay —
/// `isPreviewOnly` makes every mutating method a no-op, so a preview cannot even accidentally
/// write to the sealed container.
///
/// `Scripts/verify-all.sh` asserts none of these names reach the Release bundle.
extension ConversationStore {

    /// The conversation the `ConversationView` preview opens.
    static let previewChatID = UUID(uuidString: "10000000-0000-0000-0000-000000000001")!

    private static let previewAlice = UUID(uuidString: "00000000-0000-0000-0000-000000000002")!
    private static let previewBob = UUID(uuidString: "00000000-0000-0000-0000-000000000003")!

    static func preview() -> ConversationStore {
        let now = Date()

        let contacts = [
            Contact(
                id: previewChatID, name: "Alice Chen", username: "3F2A9C1B", initials: "AC",
                accentHue: 0.55, isVerified: false, isOnline: false, about: ""),
            Contact(
                id: previewBob, name: "Bob Novak", username: "7B14D0E5", initials: "BN",
                accentHue: 0.08, isVerified: false, isOnline: false, about: ""),
        ]

        let chats = [
            Chat(
                id: previewChatID, title: "Alice Chen", isGroup: false,
                participantIDs: [previewAlice, previewChatID],
                lastMessagePreview: "Meet at 6?", lastMessageDate: now.addingTimeInterval(-120),
                unreadCount: 2, isPinned: true, isMuted: false, isVerified: false,
                disappearingSeconds: nil, avatarInitials: "AC", accentHue: 0.55),
            Chat(
                id: previewBob, title: "Bob Novak", isGroup: false,
                participantIDs: [previewAlice, previewBob],
                lastMessagePreview: "Will call later.",
                lastMessageDate: now.addingTimeInterval(-7200),
                unreadCount: 0, isPinned: false, isMuted: false, isVerified: false,
                disappearingSeconds: nil, avatarInitials: "BN", accentHue: 0.08),
        ]

        let messages: [UUID: [Message]] = [
            previewChatID: [
                Message(
                    id: UUID(), chatID: previewChatID, senderID: previewChatID,
                    kind: .text("Did the invite code land?"),
                    date: now.addingTimeInterval(-40_000), status: .sent,
                    isFromCurrentUser: false, replyToID: nil, reactions: [:]),
                Message(
                    id: UUID(), chatID: previewChatID, senderID: previewAlice,
                    kind: .text("Yes — sending one over."),
                    date: now.addingTimeInterval(-39_000), status: .sent,
                    isFromCurrentUser: true, replyToID: nil, reactions: [:]),
                Message(
                    id: UUID(), chatID: previewChatID, senderID: previewChatID,
                    kind: .text("Meet at 6?"), date: now.addingTimeInterval(-120),
                    status: .sent, isFromCurrentUser: false, replyToID: nil, reactions: [:]),
                Message(
                    id: UUID(), chatID: previewChatID, senderID: previewChatID,
                    kind: .emoji("🙌"), date: now.addingTimeInterval(-90), status: .sent,
                    isFromCurrentUser: false, replyToID: nil, reactions: [:]),
            ],
            previewBob: [
                Message(
                    id: UUID(), chatID: previewBob, senderID: previewAlice,
                    kind: .text("Will call later."), date: now.addingTimeInterval(-7200),
                    status: .failed, isFromCurrentUser: true, replyToID: nil, reactions: [:]),
            ],
        ]

        return ConversationStore(
            previewChats: chats, previewMessages: messages, previewContacts: contacts)
    }

    /// Call history for the DEBUG-only calls screens. There is no call implementation, so this
    /// data has no production counterpart at all — which is exactly why the screens that render
    /// it are fenced.
    var previewCalls: [CallRecord] {
        let now = Date()
        return [
            CallRecord(
                id: UUID(), contactID: Self.previewChatID, contactName: "Alice Chen",
                initials: "AC", accentHue: 0.55, direction: .outgoing, kind: .video,
                date: now.addingTimeInterval(-3600), durationSeconds: 842),
            CallRecord(
                id: UUID(), contactID: Self.previewBob, contactName: "Bob Novak",
                initials: "BN", accentHue: 0.08, direction: .missed, kind: .audio,
                date: now.addingTimeInterval(-10_000), durationSeconds: nil),
        ]
    }
}

#endif
