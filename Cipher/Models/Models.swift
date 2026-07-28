//
//  Models.swift
//  Cipher
//

import Foundation
import SwiftUI

struct Contact: Identifiable, Hashable {
    let id: UUID
    var name: String
    var username: String
    var initials: String
    var accentHue: Double
    var isVerified: Bool
    var isOnline: Bool
    var about: String

    var accentColor: Color {
        Color(hue: accentHue, saturation: 0.45, brightness: 0.72)
    }
}

struct Chat: Identifiable, Hashable {
    let id: UUID
    var title: String
    var isGroup: Bool
    var participantIDs: [UUID]
    var lastMessagePreview: String
    var lastMessageDate: Date
    var unreadCount: Int
    var isPinned: Bool
    var isMuted: Bool
    var isVerified: Bool
    var disappearingSeconds: Int?
    var avatarInitials: String
    var accentHue: Double

    var accentColor: Color {
        Color(hue: accentHue, saturation: 0.45, brightness: 0.72)
    }
}

enum MessageKind: Hashable {
    case text(String)
    case emoji(String)
    case image(systemName: String, caption: String?)
    case voice(duration: TimeInterval)
    case file(name: String, sizeLabel: String)
    case link(url: String, title: String, subtitle: String)
    case system(String)
}

enum MessageStatus: Hashable {
    case sending
    case sent
    case delivered
    case read
    case failed
}

struct Message: Identifiable, Hashable {
    let id: UUID
    var chatID: UUID
    var senderID: UUID?
    var kind: MessageKind
    var date: Date
    var status: MessageStatus
    var isFromCurrentUser: Bool
    var replyToID: UUID?
    var reactions: [String: Int]
}

struct CallRecord: Identifiable, Hashable {
    enum Direction: Hashable {
        case incoming
        case outgoing
        case missed
    }

    enum CallKind: Hashable {
        case audio
        case video
    }

    let id: UUID
    var contactID: UUID
    var contactName: String
    var initials: String
    var accentHue: Double
    var direction: Direction
    var kind: CallKind
    var date: Date
    var durationSeconds: Int?

    var accentColor: Color {
        Color(hue: accentHue, saturation: 0.45, brightness: 0.72)
    }
}

struct LinkedDevice: Identifiable, Hashable {
    let id: UUID
    var name: String
    var lastActiveLabel: String
    var isCurrent: Bool
}

struct SearchHit: Identifiable, Hashable {
    let id: UUID
    var chatID: UUID
    var chatTitle: String
    var snippet: String
    var date: Date
}
