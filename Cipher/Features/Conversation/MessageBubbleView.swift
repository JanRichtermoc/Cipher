//
//  MessageBubbleView.swift
//  Cipher
//

import SwiftUI

struct MessageBubbleView: View {
    let message: Message
    var replyPreview: String?
    var onReply: () -> Void
    var onReact: (String) -> Void
    var onForward: () -> Void
    var onDelete: () -> Void
    var onOpenMedia: (() -> Void)?

    private let reactionChoices = ["👍", "❤️", "😂", "😮", "😢", "🙏"]

    var body: some View {
        Group {
            switch message.kind {
            case .system(let text):
                Text(text)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 6)
            default:
                bubbleContent
            }
        }
    }

    private var bubbleContent: some View {
        HStack(alignment: .bottom, spacing: 0) {
            if message.isFromCurrentUser { Spacer(minLength: 56) }

            VStack(alignment: message.isFromCurrentUser ? .trailing : .leading, spacing: 4) {
                ZStack(alignment: message.isFromCurrentUser ? .bottomLeading : .bottomTrailing) {
                    Group {
                        if isEmojiOnly {
                            emojiBody
                        } else {
                            VStack(alignment: .leading, spacing: 6) {
                                if let replyPreview {
                                    Text(replyPreview)
                                        .font(.caption)
                                        .foregroundStyle(message.isFromCurrentUser ? Color.white.opacity(0.85) : Color.secondary)
                                        .padding(8)
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                        .background(
                                            (message.isFromCurrentUser ? Color.white.opacity(0.18) : Color.primary.opacity(0.06)),
                                            in: RoundedRectangle(cornerRadius: 8, style: .continuous)
                                        )
                                }
                                bubbleBody
                            }
                            .padding(.horizontal, 14)
                            .padding(.vertical, 10)
                            .background(bubbleBackground, in: RoundedRectangle(cornerRadius: CipherTheme.radiusM, style: .continuous))
                            .foregroundStyle(message.isFromCurrentUser ? Color.white : Color.primary)
                        }
                    }

                    if !message.reactions.isEmpty {
                        HStack(spacing: 4) {
                            ForEach(message.reactions.keys.sorted(), id: \.self) { emoji in
                                Text("\(emoji) \(message.reactions[emoji] ?? 1)")
                                    .font(.caption2)
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 3)
                                    .background(.ultraThinMaterial, in: Capsule())
                            }
                        }
                        .offset(y: 12)
                    }
                }
                .padding(.bottom, message.reactions.isEmpty ? 0 : 10)

                HStack(spacing: 4) {
                    Text(CipherDateFormatting.messageTime(message.date))
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                    if message.isFromCurrentUser {
                        statusIcon
                    }
                }
            }

            if !message.isFromCurrentUser { Spacer(minLength: 56) }
        }
        .contextMenu {
            Button("Reply", systemImage: "arrowshape.turn.up.left") { onReply() }
            // Reactions have no wire representation: `MessagePayload` carries text and nothing
            // else, so a reaction would render on this device and never reach the peer — a
            // local decoration presented as something they can see. The picker stays for the
            // phase that adds the payload type.
            #if DEBUG
            Menu("React", systemImage: "face.smiling") {
                ForEach(reactionChoices, id: \.self) { emoji in
                    Button(emoji) { onReact(emoji) }
                }
            }
            #endif
            Button("Copy", systemImage: "doc.on.doc") {
                if case .text(let t) = message.kind {
                    // Not `UIPasteboard.general.string = t` — that syncs a decrypted
                    // message to every Mac and iPad on the account, forever.
                    SecurePasteboard.copy(t)
                }
            }
            Button("Forward", systemImage: "arrowshape.turn.up.forward") { onForward() }
            Button("Delete", systemImage: "trash", role: .destructive) { onDelete() }
        }
    }

    private var isEmojiOnly: Bool {
        if case .emoji = message.kind { return true }
        return false
    }

    @ViewBuilder
    private var emojiBody: some View {
        if case .emoji(let emoji) = message.kind {
            Text(emoji)
                .font(.system(size: 52))
                .padding(4)
        }
    }

    @ViewBuilder
    private var bubbleBody: some View {
        switch message.kind {
        case .text(let text):
            Text(text)
                .font(.body)
        case .emoji:
            EmptyView()
        case .image(let systemName, let caption):
            VStack(alignment: .leading, spacing: 8) {
                Button {
                    onOpenMedia?()
                } label: {
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .fill(Color.black.opacity(0.12))
                        .frame(width: 200, height: 140)
                        .overlay {
                            Image(systemName: systemName)
                                .font(.largeTitle)
                                .symbolRenderingMode(.hierarchical)
                                .foregroundStyle(.secondary)
                        }
                }
                .buttonStyle(.plain)
                if let caption {
                    Text(caption)
                }
            }
        case .voice(let duration):
            HStack(spacing: 10) {
                Image(systemName: "play.fill")
                VoiceWaveformView()
                Text(CipherDateFormatting.elapsedClock(Int(duration)))
                    .font(.caption.monospacedDigit())
            }
            .frame(minWidth: 160)
        case .file(let name, let sizeLabel):
            HStack {
                Image(systemName: "doc.fill")
                    .font(.title2)
                VStack(alignment: .leading) {
                    Text(name).fontWeight(.medium)
                    Text(sizeLabel).font(.caption).opacity(0.8)
                }
            }
        case .link(_, let title, let subtitle):
            VStack(alignment: .leading, spacing: 4) {
                Text(title).fontWeight(.semibold)
                Text(subtitle).font(.caption).opacity(0.85)
            }
        case .system:
            EmptyView()
        }
    }

    private var bubbleBackground: Color {
        message.isFromCurrentUser ? CipherTheme.sentBubble : CipherTheme.receivedBubble
    }

    @ViewBuilder
    private var statusIcon: some View {
        switch message.status {
        case .sending:
            ProgressView().controlSize(.mini)
        case .sent:
            Image(systemName: "checkmark")
                .font(.caption2)
                .foregroundStyle(.secondary)
        case .failed:
            Image(systemName: "exclamationmark.circle.fill")
                .font(.caption2)
                .foregroundStyle(CipherTheme.danger)
        }
    }
}

struct VoiceWaveformView: View {
    var body: some View {
        HStack(spacing: 2) {
            ForEach(0..<16, id: \.self) { i in
                RoundedRectangle(cornerRadius: 1)
                    .fill(Color.primary.opacity(0.55))
                    .frame(width: 2.5, height: CGFloat(6 + (i % 5) * 3))
            }
        }
        .accessibilityHidden(true)
    }
}

struct DaySeparatorView: View {
    let date: Date

    var body: some View {
        Text(CipherDateFormatting.daySeparator(date))
            .font(.caption.weight(.semibold))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 12)
            .padding(.vertical, 4)
            .background(.ultraThinMaterial, in: Capsule())
            .frame(maxWidth: .infinity)
            .padding(.vertical, 8)
    }
}

struct TypingIndicatorView: View {
    @State private var phase = 0.0

    var body: some View {
        HStack(spacing: 4) {
            ForEach(0..<3, id: \.self) { i in
                Circle()
                    .fill(Color.secondary)
                    .frame(width: 7, height: 7)
                    .offset(y: sin(phase + Double(i)) * 3)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(CipherTheme.receivedBubble, in: Capsule())
        .onAppear {
            withAnimation(.easeInOut(duration: 0.6).repeatForever(autoreverses: true)) {
                phase = .pi
            }
        }
        .accessibilityLabel(String(localized: "Typing"))
    }
}
