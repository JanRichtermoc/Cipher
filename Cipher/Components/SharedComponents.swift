//
//  SharedComponents.swift
//  Cipher
//

import SwiftUI

struct AvatarView: View {
    var initials: String
    var color: Color
    var size: CGFloat = CipherTheme.avatarM
    var isOnline: Bool = false
    var isVerified: Bool = false

    var body: some View {
        ZStack(alignment: .bottomTrailing) {
            Circle()
                .fill(
                    LinearGradient(
                        colors: [color, color.opacity(0.7)],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
                .frame(width: size, height: size)
                .overlay {
                    Text(initials)
                        .font(.system(size: size * 0.34, weight: .semibold, design: .rounded))
                        .foregroundStyle(.white)
                }
                .accessibilityHidden(true)

            if isOnline {
                PresenceDot(size: max(10, size * 0.22))
                    .offset(x: -1, y: -1)
            }
        }
        .frame(width: size, height: size)
        .overlay(alignment: .topTrailing) {
            if isVerified && VerificationDisplay.isAvailable {
                Image(systemName: "checkmark.seal.fill")
                    .font(.system(size: max(12, size * 0.28)))
                    .symbolRenderingMode(.palette)
                    .foregroundStyle(.white, CipherTheme.accent)
                    .background(Circle().fill(Color(.systemBackground)).padding(1))
                    .offset(x: 2, y: -2)
                    .accessibilityLabel(String(localized: "Verified"))
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("Avatar \(initials)"))
    }
}

struct PresenceDot: View {
    var size: CGFloat = 12

    var body: some View {
        Circle()
            .fill(CipherTheme.success)
            .frame(width: size, height: size)
            .overlay {
                Circle().strokeBorder(Color(.systemBackground), lineWidth: 2)
            }
            .accessibilityLabel(String(localized: "Online"))
    }
}

struct UnreadBadge: View {
    var count: Int

    var body: some View {
        if count > 0 {
            Text(count > 99 ? "99+" : "\(count)")
                .font(.caption2.weight(.bold))
                .foregroundStyle(.white)
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(CipherTheme.accent, in: Capsule())
                .accessibilityLabel(String(localized: "\(count) unread"))
        }
    }
}

/// Whether the UI is allowed to show a contact as verified.
///
/// It is not, yet. Every `isVerified` in the app comes from a hardcoded `MockStore` boolean,
/// so the checkmark is decoration that reads as a cryptographic claim — the same lie the
/// safety-number screen used to tell, spread across the chat list, the conversation header,
/// and every contact picker.
///
/// Gated in one place rather than at the eight call sites, so re-enabling it is a single
/// deliberate edit when P5.S12 derives verification from real fingerprints.
enum VerificationDisplay {
    static let isAvailable = false
}

struct VerifiedBadge: View {
    var compact: Bool = false

    var body: some View {
        if VerificationDisplay.isAvailable {
            Image(systemName: "checkmark.seal.fill")
                .font(compact ? .caption2 : .subheadline)
                .symbolRenderingMode(.palette)
                .foregroundStyle(.white, CipherTheme.accent)
                .accessibilityLabel(String(localized: "Verified"))
        }
    }
}

struct DisappearingTimerBadge: View {
    var seconds: Int?

    var body: some View {
        if let seconds, seconds > 0 {
            let timerLabel = Self.label(for: seconds)
            Label(timerLabel, systemImage: "timer")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .accessibilityLabel(String(localized: "Disappearing messages \(timerLabel)"))
        }
    }

    static func label(for seconds: Int) -> String {
        if seconds < 60 { return "\(seconds)s" }
        if seconds < 3600 { return "\(seconds / 60)m" }
        if seconds < 86_400 { return "\(seconds / 3600)h" }
        return "\(seconds / 86_400)d"
    }
}

struct EmptyStateView: View {
    var systemImage: String
    var title: LocalizedStringKey
    var message: LocalizedStringKey
    var actionTitle: LocalizedStringKey? = nil
    var action: (() -> Void)? = nil

    var body: some View {
        ContentUnavailableView {
            Label(title, systemImage: systemImage)
        } description: {
            Text(message)
        } actions: {
            if let actionTitle, let action {
                Button(actionTitle, action: action)
                    .buttonStyle(.glassProminent)
                    .tint(CipherTheme.accent)
            }
        }
    }
}

struct LoadingPlaceholder: View {
    var lines: Int = 6

    var body: some View {
        VStack(alignment: .leading, spacing: CipherTheme.spacingM) {
            ForEach(0..<lines, id: \.self) { i in
                HStack(spacing: CipherTheme.spacingM) {
                    RoundedRectangle(cornerRadius: 24, style: .continuous)
                        .fill(Color(.tertiarySystemFill))
                        .frame(width: 48, height: 48)
                    VStack(alignment: .leading, spacing: 8) {
                        RoundedRectangle(cornerRadius: 4)
                            .fill(Color(.tertiarySystemFill))
                            .frame(height: 12)
                            .frame(maxWidth: i.isMultiple(of: 2) ? 180 : 140)
                        RoundedRectangle(cornerRadius: 4)
                            .fill(Color(.quaternarySystemFill))
                            .frame(height: 10)
                            .frame(maxWidth: .infinity)
                    }
                }
                .redacted(reason: .placeholder)
            }
        }
        .padding()
        .accessibilityLabel(String(localized: "Loading"))
    }
}

struct CipherSectionHeader: View {
    let title: String

    var body: some View {
        Text(title)
            .font(.footnote.weight(.semibold))
            .foregroundStyle(.secondary)
            .textCase(.uppercase)
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct SettingsRow: View {
    var title: LocalizedStringKey
    var systemImage: String
    var tint: Color = CipherTheme.accent
    var value: String? = nil
    var showsChevron: Bool = true

    var body: some View {
        HStack(spacing: CipherTheme.spacingM) {
            Image(systemName: systemImage)
                .font(.body.weight(.semibold))
                .foregroundStyle(.white)
                .frame(width: 30, height: 30)
                .background(tint, in: RoundedRectangle(cornerRadius: 7, style: .continuous))
            Text(title)
            Spacer()
            if let value {
                Text(value)
                    .foregroundStyle(.secondary)
            }
            if showsChevron {
                Image(systemName: "chevron.right")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.tertiary)
            }
        }
    }
}
