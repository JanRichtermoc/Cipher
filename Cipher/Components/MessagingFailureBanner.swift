//
//  MessagingFailureBanner.swift
//  Cipher
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import SwiftUI

/// Says what went wrong with the last messaging operation, in the user's language.
///
/// A messenger that silently fails to send is indistinguishable, from the inside, from one that
/// delivered — and the user acts on that difference. Every failure `MessageRepository` can
/// produce has copy here; there is no "unknown error" default that quietly covers a case someone
/// forgot, because the compiler makes the switch exhaustive instead.
///
/// The copy is deliberately specific about *what the app knows* and never about what the other
/// side saw. "The relay accepted it" is a fact; "delivered" would not be.
struct MessagingFailureBanner: View {
    @Environment(ConversationStore.self) private var store

    var body: some View {
        if let failure = store.failure {
            HStack(alignment: .top, spacing: 8) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(CipherTheme.danger)
                Text(Self.message(for: failure))
                    .font(.footnote)
                    .foregroundStyle(.primary)
                Spacer(minLength: 8)
                Button {
                    store.clearFailure()
                } label: {
                    Image(systemName: "xmark")
                        .font(.caption)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Dismiss")
            }
            .padding(.horizontal, CipherTheme.spacingM)
            .padding(.vertical, 10)
            .background(.thinMaterial)
            .transition(.move(edge: .top).combined(with: .opacity))
        }
    }

    static func message(for failure: MessageRepository.Failure) -> LocalizedStringKey {
        switch failure {
        case .notAuthenticated, .sessionRejected:
            return "Your session is no longer valid. Redeem a new invite to sign in again."
        case .notRegistered:
            return "This device has not finished registering with the relay."
        case .accountMismatch:
            return "This device's keys belong to a different account than its session."
        case .peerUnavailable:
            return "That Cipher ID has no keys available, so no conversation can be started."
        case .identityNotAccepted:
            // Deliberately does not offer a way out. Accepting a changed identity key without
            // showing the user the key would be the "Mark as Verified" that verifies nothing
            // (AUDIT 5.4) — so sending stays blocked until safety numbers exist (P5.S12).
            return "This contact's identity key changed. Sending is blocked, and safety-number comparison is not implemented yet — do not treat this conversation as secure."
        case .blocked:
            return "You blocked this contact. Unblock them to send."
        case .messageTooLarge:
            return "That message is too long to send."
        case .rateLimited:
            return "The relay is rate-limiting this device. Wait a few minutes."
        case .unreachable:
            return "Could not reach the relay. Check your connection."
        case .relayUnavailable:
            return "The relay is reachable but not working right now. Try again shortly."
        case .relayRefused:
            return "The relay refused that request."
        case .storageUnavailable:
            return "Cipher could not write to its encrypted store, so nothing was changed."
        }
    }
}
