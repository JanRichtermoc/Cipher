//
//  SafetyNumberView.swift
//  Cipher
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//
//  P5.S12 / AUDIT 2.5. The send-block for a changed identity has been real since
//  P5.S10; what was missing was the screen that explains it. Without this, a user
//  is stopped from sending with no way to see *which* key they are being asked to
//  accept — the protection is half-delivered, and the half that is missing is the
//  one that lets them tell a key rotation from an attack.
//
//  Everything here is deliberately unglamorous. The screen's job is to make two
//  people read sixty digits to each other over a channel this app does not
//  control, and every affordance that makes that feel optional works against it.
//

import CipherCrypto
import SwiftUI

/// What the safety-number screen renders, captured in one read.
///
/// `identityKey` travels with the digits on purpose: it is the key the digits were computed
/// from, and it is handed straight back when the user confirms. Re-reading the key at
/// confirmation time instead would open exactly the gap the exact-key rule closes — a change
/// arriving between the screen being drawn and the tap would be silently approved.
struct SafetyNumberDetails: Equatable, Sendable {
    let peer: UUID
    let digits: String
    let identityKey: Data
    let isVerified: Bool
    /// True while the key has changed and sending is blocked pending acceptance.
    let needsAcknowledgement: Bool
    let changedAtMs: UInt64?

    /// The digits in groups of five, the form people can actually read aloud.
    ///
    /// Sixty digits as one run is unreadable and, worse, unreadable *in a way that makes
    /// people skip to the end* — which is where a substituted key would differ least
    /// noticeably. Grouping is presentation only; nothing compares the formatted string.
    var groups: [String] {
        stride(from: 0, to: digits.count, by: 5).map { offset in
            let start = digits.index(digits.startIndex, offsetBy: offset)
            let end = digits.index(start, offsetBy: 5, limitedBy: digits.endIndex) ?? digits.endIndex
            return String(digits[start..<end])
        }
    }
}

struct SafetyNumberView: View {
    let peer: UUID
    let peerName: String

    @Environment(ConversationStore.self) private var store
    @Environment(\.dismiss) private var dismiss

    @State private var details: SafetyNumberDetails?
    @State private var isLoading = true
    @State private var staleKey = false

    var body: some View {
        NavigationStack {
            Group {
                if let details {
                    content(details)
                } else if isLoading {
                    ProgressView()
                } else {
                    // No key yet is a real state, not an error: a conversation can exist
                    // before either side has sent anything, and there is nothing to compare.
                    // Literals, not String(localized:): EmptyStateView takes
                    // LocalizedStringKey, which is what puts these in the catalog.
                    EmptyStateView(
                        systemImage: "number",
                        title: "No safety number yet",
                        message: "A safety number appears once you and this contact have exchanged a message.")
                }
            }
            .navigationTitle(String(localized: "Safety number"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button(String(localized: "Done")) { dismiss() }
                }
            }
        }
        .task { await load() }
    }

    @ViewBuilder
    private func content(_ details: SafetyNumberDetails) -> some View {
        List {
            Section {
                digitGrid(details)
            } footer: {
                Text(
                    "Compare these numbers with \(peerName) in person or over a call you trust. If they match, no one is intercepting this conversation."
                )
            }

            if details.needsAcknowledgement {
                Section {
                    Label(
                        String(localized: "This contact's key changed"),
                        systemImage: "exclamationmark.triangle.fill"
                    )
                    .foregroundStyle(CipherTheme.warning)

                    Button(String(localized: "Accept the new key")) {
                        Task { await accept(details) }
                    }
                } footer: {
                    // States the trade-off rather than hiding it. Accepting is not verifying,
                    // and a user who accepts to unblock a conversation should know they have
                    // not checked anything.
                    Text(
                    "You can't send messages until you accept it. Accepting unblocks sending — it does not confirm the numbers match."
                    )
                }
            }

            Section {
                Toggle(
                    String(localized: "I compared the numbers"),
                    isOn: Binding(
                        get: { details.isVerified },
                        set: { newValue in Task { await setVerified(newValue, details) } })
                )
            } footer: {
                Text(
                    "Only mark this after comparing every digit. It clears automatically if this contact's key ever changes."
                )
            }

            if staleKey {
                Section {
                    Text(
                    "This contact's key changed while this screen was open, so nothing was saved. Compare the new numbers above."
                    )
                    .foregroundStyle(CipherTheme.warning)
                }
            }
        }
    }

    private func digitGrid(_ details: SafetyNumberDetails) -> some View {
        LazyVGrid(columns: Array(repeating: GridItem(.flexible()), count: 3), spacing: 12) {
            ForEach(Array(details.groups.enumerated()), id: \.offset) { _, group in
                Text(group)
                    .font(.system(.body, design: .monospaced))
                    .monospacedDigit()
            }
        }
        .padding(.vertical, 8)
        // One accessibility element reading the whole number, because VoiceOver moving
        // group-by-group through twelve cells is not a comparison anyone completes.
        .accessibilityElement(children: .combine)
        .accessibilityLabel(
            Text(
                    "Safety number: \(details.groups.joined(separator: " "))"))
    }

    private func load() async {
        details = await store.safetyNumberDetails(for: peer)
        isLoading = false
    }

    private func setVerified(_ verified: Bool, _ details: SafetyNumberDetails) async {
        // The key the digits came from, not one re-read now. A false result means the stored
        // key moved on, so nothing was recorded and the user is shown the current number.
        let ok = await store.setVerified(verified, peer: peer, identityKey: details.identityKey)
        staleKey = !ok
        await load()
    }

    private func accept(_ details: SafetyNumberDetails) async {
        let ok = await store.acceptIdentity(peer: peer, identityKey: details.identityKey)
        staleKey = !ok
        await load()
    }
}
