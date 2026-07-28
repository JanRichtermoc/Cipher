//
//  UnimplementedNotice.swift
//  Cipher
//

import SwiftUI

/// Marks a control whose security behaviour does not exist yet.
///
/// Cipher must never present a control that implies protection it does not provide. A toggle
/// labelled "Require Face ID" that never calls `LAContext`, or a safety number made of
/// constants, is worse than having no control at all: it suppresses exactly the caution the
/// user would otherwise apply, and it survives their attempt to check it.
///
/// So every unfinished control either disappears or says so, in the user's language, next to
/// the control itself — not in a changelog. `Registration Lock PIN` already did this
/// ("UI stub — no PIN is stored"); this makes that the house style.
///
/// Remove the notice in the same change that implements the control, never before.
struct UnimplementedNotice: View {
    private let detail: LocalizedStringKey

    init(_ detail: LocalizedStringKey) {
        self.detail = detail
    }

    var body: some View {
        Label {
            Text(detail)
        } icon: {
            Image(systemName: "exclamationmark.triangle.fill")
        }
        .font(.footnote)
        .foregroundStyle(.secondary)
        .accessibilityLabel(Text("Not implemented"))
        .accessibilityValue(Text(detail))
    }
}

extension View {
    /// Disables a control and explains why, so it reads as unfinished rather than broken.
    func unimplemented(_ detail: LocalizedStringKey) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            self.disabled(true)
            UnimplementedNotice(detail)
        }
    }
}

#Preview {
    Form {
        Section("Example") {
            // Deliberately not a real security label: a preview that renders removed
            // deceptive copy puts it straight back into the string catalog.
            Toggle("Some unfinished control", isOn: .constant(false))
                .unimplemented("Not implemented yet — this setting does nothing.")
        }
    }
}
