//
//  SecurePasteboard.swift
//  Cipher
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import UIKit
import UniformTypeIdentifiers

/// Copying, with the two options `UIPasteboard.general.string = x` silently declines.
///
/// A plain assignment to `.string` puts the text on the **general** pasteboard with no
/// expiry and no device restriction. Two consequences that matter for a messenger:
///
/// - **It leaves the device.** Universal Clipboard forwards the general pasteboard to every
///   Mac and iPad signed into the same Apple Account, over the air, within seconds. A
///   decrypted message copied on a phone lands on a laptop that may be in another room, in
///   another person's house, or unattended in an office.
/// - **It persists indefinitely.** The item stays until something else overwrites it —
///   across app launches and reboots.
///
/// Neither is exotic; both are the default.
///
/// ## What this does not fix
///
/// The pasteboard is a shared surface. Any app the user pastes into receives the text, and
/// that is the point of copying. iOS 16 and later require a user gesture before an app can
/// read it silently and show a banner when one does, but a user who taps *Paste* in a
/// hostile app has handed the text over. Expiry bounds the window; it does not close it.
///
/// Recorded in `docs/AUDIT.md` 4.6 rather than implied, because "we set an expiry" reads
/// like a stronger promise than it is.
enum SecurePasteboard {

    /// How long a copied item survives. Long enough to switch apps and paste, short enough
    /// that a phone left on a desk is not still holding a message an hour later.
    static let lifetime: TimeInterval = 90

    /// Copies `text`, local to this device, expiring after `lifetime`.
    static func copy(_ text: String) {
        UIPasteboard.general.setItems(
            [[UTType.utf8PlainText.identifier: text]], options: options())
    }

    /// The two options that are the whole control, separated from the call that applies them
    /// so they can be asserted.
    ///
    /// `UIPasteboard` exposes no way to read back the options an item was written with, so
    /// without this seam the difference between `SecurePasteboard.copy` and the plain
    /// `UIPasteboard.general.string = text` it exists to replace is invisible to a test — and
    /// AUDIT 4.6 is CLOSED, which in this ledger means a *tested* control exists. It did not.
    /// Dropping `.localOnly` in a tidy-up would have reinstated Universal Clipboard forwarding
    /// with every gate green.
    static func options(now: Date = Date()) -> [UIPasteboard.OptionsKey: Any] {
        [
            // Never Universal Clipboard. This is the option that keeps a decrypted
            // message on the device it was decrypted on.
            .localOnly: true,
            .expirationDate: now.addingTimeInterval(lifetime),
        ]
    }
}
