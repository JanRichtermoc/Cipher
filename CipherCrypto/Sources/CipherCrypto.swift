//
//  CipherCrypto.swift
//  CipherCrypto
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

/// Namespace for Cipher's cryptography module.
///
/// Everything security-critical lives in this framework and nowhere else. The module
/// deliberately does not import SwiftUI and never sees a view type, so the surface an
/// auditor must review is exactly this target.
///
/// Isolation: this target builds with `SWIFT_DEFAULT_ACTOR_ISOLATION = nonisolated`,
/// unlike the app target which defaults to `MainActor`. Crypto work must never
/// implicitly inherit main-actor isolation.
public enum CipherCrypto {
    /// The libsignal release this module is built and tested against.
    ///
    /// libsignal is deliberately versioned `0.x` and does not promise stability between
    /// releases, so this is asserted against the linked library by the test suite rather
    /// than assumed. The authoritative pin lives in `Vendor/libsignal/PINS.env`.
    public static let libsignalVersion = "0.99.1"

    /// `date` as milliseconds since the Unix epoch, clamped at zero.
    ///
    /// `UInt64(someNegativeDouble)` **traps**, and the clock this reads is user-settable: the
    /// iOS date picker reaches 1970 and below, and a device in a UTC-positive timezone set to
    /// its minimum produces a negative interval. Every `encrypt` and every inbound `saveIdentity`
    /// calls this, so the trap would be a crash on the send *and* receive paths — reached with no
    /// attacker, no relay and no malformed input.
    ///
    /// Clamping rather than refusing, because there is nothing to protect. The envelope timestamp
    /// is untrusted by construction (`Envelope`), and the record timestamps it also feeds are
    /// display and retention hints; none gates a cryptographic decision. `MessageRepository`
    /// already clamps for the same reason — this is that pattern, in the module that missed it.
    internal static func epochMilliseconds(from date: Date) -> UInt64 {
        UInt64(max(0, date.timeIntervalSince1970) * 1000)
    }
}
