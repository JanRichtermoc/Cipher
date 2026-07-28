//
//  CipherCrypto.swift
//  CipherCrypto
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

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
}
