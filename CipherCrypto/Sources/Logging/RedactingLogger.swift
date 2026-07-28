//
//  RedactingLogger.swift
//  CipherCrypto
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import LibSignalClient
import os

/// What may never be logged, at any level, in any build:
///
/// private keys · identity keys · session or ratchet state · chain and message keys ·
/// plaintext message bodies · decrypted payloads · auth tokens · session tokens ·
/// invite codes · safety numbers · prekey private halves · raw `ProtocolAddress`
/// (`debugDescription` is the unredacted `"name.deviceId"` — use `ServiceId.logString`).
///
/// The rule is enforced three ways: this module has no API that accepts a secret-bearing
/// type; `SecretData` renders only as `"SecretData(n bytes, redacted)"`; and a CI gate
/// greps the module for logging primitives and raw address interpolation.
internal enum CipherLog {
    private static let subsystem = "cz.janrichtermoc.Cipher"

    /// Session establishment, ratcheting, trust decisions. Never message content.
    internal static let session = Logger(subsystem: subsystem, category: "session")
    /// Store and database lifecycle. Never key material.
    internal static let store = Logger(subsystem: subsystem, category: "store")
    /// Key generation, rotation, replenishment. Identifiers only, never key bytes.
    internal static let keys = Logger(subsystem: subsystem, category: "keys")
}

/// Bridges libsignal's log output into the unified log with everything redacted.
///
/// Two properties of libsignal's contract shape this type:
///
/// 1. `log` "may be called on any thread, and will be called synchronously from the middle
///    of complicated operations" — so it must be cheap and must not take locks that any
///    crypto path could already hold.
/// 2. libsignal maps unknown log levels down to `.debug` precisely because they "might
///    have personal info in them". We go further and treat **every** message from the Rust
///    layer as `.private`, so nothing reaches a sysdiagnose or a collected log archive.
///    The text is still visible on an attached debugger during local development.
internal struct RedactingLogger: LibsignalLogger {
    internal static let shared = RedactingLogger()

    private static let log = Logger(subsystem: "cz.janrichtermoc.Cipher", category: "libsignal")

    internal func log(
        level: LibsignalLogLevel,
        file: UnsafePointer<CChar>?,
        line: UInt32,
        message: UnsafePointer<CChar>
    ) {
        // `message` is Rust-owned and freed by the caller, so it must be copied to be used.
        let text = String(cString: message)

        switch level {
        case .error:
            Self.log.error("\(text, privacy: .private)")
        case .warn:
            Self.log.warning("\(text, privacy: .private)")
        case .info:
            Self.log.info("\(text, privacy: .private)")
        case .debug, .trace:
            Self.log.debug("\(text, privacy: .private)")
        }
    }

    internal func flush() {
        // os.Logger writes synchronously to the unified log; there is no buffer to drain.
    }

    // `logFatal` is deliberately NOT overridden.
    //
    // Its default implementation logs a stack trace, logs the message, flushes, and then
    // calls `fatalError` — and it returns `Never`, so an override cannot avert the crash
    // either. Installing a logger therefore makes libsignal's internal aborts *observable*;
    // it does not make them survivable. Anything reachable through `failOnError`
    // (`serialize()`, `.body`, `.messageType`, `.id`, `.timestamp`, `.signature`) is a
    // potential abort point, and this module only calls those on objects it just
    // constructed or that libsignal just returned from a successful call.
}

/// One-time initialisation for the crypto module.
public enum CipherCryptoBootstrap {

    /// libsignal's `setUpLibsignalLogging` "can only be called once in the lifetime of a
    /// program; later calls will result in a warning and will not change the active
    /// logger." Swift guarantees a `static let` initialiser runs exactly once and is
    /// thread-safe, so idempotence here is structural rather than a flag someone must
    /// remember to check.
    private static let performed: Bool = {
        #if DEBUG
        let level: LibsignalLogLevel = .info
        #else
        // Release keeps only what is needed to diagnose a field failure. Everything is
        // `.private` regardless, but less volume means less to leak.
        let level: LibsignalLogLevel = .warn
        #endif
        RedactingLogger.shared.setUpLibsignalLogging(level: level)
        return true
    }()

    /// Installs the redacting logger. Safe to call repeatedly and from any thread.
    ///
    /// Must run before any other entry point in this module so that libsignal's internal
    /// aborts are observed rather than silent.
    public static func start() {
        _ = performed
    }
}
