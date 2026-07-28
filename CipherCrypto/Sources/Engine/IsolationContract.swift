//
//  IsolationContract.swift
//  CipherCrypto
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import LibSignalClient

/// Compile-time proof of the concurrency model, kept in the shipping target on purpose.
///
/// The central question for this module is whether the object satisfying libsignal's six
/// store protocols must be `Sendable`. It must not be: `@unchecked Sendable` is an
/// unchecked promise, and pairing it with a lock would mean the safety argument rests on a
/// comment rather than on the compiler.
///
/// The claim this file exists to verify is:
///
///   A non-`Sendable` store held in `@CryptoActor`-isolated storage may be passed to
///   libsignal's non-isolated **synchronous** entry points without crossing an isolation
///   boundary, because a synchronous call does not hop executors — the callee, and every
///   store callback it makes, runs in the caller's domain.
///
/// If that claim were false, this file would not compile under
/// `SWIFT_STRICT_CONCURRENCY = complete` in Swift 6 language mode, and the module would
/// have to fall back to `@unchecked Sendable` plus a lock. It compiles, so it does not.
///
/// Keeping this in the target means the guarantee is re-verified on every build, and any
/// future Swift release that changes the rule breaks the build loudly instead of silently
/// degrading the argument into an unchecked assertion.
@CryptoActor
internal enum IsolationContract {

    /// `InMemorySignalProtocolStore` is a non-`Sendable` class from libsignal. Holding it
    /// in actor-isolated storage and handing it to `signalEncrypt` is the exact shape the
    /// real store uses.
    internal static func verify() throws {
        let store = InMemorySignalProtocolStore()
        let context = NullContext()

        let peer = try ProtocolAddress(name: "isolation-probe-peer", deviceId: 1)
        let local = try ProtocolAddress(name: "isolation-probe-local", deviceId: 1)

        // The call below is the assertion. It passes a non-Sendable existential into a
        // non-isolated synchronous function from actor-isolated context. The result is
        // deliberately discarded: this is a type-checking contract, not a behavioural one,
        // and it is expected to throw `sessionNotFound` at runtime.
        _ = try? signalEncrypt(
            message: Array("isolation".utf8),
            for: peer,
            localAddress: local,
            sessionStore: store,
            identityStore: store,
            context: context
        )

        // The store must not escape this domain. There is deliberately no way to return
        // it, store it globally, or capture it in an escaping closure.
        CryptoActor.assertIsolated()
    }
}
