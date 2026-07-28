//
//  CryptoActor.swift
//  CipherCrypto
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

/// The single isolation domain in which all cryptography and all database work happens.
///
/// Why a custom executor rather than a bare `actor`:
///
/// 1. **libsignal's store protocols are synchronous and non-isolated.** They cannot be
///    satisfied by a Swift `actor`. libsignal invokes them through C function pointers
///    from inside an FFI call, so Swift's isolation checking does not reach them. Pinning
///    the domain to one identifiable `DispatchQueue` gives us `dispatchPrecondition`,
///    which is the only mechanism that can *assert* — and let a test *prove* — that those
///    callbacks really are serialized.
///
/// 2. **SQLite.** The database has not been built yet, but when it is, it will live on this
///    same queue — one connection, one domain — so the store callbacks libsignal makes
///    mid-decrypt all land inside a single transaction with no suspension point. Whether
///    that permits `SQLITE_OPEN_NOMUTEX` is a decision for the persistence milestone; this
///    type deliberately does not pre-commit to it.
///
/// The app target builds with `SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor`; this framework
/// builds `nonisolated`. Note that under `SWIFT_APPROACHABLE_CONCURRENCY`, a
/// `nonisolated async` function runs on the *caller's* executor — so marking crypto work
/// `nonisolated async` would run it on the main thread. Escaping the main actor requires
/// this explicit annotation.
@globalActor
public actor CryptoActor {
    public static let shared = CryptoActor()

    private static let executor = CryptoQueueExecutor()

    public nonisolated var unownedExecutor: UnownedSerialExecutor {
        CryptoActor.executor.asUnownedSerialExecutor()
    }

    /// True when the caller is already running inside the crypto domain.
    ///
    /// Usable from the synchronous libsignal store callbacks, where no Swift isolation
    /// information survives.
    public static var isCurrent: Bool { CryptoQueueExecutor.isCurrentQueue }

    /// Traps if called from outside the crypto domain.
    ///
    /// Every store method funnels through this in debug builds. It converts "we believe
    /// libsignal serializes its callbacks" into something the test suite demonstrates.
    public static func assertIsolated(
        _ message: @autoclosure () -> String = "reached from outside the crypto domain",
        file: StaticString = #fileID,
        line: UInt = #line
    ) {
        precondition(isCurrent, message(), file: file, line: line)
    }
}

/// A `SerialExecutor` backed by one named, identifiable `DispatchQueue`.
///
/// The queue is named so it is recognisable in Instruments and in crash reports without
/// revealing anything about what it is processing.
private final class CryptoQueueExecutor: SerialExecutor {
    private static let key = DispatchSpecificKey<UInt8>()
    private static let marker: UInt8 = 0x1

    fileprivate static let queue: DispatchQueue = {
        let q = DispatchQueue(
            label: "cz.janrichtermoc.Cipher.crypto",
            qos: .userInitiated,
            autoreleaseFrequency: .workItem
        )
        q.setSpecific(key: key, value: marker)
        return q
    }()

    /// Queue identity via `DispatchSpecificKey`, not `dispatchPrecondition`, so the same
    /// check can be read as a `Bool` for tests as well as asserted.
    fileprivate static var isCurrentQueue: Bool {
        DispatchQueue.getSpecific(key: key) == marker
    }

    func enqueue(_ job: consuming ExecutorJob) {
        let unowned = UnownedJob(job)
        let executor = asUnownedSerialExecutor()
        CryptoQueueExecutor.queue.async {
            unowned.runSynchronously(on: executor)
        }
    }

    func asUnownedSerialExecutor() -> UnownedSerialExecutor {
        UnownedSerialExecutor(ordinary: self)
    }

    /// Makes `assumeIsolated` sound if it is ever needed.
    func checkIsolated() {
        precondition(CryptoQueueExecutor.isCurrentQueue, "not on the crypto queue")
    }
}
