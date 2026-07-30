//
//  SerialGate.swift
//  Cipher
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import Synchronization

/// A first-in, first-out async mutex.
///
/// ## Why an actor is not already this
///
/// Actor isolation serialises *statements*, not *operations*. An actor method that suspends at
/// an `await` releases the actor, and another call can run to its own first suspension in the
/// gap. So a read-modify-write that spans a suspension — read a counter from storage, use it,
/// write it back — is **not** atomic inside an actor, even though every individual line is.
///
/// That is exactly the shape of appending a message: read the conversation's next ordinal,
/// write the message under it, write the incremented counter back. Two appends interleaving
/// there both read the same ordinal, both write a message to the same slot, and one message is
/// silently gone — with no error anywhere, because each write succeeded.
///
/// ## Why it is a class and not an actor
///
/// The waiter queue is guarded by a `Mutex`, so every method is `nonisolated`. That matters for
/// the caller rather than for performance: `withExclusiveAccess` runs the caller's closure on
/// the caller's own isolation, so the critical section can touch actor-isolated state directly.
/// An `actor` gate would require the closure to be *sent* to it, which strict concurrency
/// correctly refuses for a closure that captures another actor's state.
///
/// ## In-process only
///
/// This is a lock between tasks in one process, not between processes. A notification-service
/// extension writing the same container is a different problem and a documented blocker
/// (`AUDIT.md` 4.4, item 2): the lock it needs must survive the holder being killed, which this
/// one cannot. Nothing here makes an NSE safe, and nothing here is meant to.
nonisolated final class SerialGate: Sendable {

    private struct State {
        var isHeld = false
        /// FIFO. A stack would let a busy send loop starve the receive path, and "eventually" is
        /// not a property worth relying on for the code that decides whether a received message
        /// is durable before it is acknowledged.
        var waiting: [CheckedContinuation<Void, Never>] = []
    }

    private let state = Mutex(State())

    /// Runs `body` with exclusive access, releasing the gate even if it throws.
    func withExclusiveAccess<T>(_ body: () async throws -> T) async rethrows -> T {
        await acquire()
        defer { release() }
        return try await body()
    }

    private func acquire() async {
        let mustWait = state.withLock { state -> Bool in
            if state.isHeld { return true }
            state.isHeld = true
            return false
        }
        guard mustWait else { return }

        await withCheckedContinuation { continuation in
            // Re-check under the lock: the holder may have released between the two, and a
            // continuation appended after that would never be resumed.
            let resumeNow = state.withLock { state -> Bool in
                if state.isHeld {
                    state.waiting.append(continuation)
                    return false
                }
                state.isHeld = true
                return true
            }
            if resumeNow { continuation.resume() }
        }
    }

    /// Hands the gate directly to the next waiter rather than clearing `isHeld`.
    ///
    /// Clearing it and letting waiters race would reintroduce the interleaving this type exists
    /// to prevent: a caller arriving between the clear and the resume would find the gate free
    /// and proceed alongside the waiter that was just resumed.
    private func release() {
        let next = state.withLock { state -> CheckedContinuation<Void, Never>? in
            if state.waiting.isEmpty {
                state.isHeld = false
                return nil
            }
            return state.waiting.removeFirst()
        }
        next?.resume()
    }
}
