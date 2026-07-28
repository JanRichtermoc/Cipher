//
//  SecretData.swift
//  CipherCrypto
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

/// A fixed-size buffer for secret bytes that owns its storage and wipes it on release.
///
/// ## What this actually guarantees, and what it does not
///
/// Swift cannot promise that a value is never copied. `Data`, `Array`, and `String` all
/// copy freely, and the optimiser may keep values in registers or spill them to the stack
/// where nothing can reach them. Any type claiming to "securely erase" a Swift value is
/// overstating its case.
///
/// What `SecretData` does guarantee, and what the tests in `ZeroizationRealityTests`
/// demonstrate rather than assert:
///
/// - It allocates its own storage, so there is exactly one buffer and we know its address.
///   Zeroing it is observable, unlike zeroing a `Data` that may copy-on-write first.
/// - The wipe uses `memset_s`, which is specified not to be optimised away. A plain loop or
///   `memset` over memory that is about to be freed is a dead store the compiler may elide.
/// - Access is scoped. There is no property that returns the bytes, so a caller cannot
///   casually copy the secret into a longer-lived value.
///
/// What it explicitly does NOT cover:
///
/// - **libsignal's buffers.** `serialize()` returns a `Data` wrapping a Rust allocation that
///   `signal_free_buffer` releases with a plain `drop` — no zeroization anywhere in
///   libsignal's Swift layer. `SecretData(consuming:)` copies out of it and makes a
///   best-effort wipe, but the Rust-side buffer is outside our control. This is a recorded
///   residual risk, not a solved problem.
/// - Anything the caller derives from the bytes inside the scope. Converting to `Data`,
///   `[UInt8]`, or `String` creates a copy this type can never reach.
///
/// Deliberately not `Sendable`, not `Codable`, and not `CustomStringConvertible` beyond a
/// redacted form: a secret must not be able to drift across isolation domains, into an
/// encoder, or into a log line.
internal final class SecretData {

    private let storage: UnsafeMutableRawPointer
    internal let count: Int

    /// Creates a buffer of `count` bytes, every byte set to `value`.
    internal init(repeating value: UInt8, count: Int) {
        precondition(count > 0, "SecretData must not be empty")
        self.count = count
        self.storage = UnsafeMutableRawPointer.allocate(
            byteCount: count, alignment: MemoryLayout<UInt8>.alignment)
        memset(storage, Int32(value), count)
    }

    /// Copies `source` into owned storage.
    internal init(copying source: UnsafeRawBufferPointer) {
        precondition(!source.isEmpty, "SecretData must not be empty")
        self.count = source.count
        self.storage = UnsafeMutableRawPointer.allocate(
            byteCount: source.count, alignment: MemoryLayout<UInt8>.alignment)
        storage.copyMemory(from: source.baseAddress!, byteCount: source.count)
    }

    /// Copies a secret out of a `Data` — typically one returned by a libsignal
    /// `serialize()` — and makes a best-effort attempt to wipe the source.
    ///
    /// Measured behaviour, not assumption (see `ZeroizationRealityTests`):
    ///
    /// | source state | in-place wipe reaches the original buffer? |
    /// |---|---|
    /// | uniquely referenced, unsliced | **yes** |
    /// | another `Data` aliases the storage | **no** — copy-on-write; the secret survives |
    /// | any slice of a larger buffer | **no** — copy-on-write; the secret survives |
    ///
    /// So the wipe is genuinely best-effort and its success is not observable from here:
    /// `Data`'s uniqueness lives on an internal storage object that Swift code cannot
    /// inspect, so `isKnownUniquelyReferenced` reasoning does not apply and no assertion
    /// could tell the caller which row of that table they are in.
    ///
    /// The parameter is `inout` and is reassigned to an empty `Data` before returning. That
    /// does not un-leak an alias someone else already holds, but it does drop *this*
    /// reference and makes any further use by the caller a visible mistake rather than a
    /// silent read of a secret we believed was gone.
    ///
    /// Callers must treat `source` as compromised regardless, and keep its lifetime as
    /// short as possible. For libsignal `serialize()` output the underlying Rust buffer is
    /// freed by a plain `drop` with no zeroization, and that remains outside our control.
    internal convenience init(consuming source: inout Data) {
        self.init(copying: source.withUnsafeBytes { $0 })
        source.resetBytes(in: source.startIndex..<source.endIndex)
        source = Data()
    }

    /// Zeroes the storage in place, leaving the buffer allocated.
    ///
    /// `memset_s` is specified not to be elided. A plain `memset` or a byte loop over
    /// memory that is about to be freed is a dead store the optimiser is entitled to
    /// remove, which is the classic way "secure erase" code silently stops working.
    ///
    /// This is the single wipe primitive: `deinit` and `withScopedBytes` both call it, so
    /// the behaviour verified by `testWipeZeroesStorageObservably` is the behaviour used
    /// everywhere.
    internal func wipe() {
        _ = memset_s(storage, count, 0, count)
    }

    deinit {
        wipe()
        storage.deallocate()
    }

    /// Scoped read access. The pointer is valid only for the duration of `body`.
    internal func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try body(UnsafeRawBufferPointer(start: storage, count: count))
    }

    /// Scoped mutable access.
    internal func withUnsafeMutableBytes<R>(
        _ body: (UnsafeMutableRawBufferPointer) throws -> R
    ) rethrows -> R {
        try body(UnsafeMutableRawBufferPointer(start: storage, count: count))
    }

    /// Runs `body` over the storage and wipes it on exit, including on `throw`.
    ///
    /// The buffer remains allocated after this returns, which is what makes the wipe
    /// directly observable in tests. `withSecret` composes this with a bounded lifetime.
    @discardableResult
    internal func withScopedBytes<R>(
        _ body: (UnsafeMutableRawBufferPointer) throws -> R
    ) rethrows -> R {
        defer { wipe() }
        return try withUnsafeMutableBytes(body)
    }

    /// Allocates a secret buffer, runs `body`, wipes it, then releases it.
    ///
    /// Preferred over holding a `SecretData`: the lifetime is bounded by the call.
    @discardableResult
    internal static func withSecret<R>(
        repeating value: UInt8 = 0,
        count: Int,
        _ body: (UnsafeMutableRawBufferPointer) throws -> R
    ) rethrows -> R {
        try SecretData(repeating: value, count: count).withScopedBytes(body)
    }
}

extension SecretData: CustomStringConvertible, CustomDebugStringConvertible {
    /// Never renders contents. A secret that can be interpolated into a string is a secret
    /// that will eventually appear in a log line or a crash report.
    internal var description: String { "SecretData(\(count) bytes, redacted)" }
    internal var debugDescription: String { description }
}
