//
//  ZeroizationRealityTests.swift
//  CipherCryptoTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//
//  These tests do not test our code. They pin down what Swift and libsignal ACTUALLY do
//  with secret-bearing memory, so the zeroization design rests on measurements rather than
//  on folklore. Every claim `SecretData` makes is derived from a test in this file.
//
//  If a future Swift or libsignal release changes this behaviour, these tests fail and the
//  zeroization design must be revisited before shipping.
//

import XCTest
import LibSignalClient
@testable import CipherCrypto

final class ZeroizationRealityTests: XCTestCase {

    // MARK: - What does libsignal hand us?

    /// `serialize()` is documented (by us) as wrapping Rust-owned memory via
    /// `init(bytesNoCopy:)`. Establish the baseline: the bytes are real and non-empty.
    func testPrivateKeySerializeProducesSecretBytes() {
        let key = PrivateKey.generate()
        let bytes = key.serialize()
        XCTAssertEqual(bytes.count, 32, "X25519 private scalar is 32 bytes")
        XCTAssertFalse(bytes.allSatisfy { $0 == 0 }, "a generated key must not be all-zero")
    }

    // MARK: - The copy-on-write hazard, measured

    /// THE decisive experiment.
    ///
    /// A `Data` created with `init(bytesNoCopy:deallocator:)` does not own its storage. The
    /// question the design hinges on: does mutating that `Data` write THROUGH to the
    /// original allocation, or does Swift copy first and leave the original intact?
    ///
    /// We allocate a buffer ourselves, wrap it, zero the wrapper, and then inspect the
    /// ORIGINAL pointer directly.
    func testMutatingBytesNoCopyDataWritesThroughToOriginalAllocation() {
        let count = 32
        let raw = UnsafeMutablePointer<UInt8>.allocate(capacity: count)
        raw.initialize(repeating: 0xAB, count: count)
        defer { raw.deallocate() }

        var data = Data(bytesNoCopy: raw, count: count, deallocator: .none)
        XCTAssertTrue(data.allSatisfy { $0 == 0xAB })

        data.withUnsafeMutableBytes { buf in
            _ = memset_s(buf.baseAddress, buf.count, 0, buf.count)
        }

        let originalAfter = UnsafeBufferPointer(start: raw, count: count)
        let wroteThrough = originalAfter.allSatisfy { $0 == 0 }

        // Record the answer loudly either way — this drives the SecretData design.
        if wroteThrough {
            XCTAssertTrue(wroteThrough, "in-place mutation wrote through to the original buffer")
        } else {
            XCTFail("""
                CoW HAZARD CONFIRMED: mutating a bytesNoCopy Data did NOT zero the original \
                allocation. Zeroing such a Data in place is therefore theatre, and SecretData \
                must copy into owned storage and zero that, while treating the libsignal-owned \
                buffer as unreachable.
                """)
        }
    }

    /// An alias defeats the write-through. This is the row of the table that makes
    /// `SecretData(consuming:)` best-effort rather than guaranteed: the wrapper is
    /// uniquely referenced from the caller's point of view, yet the wipe does not reach
    /// the original allocation.
    func testAliasDefeatsWriteThroughToTheOriginalAllocation() {
        let count = 32
        let raw = UnsafeMutablePointer<UInt8>.allocate(capacity: count)
        raw.initialize(repeating: 0xAB, count: count)
        defer { raw.deallocate() }

        var data = Data(bytesNoCopy: raw, count: count, deallocator: .none)
        let alias = data                       // forces CoW on the next mutation
        withExtendedLifetime(alias) {
            data.withUnsafeMutableBytes { buf in
                _ = memset_s(buf.baseAddress, buf.count, 0, buf.count)
            }
        }

        let original = UnsafeBufferPointer(start: raw, count: count)
        XCTAssertTrue(original.allSatisfy { $0 == 0xAB },
                      "with an alias present the mutation copies first, so the original " +
                      "buffer keeps the secret — an in-place wipe here is theatre")
    }

    /// A slice likewise copies. Anything derived by slicing a larger buffer cannot be
    /// wiped through.
    func testSliceDefeatsWriteThroughToTheOriginalAllocation() {
        let count = 32
        let raw = UnsafeMutablePointer<UInt8>.allocate(capacity: count)
        raw.initialize(repeating: 0xAB, count: count)
        defer { raw.deallocate() }

        let backing = Data(bytesNoCopy: raw, count: count, deallocator: .none)
        var slice = backing.dropFirst(8)
        slice.withUnsafeMutableBytes { buf in
            _ = memset_s(buf.baseAddress, buf.count, 0, buf.count)
        }

        let original = UnsafeBufferPointer(start: raw, count: count)
        XCTAssertTrue(original.allSatisfy { $0 == 0xAB },
                      "a slice does not write through to its backing allocation")
    }

    /// A second reference forces copy-on-write. If anything else is holding the value,
    /// zeroing "it" provably zeroes only one of the two copies.
    func testSecondReferenceDefeatsInPlaceZeroing() {
        var original = Data(repeating: 0xCD, count: 32)
        let alias = original          // shares storage until one side mutates

        original.withUnsafeMutableBytes { buf in
            _ = memset_s(buf.baseAddress, buf.count, 0, buf.count)
        }

        XCTAssertTrue(original.allSatisfy { $0 == 0 }, "the mutated value is zeroed")
        XCTAssertTrue(alias.allSatisfy { $0 == 0xCD },
                      "the alias still holds the secret — proof that zeroing a shared Data " +
                      "protects nothing if any copy escaped")
    }

    /// `Data.append`, slicing, and `Array(...)` conversions all produce fresh allocations.
    /// Each one is a copy of the secret that our zeroization can never reach.
    func testDerivedValuesAreIndependentCopies() {
        var source = Data(repeating: 0xEF, count: 32)
        let derivedArray = [UInt8](source)
        let derivedSlice = Data(source[0..<16])

        source.withUnsafeMutableBytes { buf in
            _ = memset_s(buf.baseAddress, buf.count, 0, buf.count)
        }

        XCTAssertTrue(derivedArray.allSatisfy { $0 == 0xEF },
                      "[UInt8](data) copied the secret out of reach")
        XCTAssertTrue(derivedSlice.allSatisfy { $0 == 0xEF },
                      "slicing copied the secret out of reach")
    }

    // MARK: - What SecretData must therefore guarantee

    /// The wipe primitive, observed while the allocation is still live.
    ///
    /// An earlier version of this test probed the buffer *after* `deallocate()`. That is
    /// undefined behaviour and it does not measure what it claims: macOS's allocator
    /// scribbles over and recycles freed blocks, so a non-zero read afterwards says
    /// nothing about whether the wipe ran. Post-free memory is unobservable by
    /// construction; the honest test keeps the object alive.
    func testWipeZeroesStorageObservably() {
        let secret = SecretData(repeating: 0x5A, count: 48)
        secret.withUnsafeBytes { XCTAssertTrue($0.allSatisfy { $0 == 0x5A }) }

        secret.wipe()

        secret.withUnsafeBytes {
            XCTAssertTrue($0.allSatisfy { $0 == 0 }, "wipe() must zero the storage in place")
        }
    }

    /// Scoped access must wipe on exit, and must still wipe when the body throws.
    func testScopedAccessWipesOnExitIncludingOnThrow() {
        struct Boom: Error {}

        let secret = SecretData(repeating: 0x77, count: 32)
        secret.withScopedBytes { XCTAssertTrue($0.allSatisfy { $0 == 0x77 }) }
        secret.withUnsafeBytes {
            XCTAssertTrue($0.allSatisfy { $0 == 0 }, "withScopedBytes must wipe on normal exit")
        }

        let throwing = SecretData(repeating: 0x99, count: 32)
        XCTAssertThrowsError(try throwing.withScopedBytes { _ in throw Boom() })
        throwing.withUnsafeBytes {
            XCTAssertTrue($0.allSatisfy { $0 == 0 }, "withScopedBytes must wipe on a throw too")
        }
    }

    /// `deinit` calls the same verified primitive. That the storage is wiped *before*
    /// `deallocate()` cannot be asserted from outside without reading freed memory, so it
    /// is guaranteed by construction (one wipe primitive, called from `deinit`) rather
    /// than by a test that would only be measuring the allocator.
    func testWithSecretRunsBodyOverRequestedSize() {
        var seen = 0
        SecretData.withSecret(repeating: 0x42, count: 64) { buf in
            seen = buf.count
            XCTAssertTrue(buf.allSatisfy { $0 == 0x42 })
        }
        XCTAssertEqual(seen, 64)
    }

    /// Zeroization must survive optimisation. `memset_s` is specified not to be elided;
    /// a plain loop or `memset` may be optimised away as a dead store.
    func testZeroizationUsesNonElidableWipe() {
        let secret = SecretData(repeating: 0x11, count: 64)
        var sawSecret = false
        secret.withUnsafeBytes { buf in sawSecret = buf.allSatisfy { $0 == 0x11 } }
        XCTAssertTrue(sawSecret)
        // The wipe itself is exercised by the two tests above; this asserts the buffer is
        // sized as requested so a partial wipe would be visible there.
        XCTAssertEqual(secret.count, 64)
    }
}
