//
//  MessagePaddingTests.swift
//  CipherCryptoTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//
//  P7.S02 — length bucketing (THREAT_MODEL.md §3.5).
//
//  The scheme is tested twice over, because the two halves fail differently. The unit tests
//  below drive `MessagePadding` directly and are about *correctness*: a padded plaintext must
//  come back byte-identical, and anything that is not this scheme's output must be refused
//  rather than returned as content. `SealedSenderTests` would keep passing if padding were
//  removed entirely, so the property the step exists for — that the frame the relay stores
//  takes one of a small fixed set of lengths — is asserted separately, against real sends, in
//  `MessagingTests.testTheRelayedLengthTakesOneOfASmallFixedSetOfValues`.
//

import Foundation
import LibSignalClient
import XCTest

@testable import CipherCrypto

final class MessagePaddingTests: XCTestCase {

    // MARK: - The bucket set itself

    /// The step's `Done when` is "wire lengths take a small fixed set of values", so the size of
    /// that set is part of the contract rather than an implementation detail. Pinned here so
    /// widening it — a finer ladder, a per-message size — is a deliberate edit with a failing
    /// test in front of it.
    func testTheBucketSetIsSmallAscendingAndCoversEveryLegalPayload() {
        let buckets = MessagePadding.buckets

        XCTAssertEqual(buckets.count, 9, "a bucket set that grows stops being a bucket set")
        XCTAssertEqual(buckets, buckets.sorted(), "buckets must ascend")
        XCTAssertEqual(Set(buckets).count, buckets.count, "no duplicates")

        for bucket in buckets {
            XCTAssertEqual(bucket % 256, 0, "every bucket is a whole number of 256-byte blocks")
        }

        // The largest legal payload must fit *with* its terminator, or the scheme would refuse
        // messages the payload format accepts.
        XCTAssertGreaterThan(
            buckets.last!, MessagePayload.maxEncodedBytes,
            "the top bucket cannot hold the largest payload plus its terminator")
        XCTAssertEqual(MessagePadding.maxPlaintextBytes, buckets.last! - 1)
    }

    // MARK: - Round trip

    /// Every length from empty to the ceiling, including each boundary, comes back identical.
    ///
    /// The lengths are chosen around the bucket edges rather than sampled at random: an
    /// off-by-one in the "does it fit" comparison is invisible in the middle of a bucket and is
    /// the whole failure mode at its edge.
    func testPaddingRoundTripsAtEveryBoundary() throws {
        var lengths: Set<Int> = [0, 1, 2, 255]
        for bucket in MessagePadding.buckets {
            lengths.formUnion([bucket - 2, bucket - 1, bucket, bucket + 1])
        }
        lengths = lengths.filter { $0 >= 0 && $0 <= MessagePadding.maxPlaintextBytes }

        for length in lengths.sorted() {
            // Content that is not all one byte, and that ends in a byte the stripper must not
            // mistake for its terminator or for padding.
            let plaintext = Data((0..<length).map { UInt8(($0 % 251) + 1) })

            let padded = try MessagePadding.pad(plaintext)
            XCTAssertTrue(
                MessagePadding.buckets.contains(padded.count),
                "\(length) bytes padded to \(padded.count), which is not a bucket")
            XCTAssertGreaterThan(padded.count, length, "there must be room for the terminator")

            XCTAssertEqual(try MessagePadding.strip(padded), plaintext,
                           "a \(length)-byte plaintext did not survive the round trip")
        }
    }

    /// Content ending in the terminator byte, or in zeros, is the case a scan-backwards stripper
    /// gets wrong. Both must survive, because both are legal bytes inside a message.
    func testContentThatLooksLikePaddingSurvives() throws {
        for trailing: [UInt8] in [
            [MessagePadding.terminator],
            [0x00],
            [0x00, 0x00, 0x00],
            [MessagePadding.terminator, 0x00, 0x00],
            [0x01, MessagePadding.terminator],
        ] {
            let plaintext = Data([0x41, 0x42]) + Data(trailing)
            XCTAssertEqual(try MessagePadding.strip(try MessagePadding.pad(plaintext)), plaintext,
                           "content ending \(trailing) was damaged by the round trip")
        }
    }

    func testDifferentLengthsInOneBucketPadToTheSameSize() throws {
        let short = try MessagePadding.pad(Data("hi".utf8))
        let long = try MessagePadding.pad(Data(repeating: 0x41, count: 200))

        XCTAssertEqual(short.count, long.count)
        XCTAssertEqual(short.count, MessagePadding.buckets.first)
    }

    // MARK: - Malformed padding is refused, never returned as content

    /// The failure that matters: trailing NUL bytes are valid UTF-8, so a stripper that gave up
    /// and returned the buffer would hand the caller a message with invisible characters
    /// appended rather than an error.
    func testMalformedPaddingIsRefused() {
        let cases: [(String, Data)] = [
            ("empty", Data()),
            ("all zeros", Data(repeating: 0, count: 256)),
            ("no terminator", Data([0x41, 0x42, 0x43])),
            ("wrong terminator", Data([0x41, 0x7F]) + Data(repeating: 0, count: 10)),
            ("terminator is zero", Data([0x41]) + Data(repeating: 0, count: 10)),
        ]

        for (name, bytes) in cases {
            XCTAssertThrowsError(try MessagePadding.strip(bytes), name) { error in
                XCTAssertEqual(error as? MessagingError, .malformedPadding, name)
            }
        }
    }

    func testAPlaintextLargerThanTheTopBucketIsRefused() {
        let tooBig = Data(repeating: 0x41, count: MessagePadding.maxPlaintextBytes + 1)
        XCTAssertThrowsError(try MessagePadding.pad(tooBig)) { error in
            XCTAssertEqual(error as? MessagingError,
                           .messageTooLarge(MessagePadding.maxPlaintextBytes + 1))
        }

        // Positive control: one byte less is accepted, so the refusal is the ceiling and not
        // the fixture.
        XCTAssertNoThrow(
            try MessagePadding.pad(Data(repeating: 0x41, count: MessagePadding.maxPlaintextBytes)))
    }

    /// A payload the format accepts must always be sendable. If `MessagePayload.maxEncodedBytes`
    /// ever rises past the top bucket, the failure would otherwise appear as messages that
    /// encode fine and refuse to send.
    func testEveryLegalPayloadFitsAPadding() throws {
        XCTAssertNoThrow(
            try MessagePadding.pad(
                Data(repeating: 0x41, count: MessagePayload.maxEncodedBytes)),
            "a payload at the format's own ceiling cannot be padded")
    }

    // MARK: - Stripping is not applied where nothing was padded

    /// Sliced buffers do not start at index 0, and a stripper that assumed they did would read
    /// the wrong bytes and fail silently.
    func testStripsCorrectlyFromANonZeroStartIndex() throws {
        let plaintext = Data("offset me".utf8)
        let padded = try MessagePadding.pad(plaintext)

        var prefixed = Data([0xFF, 0xFF, 0xFF])
        prefixed.append(padded)
        let slice = prefixed[3...]

        XCTAssertNotEqual(slice.startIndex, 0, "precondition: the slice is offset")
        XCTAssertEqual(try MessagePadding.strip(slice), plaintext)
    }
}
