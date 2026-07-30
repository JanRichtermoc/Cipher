//
//  MessagePayloadTests.swift
//  CipherCryptoTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//
//  The payload format is a parser of hostile input: the ciphertext is authenticated, so these
//  bytes really came from the peer whose session decrypted them, but "the peer" is not "a
//  well-behaved client". Every test here is a refusal.
//

import Foundation
import XCTest

@testable import CipherCrypto

final class MessagePayloadTests: XCTestCase {

    func testTextRoundTrips() throws {
        let payload = MessagePayload(content: .text("meet at six"))
        let decoded = try MessagePayload.decode(try payload.encode())
        XCTAssertEqual(decoded, payload)
    }

    func testEncodingIsVersionedAndTyped() throws {
        let encoded = try MessagePayload(content: .text("x")).encode()
        XCTAssertEqual(encoded.count, 3)
        XCTAssertEqual(encoded[encoded.startIndex], MessagePayload.version)
        // The type byte is wire-visible and 0 is deliberately unused, so an all-zero buffer can
        // never be a valid payload.
        XCTAssertEqual(encoded[encoded.startIndex + 1], 1)
    }

    func testAnEmptyBodyIsStillAValidTextMessage() throws {
        // Not the same question as whether the app should send it — `MessageRepository` refuses
        // blank text. The format must round-trip it rather than treat a two-byte payload as
        // malformed, because "too short to hold a header" and "an empty message" are different
        // failures and only one of them is corruption.
        let decoded = try MessagePayload.decode(Data([MessagePayload.version, 1]))
        XCTAssertEqual(decoded, MessagePayload(content: .text("")))
    }

    // MARK: Refusals

    func testTooShortToHoldAHeaderIsRefused() {
        for bytes in [Data(), Data([1])] {
            XCTAssertThrowsError(try MessagePayload.decode(bytes)) { error in
                XCTAssertEqual(error as? MessagePayloadError, .malformed)
            }
        }
    }

    func testAnUnknownVersionIsRefusedRatherThanInterpreted() {
        // The body is a perfectly good text payload; only the version differs. A build that
        // "tolerantly" read it would be guessing at a format it does not have.
        var bytes = Data([2, 1])
        bytes.append(contentsOf: Array("hello".utf8))

        XCTAssertThrowsError(try MessagePayload.decode(bytes)) { error in
            XCTAssertEqual(error as? MessagePayloadError, .unsupportedVersion(2))
        }
    }

    func testAnUnknownContentTypeIsRefusedRatherThanRenderedAsText() {
        // The whole point: a future receipt or reaction type must not display as a message a
        // human appears to have written. Sweeps the byte space rather than picking one value.
        for type in UInt8(2)...UInt8(255) {
            var bytes = Data([MessagePayload.version, type])
            bytes.append(contentsOf: Array("looks like a message".utf8))

            XCTAssertThrowsError(try MessagePayload.decode(bytes)) { error in
                XCTAssertEqual(error as? MessagePayloadError, .unsupportedContent(type))
            }
        }
        // Type 0 too, separately, because an all-zero buffer is the cheapest thing to send.
        XCTAssertThrowsError(try MessagePayload.decode(Data([MessagePayload.version, 0, 0]))) {
            XCTAssertEqual($0 as? MessagePayloadError, .unsupportedContent(0))
        }
    }

    func testInvalidUTF8IsRefusedRatherThanRepaired() {
        // 0xC3 starts a two-byte sequence and 0x28 cannot continue it. `String(decoding:as:)`
        // would substitute U+FFFD and hand back "content"; this must not.
        var bytes = Data([MessagePayload.version, 1])
        bytes.append(contentsOf: [0xC3, 0x28])

        XCTAssertThrowsError(try MessagePayload.decode(bytes)) { error in
            XCTAssertEqual(error as? MessagePayloadError, .malformed)
        }
    }

    func testAnOversizedPayloadIsRefusedOnBothSides() throws {
        let tooLong = String(repeating: "a", count: MessagePayload.maxEncodedBytes)
        XCTAssertThrowsError(try MessagePayload(content: .text(tooLong)).encode()) { error in
            XCTAssertEqual(
                error as? MessagePayloadError,
                .tooLarge(MessagePayload.maxEncodedBytes + 2))
        }

        // And on decode, so a peer cannot hand over something this build would not produce.
        var bytes = Data([MessagePayload.version, 1])
        bytes.append(Data(repeating: 0x61, count: MessagePayload.maxEncodedBytes))
        XCTAssertThrowsError(try MessagePayload.decode(bytes)) { error in
            XCTAssertEqual(
                error as? MessagePayloadError,
                .tooLarge(MessagePayload.maxEncodedBytes + 2))
        }
    }

    func testTheCapLeavesRoomInsideTheEnvelope() {
        // The reason for a second, lower ceiling: a send that fails at the envelope has already
        // stepped the ratchet, so the sender cannot retry the identical message. The payload cap
        // must therefore be comfortably below the envelope's.
        XCTAssertLessThan(MessagePayload.maxEncodedBytes, Envelope.maxCiphertextBytes)
    }

    func testDecodingIsIndexSafeForASlicedBuffer() throws {
        // A `Data` sliced out of a larger buffer does not start at zero. Assuming it does is a
        // silent parsing bug that only appears once the transport hands over a subrange.
        var backing = Data([0xFF, 0xFF, 0xFF])
        backing.append(try MessagePayload(content: .text("sliced")).encode())

        let decoded = try MessagePayload.decode(backing.dropFirst(3))
        XCTAssertEqual(decoded, MessagePayload(content: .text("sliced")))
    }
}
