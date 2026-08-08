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
        //
        // The *implemented* set is subtracted rather than a boundary being hardcoded. This test
        // began as `for type in 2...255`, which was correct until P6.S03 made 2 a real type —
        // at which point it failed, loudly, which is the good outcome. The next addition would
        // have moved the same boundary again. Deriving the exclusion from the enum keeps the
        // covered set maximal by construction, and cannot hide a gap the way R5 warns about:
        // what it excludes is exactly what is supported, and that support is separately pinned
        // by the round-trip tests naming each case as a literal.
        let implemented = Set(MessagePayload.ContentType.allCases.map(\.rawValue))
        XCTAssertFalse(implemented.isEmpty, "an empty content-type set would vacuously pass")

        for type in UInt8.min...UInt8.max where !implemented.contains(type) {
            var bytes = Data([MessagePayload.version, type])
            bytes.append(contentsOf: Array("looks like a message".utf8))

            XCTAssertThrowsError(try MessagePayload.decode(bytes)) { error in
                XCTAssertEqual(error as? MessagePayloadError, .unsupportedContent(type))
            }
        }
        // Type 0 is in that sweep, and is called out here too because an all-zero buffer is the
        // cheapest thing to send and 0 is deliberately never assigned.
        XCTAssertFalse(implemented.contains(0))
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

    // MARK: - Expiring text (P6.S03)

    func testExpiringTextRoundTripsWithItsTimer() throws {
        let payload = MessagePayload(content: .expiringText("gone soon", ttlSeconds: 3600))
        let decoded = try MessagePayload.decode(try payload.encode())
        XCTAssertEqual(decoded, payload)
    }

    func testAnExpiringPayloadIsADistinctWireTypeFromText() throws {
        // Not a version bump, deliberately: a version this build does not know is refused for
        // *every* message, while an unknown type costs only the messages that use it. The type
        // byte is what makes that containment possible, so it has to be the thing that differs.
        let timed = try MessagePayload(content: .expiringText("x", ttlSeconds: 30)).encode()
        let plain = try MessagePayload(content: .text("x")).encode()
        XCTAssertEqual(timed[timed.startIndex], MessagePayload.version)
        XCTAssertEqual(plain[plain.startIndex], MessagePayload.version)
        XCTAssertNotEqual(timed[timed.startIndex + 1], plain[plain.startIndex + 1])
        // Four bytes of timer between the header and the text.
        XCTAssertEqual(timed.count, plain.count + 4)
    }

    func testATimerOfZeroIsRefusedInBothDirections() throws {
        // Zero is the one value that would be ambiguous with `.text`, and a payload that can be
        // read two ways is a payload that will be.
        XCTAssertThrowsError(
            try MessagePayload(content: .expiringText("x", ttlSeconds: 0)).encode()
        ) { error in
            XCTAssertEqual(error as? MessagePayloadError, .invalidExpiry(0))
        }

        var hostile = Data([MessagePayload.version, 2])
        hostile.append(contentsOf: [0, 0, 0, 0])
        hostile.append(Data("x".utf8))
        XCTAssertThrowsError(try MessagePayload.decode(hostile)) { error in
            XCTAssertEqual(error as? MessagePayloadError, .invalidExpiry(0))
        }
    }

    func testATimerBeyondTheCeilingIsRefused() throws {
        let tooLong = MessagePayload.maxExpirySeconds + 1
        XCTAssertThrowsError(
            try MessagePayload(content: .expiringText("x", ttlSeconds: tooLong)).encode()
        ) { error in
            XCTAssertEqual(error as? MessagePayloadError, .invalidExpiry(tooLong))
        }

        // And from a hostile peer, which is the direction that matters: an unbounded value here
        // reaches a date computation downstream.
        var hostile = Data([MessagePayload.version, 2])
        withUnsafeBytes(of: UInt32.max.bigEndian) { hostile.append(contentsOf: $0) }
        hostile.append(Data("x".utf8))
        XCTAssertThrowsError(try MessagePayload.decode(hostile)) { error in
            XCTAssertEqual(error as? MessagePayloadError, .invalidExpiry(.max))
        }
    }

    func testTheCeilingItselfIsAccepted() throws {
        // The positive control for the bound above. A gate that refuses everything is not a
        // bound, and refusing a legal-looking timer from a future build would drop the message
        // rather than the timer.
        let payload = MessagePayload(
            content: .expiringText("x", ttlSeconds: MessagePayload.maxExpirySeconds))
        XCTAssertEqual(try MessagePayload.decode(try payload.encode()), payload)
    }

    func testABodyTooShortToHoldATimerIsMalformed() throws {
        // Read as a zero-length timer this would become a message that never expires — a
        // truncated payload outliving what its sender asked for.
        for length in 0..<4 {
            var truncated = Data([MessagePayload.version, 2])
            truncated.append(Data(repeating: 0x01, count: length))
            XCTAssertThrowsError(try MessagePayload.decode(truncated)) { error in
                XCTAssertEqual(
                    error as? MessagePayloadError, .malformed,
                    "a \(length)-byte timer must be malformed, not defaulted")
            }
        }
    }

    func testAnExpiringPayloadWithInvalidUTF8IsRefused() throws {
        var hostile = Data([MessagePayload.version, 2])
        withUnsafeBytes(of: UInt32(30).bigEndian) { hostile.append(contentsOf: $0) }
        hostile.append(Data([0xFF, 0xFE]))
        XCTAssertThrowsError(try MessagePayload.decode(hostile)) { error in
            XCTAssertEqual(error as? MessagePayloadError, .malformed)
        }
    }

    func testAnExpiringPayloadDecodesFromASlicedBuffer() throws {
        var backing = Data([0xFF, 0xFF, 0xFF])
        let payload = MessagePayload(content: .expiringText("sliced", ttlSeconds: 90))
        backing.append(try payload.encode())
        XCTAssertEqual(try MessagePayload.decode(backing.dropFirst(3)), payload)
    }

    // MARK: Attachments (P6.S04)

    private func attachment(
        byteCount: Int = 4096, ttlSeconds: UInt32? = nil
    ) -> MessagePayload.Attachment {
        MessagePayload.Attachment(
            blobId: UUID(uuidString: "4e0d2c1a-0000-4000-8000-0123456789ab")!,
            key: Data(repeating: 0xA1, count: AttachmentCipher.keyBytes),
            digest: Data(repeating: 0xB2, count: AttachmentCipher.digestBytes),
            byteCount: byteCount, ttlSeconds: ttlSeconds)
    }

    func testAnAttachmentPointerRoundTripsWithAndWithoutATimer() throws {
        for ttl in [nil, UInt32(3600)] {
            let payload = MessagePayload(content: .attachment(attachment(ttlSeconds: ttl)))
            XCTAssertEqual(try MessagePayload.decode(try payload.encode()), payload)
        }
    }

    func testAnAttachmentIsItsOwnTypeAndAFixedWidth() throws {
        let encoded = try MessagePayload(content: .attachment(attachment())).encode()
        XCTAssertEqual(encoded[encoded.startIndex], MessagePayload.version)
        // A new type rather than a version bump: an older build refuses one kind of message
        // instead of all of them.
        XCTAssertEqual(encoded[encoded.startIndex + 1], 3)
        XCTAssertEqual(encoded.count, 2 + MessagePayload.attachmentBodySize)
    }

    func testAnAttachmentBodyOfTheWrongWidthIsRefused() throws {
        let encoded = try MessagePayload(content: .attachment(attachment())).encode()

        for mutated in [encoded.dropLast(), encoded + Data([0x00])] {
            XCTAssertThrowsError(try MessagePayload.decode(Data(mutated))) { error in
                XCTAssertEqual(error as? MessagePayloadError, .malformedAttachment)
            }
        }
    }

    func testAPeerCannotNameALengthThisBuildWouldAllocateFor() throws {
        // The value that would size a download and a buffer, chosen by an untrusted party. Both
        // ends of the range, because zero is as wrong as enormous — an attachment with no bytes
        // is a fetch that can never satisfy its own length check.
        let encoded = try MessagePayload(content: .attachment(attachment())).encode()
        let lengthOffset = encoded.count - 4

        for hostile in [UInt32(0), UInt32(AttachmentCipher.maxPlaintextBytes) + 1] {
            var mutated = encoded
            withUnsafeBytes(of: hostile.bigEndian) { bytes in
                for (index, byte) in bytes.enumerated() {
                    mutated[mutated.startIndex + lengthOffset + index] = byte
                }
            }
            XCTAssertThrowsError(try MessagePayload.decode(mutated)) { error in
                XCTAssertEqual(
                    error as? MessagePayloadError, .malformedAttachment,
                    "a declared length of \(hostile) was accepted")
            }
        }
    }

    func testTheLargestLegalAttachmentLengthIsStillAccepted() throws {
        // The positive control for the bound above.
        let payload = MessagePayload(
            content: .attachment(attachment(byteCount: AttachmentCipher.maxPlaintextBytes)))
        XCTAssertEqual(try MessagePayload.decode(try payload.encode()), payload)
    }

    func testAnAttachmentTimerIsHeldToTheSameCeilingAsText() throws {
        var encoded = try MessagePayload(content: .attachment(attachment())).encode()
        let hostile = MessagePayload.maxExpirySeconds + 1
        withUnsafeBytes(of: hostile.bigEndian) { bytes in
            for (index, byte) in bytes.enumerated() {
                encoded[encoded.startIndex + 2 + index] = byte
            }
        }
        XCTAssertThrowsError(try MessagePayload.decode(encoded)) { error in
            XCTAssertEqual(error as? MessagePayloadError, .invalidExpiry(hostile))
        }
    }

    func testAnAttachmentPointerThisBuildCannotHonourIsRefusedBeforeItIsSent() throws {
        // The encoder applies the decoder's bounds to our own values, so a pointer that could
        // be built here and refused there — a message the recipient loses for a reason the
        // sender never saw — cannot leave this device.
        let shortKey = MessagePayload.Attachment(
            blobId: UUID(), key: Data(repeating: 1, count: 8),
            digest: Data(repeating: 2, count: AttachmentCipher.digestBytes),
            byteCount: 10, ttlSeconds: nil)
        XCTAssertThrowsError(
            try MessagePayload(content: .attachment(shortKey)).encode()
        ) { error in
            XCTAssertEqual(error as? MessagePayloadError, .malformedAttachment)
        }
    }

    func testAnAttachmentDecodesFromASlicedBuffer() throws {
        var backing = Data([0xFF, 0xFF, 0xFF])
        let payload = MessagePayload(content: .attachment(attachment(ttlSeconds: 30)))
        backing.append(try payload.encode())
        XCTAssertEqual(try MessagePayload.decode(backing.dropFirst(3)), payload)
    }
}
