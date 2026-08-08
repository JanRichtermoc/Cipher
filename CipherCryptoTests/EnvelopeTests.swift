//
//  EnvelopeTests.swift
//  CipherCryptoTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest
import LibSignalClient
@testable import CipherCrypto

final class EnvelopeTests: XCTestCase {

    // A fixed ACI so the vectors below are deterministic.
    private let libsignalAci = Aci(fromUUID: UUID(uuidString: "de305d54-75b4-431b-adb2-eb6b9e546014")!)
    private let aci = ServiceIdentifier(
        kind: .aci, uuid: UUID(uuidString: "de305d54-75b4-431b-adb2-eb6b9e546014")!)
    private let timestamp: UInt64 = 0x0000_0193_A1B2_C3D4
    private let ciphertext = Data([0xDE, 0xAD, 0xBE, 0xEF])

    private func sample() throws -> Envelope {
        try Envelope(type: .whisper, sender: aci, timestamp: timestamp, ciphertext: ciphertext)
    }

    // MARK: - Known-answer vectors

    /// Pins the byte layout field by field.
    ///
    /// This is a regression vector for a format we define ourselves, so it proves the
    /// encoding has not drifted — not that it agrees with some external specification.
    /// Any change here is a wire break and must come with a `wireVersion` bump.
    func testEncodingMatchesTheDocumentedLayout() throws {
        let encoded = try sample().encode()

        XCTAssertEqual(encoded.count, Envelope.headerSize + ciphertext.count)
        XCTAssertEqual(encoded.count, 35)

        XCTAssertEqual(encoded[0], 1, "wireVersion")
        XCTAssertEqual(encoded[1], 2, "type = whisper")

        // Compared against *libsignal's* encoding, not our own: this byte range is the
        // golden vector, so checking it against the type that produced it would prove
        // nothing.
        XCTAssertEqual(Data(encoded[2..<19]), libsignalAci.serviceIdFixedWidthBinary,
                       "sender uses libsignal's own 17-byte fixed-width encoding")
        XCTAssertEqual(Data(encoded[2..<19]).count, 17)

        XCTAssertEqual(Array(encoded[19..<27]),
                       [0x00, 0x00, 0x01, 0x93, 0xA1, 0xB2, 0xC3, 0xD4],
                       "timestamp is big-endian UInt64 milliseconds")

        XCTAssertEqual(Array(encoded[27..<31]), [0x00, 0x00, 0x00, 0x04],
                       "ciphertext length is big-endian UInt32")

        XCTAssertEqual(Data(encoded[31...]), ciphertext)
    }

    func testEncodingIsDeterministic() throws {
        XCTAssertEqual(try sample().encode(), try sample().encode())
    }

    func testRoundTripPreservesEveryField() throws {
        let decoded = try Envelope.decode(try sample().encode())
        XCTAssertEqual(decoded.type, .whisper)
        XCTAssertEqual(decoded.sender, aci)
        XCTAssertEqual(decoded.timestamp, timestamp)
        XCTAssertEqual(decoded.ciphertext, ciphertext)
    }

    func testRoundTripForEveryPayloadType() throws {
        for type in Envelope.PayloadType.allCases {
            // `.sealed` names nobody; the other two must. Driven off the type rather than
            // listed, so a new payload type has to state which side of that line it is on.
            let sender: ServiceIdentifier? = type == .sealed ? nil : aci
            let env = try Envelope(
                type: type, sender: sender, timestamp: 1, ciphertext: Data([0x01]))
            let decoded = try Envelope.decode(env.encode())
            XCTAssertEqual(decoded.type, type)
            XCTAssertEqual(decoded.sender, sender)
        }
    }

    // MARK: - Sealed frames name nobody (P7.S01)

    /// The seventeen sender bytes of a sealed frame are zero, and that is checked on the way
    /// in rather than assumed. A frame the parser merely *ignored* would leave a relay a place
    /// to write, and would make "sealed carries no sender" a promise instead of a property.
    func testSealedEnvelopesCarryZeroWhereASenderWouldBe() throws {
        let encoded = try Envelope(
            type: .sealed, sender: nil, timestamp: timestamp, ciphertext: ciphertext).encode()

        XCTAssertEqual(encoded[1], 4, "type = sealed")
        XCTAssertEqual(Data(encoded[2..<19]), Data(repeating: 0, count: 17))
        XCTAssertEqual(encoded.count, Envelope.headerSize + ciphertext.count,
                       "the layout is unchanged, so the relay's size bounds still hold")
        XCTAssertNil(try Envelope.decode(encoded).sender)
    }

    func testSealedEnvelopeCarryingASenderIsRefused() throws {
        var encoded = try Envelope(
            type: .sealed, sender: nil, timestamp: 1, ciphertext: ciphertext).encode()
        encoded.replaceSubrange(2..<19, with: aci.fixedWidthBinary)

        XCTAssertThrowsError(try Envelope.decode(encoded)) { error in
            XCTAssertEqual(error as? EnvelopeError, .senderPresentOnSealedEnvelope)
        }

        // A single non-zero byte is enough — the check is on all seventeen, not on the kind.
        var oneByte = try Envelope(
            type: .sealed, sender: nil, timestamp: 1, ciphertext: ciphertext).encode()
        oneByte[18] = 0x01
        XCTAssertThrowsError(try Envelope.decode(oneByte)) { error in
            XCTAssertEqual(error as? EnvelopeError, .senderPresentOnSealedEnvelope)
        }
    }

    /// The same invariant on the encoding side, so a frame this module produces can never be
    /// one it would refuse to read.
    func testConstructionEnforcesTheSenderRuleInBothDirections() {
        XCTAssertThrowsError(
            try Envelope(type: .sealed, sender: aci, timestamp: 1, ciphertext: ciphertext)
        ) { XCTAssertEqual($0 as? EnvelopeError, .senderPresentOnSealedEnvelope) }

        for addressed: Envelope.PayloadType in [.preKey, .whisper] {
            XCTAssertThrowsError(
                try Envelope(type: addressed, sender: nil, timestamp: 1, ciphertext: ciphertext)
            ) { XCTAssertEqual($0 as? EnvelopeError, .senderMissing) }
        }
    }

    // MARK: - The fixed-width ServiceId contract

    /// `ServiceIdentifier` re-implements libsignal's 17-byte layout so no libsignal type
    /// crosses the module boundary. That is only safe while the two encodings agree
    /// **byte for byte**, because the same bytes address store slots and travel on the wire.
    /// This asserts the agreement against the real library, in both directions, for both
    /// namespaces — so an upstream layout change fails here instead of silently producing a
    /// different identity that would look like a peer who had re-keyed.
    func testFixedWidthLayoutMatchesLibsignal() throws {
        let uuid = UUID(uuidString: "de305d54-75b4-431b-adb2-eb6b9e546014")!

        for reference in [Aci(fromUUID: uuid) as ServiceId, Pni(fromUUID: uuid) as ServiceId] {
            let ours = ServiceIdentifier(reference)

            XCTAssertEqual(ours.fixedWidthBinary, reference.serviceIdFixedWidthBinary,
                           "our encoding diverged from libsignal's")
            XCTAssertEqual(ours.kind.rawValue, reference.kind.rawValue)
            XCTAssertEqual(ours.uuid, uuid)

            // And back out of an envelope, which is the path that actually runs.
            let env = try Envelope(type: .whisper, sender: ours,
                                   timestamp: 7, ciphertext: Data([0x01]))
            let decoded = try Envelope.decode(env.encode())
            XCTAssertEqual(decoded.sender, ours)
            XCTAssertEqual(decoded.sender?.canonicalString, reference.serviceIdString,
                           "the store slot a peer maps to must match libsignal's naming")
        }
    }

    /// `ServiceIdentifier.canonicalString` delegates into the Rust core rather than
    /// hand-rolling the per-namespace format, because that string names the record-store
    /// slot for every session and trust decision. Pinned separately from the layout: the two
    /// could drift independently.
    func testCanonicalStringMatchesLibsignal() throws {
        let uuid = UUID(uuidString: "de305d54-75b4-431b-adb2-eb6b9e546014")!
        XCTAssertEqual(
            ServiceIdentifier(kind: .aci, uuid: uuid).canonicalString,
            Aci(fromUUID: uuid).serviceIdString)
        XCTAssertEqual(
            ServiceIdentifier(kind: .pni, uuid: uuid).canonicalString,
            Pni(fromUUID: uuid).serviceIdString)
        XCTAssertNotEqual(
            ServiceIdentifier(kind: .aci, uuid: uuid).canonicalString,
            ServiceIdentifier(kind: .pni, uuid: uuid).canonicalString,
            "one UUID in two namespaces must not collapse to one store slot")
    }

    /// ACI and PNI with the same UUID must not be interchangeable on the wire.
    func testAciAndPniAreDistinguishedOnTheWire() throws {
        let uuid = UUID(uuidString: "de305d54-75b4-431b-adb2-eb6b9e546014")!
        let aciEnv = try Envelope(type: .whisper, sender: ServiceIdentifier(kind: .aci, uuid: uuid),
                                  timestamp: 7, ciphertext: Data([0x01])).encode()
        let pniEnv = try Envelope(type: .whisper, sender: ServiceIdentifier(kind: .pni, uuid: uuid),
                                  timestamp: 7, ciphertext: Data([0x01])).encode()

        XCTAssertNotEqual(aciEnv, pniEnv, "the kind byte must distinguish them")
        XCTAssertEqual(try Envelope.decode(aciEnv).sender?.kind, .aci)
        XCTAssertEqual(try Envelope.decode(pniEnv).sender?.kind, .pni)
    }

    func testRejectsUnknownServiceIdKind() throws {
        var encoded = try sample().encode()
        encoded[2] = 0x7F
        XCTAssertThrowsError(try Envelope.decode(encoded)) { error in
            XCTAssertEqual(error as? EnvelopeError, .invalidSender)
        }
    }

    // MARK: - Decoding a slice

    /// A `Data` produced by slicing does not start at index 0. A parser that assumes it
    /// does reads the wrong bytes and fails silently — so decoding must be indexed from
    /// `startIndex`.
    func testDecodesCorrectlyFromANonZeroStartIndex() throws {
        let encoded = try sample().encode()
        var padded = Data([0xFF, 0xFF, 0xFF])
        padded.append(encoded)
        let slice = padded[3...]

        XCTAssertNotEqual(slice.startIndex, 0, "precondition: the slice is offset")
        let decoded = try Envelope.decode(slice)
        XCTAssertEqual(decoded.ciphertext, ciphertext)
        XCTAssertEqual(decoded.timestamp, timestamp)
    }

    // MARK: - Malformed input is rejected, never repaired

    func testRejectsTruncatedHeader() throws {
        let encoded = try sample().encode()
        for length in 0..<Envelope.headerSize {
            XCTAssertThrowsError(try Envelope.decode(encoded.prefix(length)),
                                 "a \(length)-byte frame must not parse")
        }
    }

    func testRejectsUnsupportedWireVersion() throws {
        var encoded = try sample().encode()
        encoded[0] = 2
        XCTAssertThrowsError(try Envelope.decode(encoded)) { error in
            XCTAssertEqual(error as? EnvelopeError, .unsupportedWireVersion(2))
        }
    }

    /// 4 is absent from this list because it became `.sealed` in P7.S01. 3 stays reserved.
    func testRejectsReservedAndUnknownPayloadTypes() throws {
        for raw: UInt8 in [0, 5, 6, 200, 255] {
            var encoded = try sample().encode()
            encoded[1] = raw
            XCTAssertThrowsError(try Envelope.decode(encoded)) { error in
                XCTAssertEqual(error as? EnvelopeError, .unknownPayloadType(raw))
            }
        }
    }

    /// A short declared length would leave unparsed trailing bytes the client never sees —
    /// a smuggling channel. A long one is truncation. Both must be refused.
    func testRejectsDeclaredLengthThatDisagreesWithTheFrame() throws {
        var short = try sample().encode()
        short[30] = 0x03
        XCTAssertThrowsError(try Envelope.decode(short)) { error in
            XCTAssertEqual(error as? EnvelopeError, .lengthMismatch(declared: 3, available: 4))
        }

        var long = try sample().encode()
        long[30] = 0x05
        XCTAssertThrowsError(try Envelope.decode(long)) { error in
            XCTAssertEqual(error as? EnvelopeError, .lengthMismatch(declared: 5, available: 4))
        }
    }

    func testRejectsTrailingGarbage() throws {
        var encoded = try sample().encode()
        encoded.append(contentsOf: [0x00, 0x00])
        XCTAssertThrowsError(try Envelope.decode(encoded))
    }

    /// A hostile server must not be able to induce a large allocation by claiming an
    /// enormous length in a small frame.
    func testRejectsAbsurdDeclaredLengthWithoutAllocating() throws {
        var encoded = try sample().encode()
        encoded[27] = 0xFF; encoded[28] = 0xFF; encoded[29] = 0xFF; encoded[30] = 0xFF
        XCTAssertThrowsError(try Envelope.decode(encoded)) { error in
            XCTAssertEqual(error as? EnvelopeError, .ciphertextTooLarge(Int(UInt32.max)))
        }
    }

    func testRejectsEmptyCiphertextOnConstructionAndDecoding() throws {
        XCTAssertThrowsError(
            try Envelope(type: .whisper, sender: aci, timestamp: 1, ciphertext: Data())
        ) { XCTAssertEqual($0 as? EnvelopeError, .emptyCiphertext) }

        var encoded = try sample().encode()
        encoded[30] = 0x00
        XCTAssertThrowsError(try Envelope.decode(encoded.prefix(Envelope.headerSize)))
    }

    func testRejectsOversizedCiphertextOnConstruction() {
        let tooBig = Data(repeating: 0, count: Envelope.maxCiphertextBytes + 1)
        XCTAssertThrowsError(
            try Envelope(type: .whisper, sender: aci, timestamp: 1, ciphertext: tooBig)
        ) { XCTAssertEqual($0 as? EnvelopeError, .ciphertextTooLarge(Envelope.maxCiphertextBytes + 1)) }
    }

    func testAcceptsCiphertextExactlyAtTheLimit() throws {
        let atLimit = Data(repeating: 0xA5, count: Envelope.maxCiphertextBytes)
        let env = try Envelope(type: .whisper, sender: aci, timestamp: 1, ciphertext: atLimit)
        XCTAssertEqual(try Envelope.decode(env.encode()).ciphertext.count, Envelope.maxCiphertextBytes)
    }

    // MARK: - libsignal type mapping

    func testMapsLibsignalMessageTypes() throws {
        XCTAssertEqual(try Envelope.payloadType(for: .preKey), .preKey)
        XCTAssertEqual(try Envelope.payloadType(for: .whisper), .whisper)
    }

    /// `PlaintextContent` carries `DecryptionErrorMessage` and does not go through
    /// `signalEncrypt`, so nothing authenticates its sender — and P7.S01 did not change that,
    /// because Cipher's sealed-sender certificate is self-issued. Accepting it would give a
    /// malicious relay a session-reset primitive it could aim at any peer. It must be refused
    /// on both the encode and decode side.
    func testRefusesUnauthenticatedPlaintextContent() throws {
        XCTAssertThrowsError(try Envelope.payloadType(for: .plaintext)) { error in
            XCTAssertEqual(error as? EnvelopeError, .unauthenticatedPayloadRefused)
        }

        var encoded = try sample().encode()
        encoded[1] = Envelope.reservedPlaintextType
        XCTAssertThrowsError(try Envelope.decode(encoded)) { error in
            XCTAssertEqual(error as? EnvelopeError,
                           .unknownPayloadType(Envelope.reservedPlaintextType))
        }
    }

    /// Group messaging is out of scope; a sender-key message must be refused loudly rather
    /// than relayed as if it were understood.
    func testRejectsSenderKeyMessages() {
        XCTAssertThrowsError(try Envelope.payloadType(for: .senderKey)) { error in
            XCTAssertEqual(error as? EnvelopeError, .groupMessagingNotSupported)
        }
    }

    /// `CiphertextMessage.MessageType` is a RawRepresentable struct, so values outside the
    /// known set exist and must hit a `default` branch instead of trapping.
    func testRejectsUnknownLibsignalMessageType() {
        let unknown = CiphertextMessage.MessageType(rawValue: 200)
        XCTAssertThrowsError(try Envelope.payloadType(for: unknown)) { error in
            XCTAssertEqual(error as? EnvelopeError, .unknownPayloadType(200))
        }
    }

    // MARK: - Fuzz

    /// Random and mutated input must always produce an error or a valid envelope — never a
    /// crash, a trap, or an out-of-bounds read.
    func testDecodeNeverTrapsOnArbitraryInput() throws {
        var rng = SystemRandomNumberGenerator()

        for _ in 0..<2_000 {
            let length = Int.random(in: 0...80, using: &rng)
            let random = Data((0..<length).map { _ in UInt8.random(in: 0...255, using: &rng) })
            _ = try? Envelope.decode(random)
        }

        let valid = try sample().encode()
        for _ in 0..<2_000 {
            var mutated = valid
            let index = Int.random(in: 0..<mutated.count, using: &rng)
            mutated[index] = UInt8.random(in: 0...255, using: &rng)
            _ = try? Envelope.decode(mutated)
        }
    }
}
