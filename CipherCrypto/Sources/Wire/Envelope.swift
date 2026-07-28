//
//  Envelope.swift
//  CipherCrypto
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import LibSignalClient

/// The unit the server relays. It carries a Signal ciphertext and the minimum routing
/// metadata needed to deliver it.
///
/// ## The envelope is NOT authenticated — this is the single most important thing about it
///
/// Every field here is attacker-controlled. The transport is a hostile network and the
/// server is untrusted, so a malicious or compromised relay can forge, replay, reorder, or
/// rewrite any header byte. Nothing in an `Envelope` may be trusted for a security
/// decision.
///
/// In particular `sender` is a **routing hint only**. The authentic sender identity is the
/// one bound into the Double Ratchet session that successfully decrypts `ciphertext`;
/// callers must attribute a decrypted message to the session they actually decrypted with,
/// never to this field. Authenticity and integrity come from the Signal ciphertext, which
/// is exactly why end-to-end encryption still holds when TLS does not.
///
/// `timestamp` is likewise untrusted, and is retained only so a client can detect gross
/// skew and display ordering hints. It must never gate a cryptographic decision.
///
/// ## Wire format v1 (big-endian, fixed layout)
///
/// ```text
///  offset  size  field
///       0     1  wireVersion   always 0x01
///       1     1  type          1 = preKey, 2 = whisper, 3 = plaintext; others reserved
///       2    17  sender        ServiceId.serviceIdFixedWidthBinary
///      19     8  timestamp     UInt64, milliseconds since the Unix epoch
///      27     4  ciphertextLen UInt32
///      31     N  ciphertext
/// ```
///
/// Total size is exactly `31 + N`.
///
/// Design notes:
///
/// - The **sender uses libsignal's own** `serviceIdFixedWidthBinary`, not a hand-rolled
///   UUID encoding. It is always 17 bytes and distinguishes ACI from PNI, so no new
///   serialization was invented and PNI support needs no format change.
/// - `wireVersion` plus a reserved `type` space is what lets **sealed sender** arrive later
///   without a wire break: a future version can omit `sender` entirely, and new payload
///   types can be added without redefining existing ones.
/// - `deviceId` is deliberately **absent** (single-device decision). Adding multi-device is
///   a breaking change requiring `wireVersion` 2 — recorded, not hidden.
/// - Timestamps are milliseconds, matching libsignal's convention for sessions and
///   certificates. (Group-send endorsements use seconds; no such value appears here.)
public struct Envelope: Sendable, Equatable {

    /// Payload discriminator.
    ///
    /// Modelled as an enum with explicit wire values because *our* format is closed and
    /// versioned. This is unlike libsignal's `CiphertextMessage.MessageType`, which is a
    /// `RawRepresentable` struct and therefore always needs a `default` branch — the
    /// conversion below handles that asymmetry explicitly.
    /// Live payload types.
    ///
    /// **Value 3 is reserved for `PlaintextContent` and deliberately NOT live.** That is the
    /// carrier for `DecryptionErrorMessage` session resets, and it is unauthenticated: it
    /// does not travel through `signalEncrypt`, so the only sender binding would be this
    /// envelope's `sender` field — which is a routing hint an attacker controls. In Signal
    /// the equivalent path is authenticated by sealed sender, which this phase defers.
    ///
    /// Accepting it would hand a malicious relay a free session-reset primitive:
    /// `SignalMessage.senderRatchetKey` is a cleartext header field readable without any
    /// key, so a relay can take a ratchet key out of a message it relayed, wrap it in a
    /// forged `DecryptionErrorMessage`, and send it back. `currentRatchetKeyMatches` then
    /// succeeds by construction and the victim archives the session — repeatable
    /// indefinitely, burning a one-time prekey pair per cycle and training the user to
    /// ignore genuine "session reset" warnings. Worse, since the destination is the
    /// attacker-chosen sender field, it reflects: garbage addressed to A claiming to be
    /// from B makes A attack B's prekey pool.
    ///
    /// When session resets are needed, the `DecryptionErrorMessage` must be carried as the
    /// *plaintext of an ordinary encrypted message*, so authentication comes from the
    /// ratchet. Reserving the value keeps that door open without a wire break.
    public enum PayloadType: UInt8, Sendable, CaseIterable {
        /// A `PreKeySignalMessage` — establishes a session.
        case preKey = 1
        /// A `SignalMessage` — an established-session message.
        case whisper = 2
    }

    /// Reserved, not live. See `PayloadType`.
    internal static let reservedPlaintextType: UInt8 = 3

    public static let wireVersion: UInt8 = 1
    public static let headerSize = 31

    /// Upper bound on a single relayed ciphertext.
    ///
    /// Attachments travel out of band as separately encrypted blobs, so an envelope only
    /// ever carries message text or control content. The cap exists so a hostile server
    /// cannot induce a large allocation by claiming an enormous length.
    public static let maxCiphertextBytes = 64 * 1024

    public let type: PayloadType
    /// Routing hint only. See the type-level warning — never trust this.
    public let sender: ServiceId
    /// Untrusted, milliseconds since the Unix epoch.
    public let timestamp: UInt64
    public let ciphertext: Data

    public init(type: PayloadType, sender: ServiceId, timestamp: UInt64, ciphertext: Data) throws {
        guard !ciphertext.isEmpty else { throw EnvelopeError.emptyCiphertext }
        guard ciphertext.count <= Self.maxCiphertextBytes else {
            throw EnvelopeError.ciphertextTooLarge(ciphertext.count)
        }
        self.type = type
        self.sender = sender
        self.timestamp = timestamp
        self.ciphertext = ciphertext
    }

    // MARK: - Encoding

    public func encode() -> Data {
        var out = Data(capacity: Self.headerSize + ciphertext.count)
        out.append(Self.wireVersion)
        out.append(type.rawValue)
        out.append(sender.serviceIdFixedWidthBinary)
        out.append(bigEndian: timestamp)
        out.append(bigEndian: UInt32(ciphertext.count))
        out.append(ciphertext)
        return out
    }

    // MARK: - Decoding

    /// Parses an envelope, rejecting anything malformed.
    ///
    /// Decoding is strict on purpose. This is a parser fed directly by a hostile network,
    /// so it is the module's largest malformed-input surface and is fuzzed accordingly.
    public static func decode(_ bytes: Data) throws -> Envelope {
        guard bytes.count >= headerSize else {
            throw EnvelopeError.truncated(expected: headerSize, actual: bytes.count)
        }

        // Index from `startIndex`: a `Data` sliced from a larger buffer does not start at 0,
        // and assuming it does is a classic and silent parsing bug.
        let base = bytes.startIndex

        let version = bytes[base]
        guard version == wireVersion else { throw EnvelopeError.unsupportedWireVersion(version) }

        let rawType = bytes[base + 1]
        guard let type = PayloadType(rawValue: rawType) else {
            throw EnvelopeError.unknownPayloadType(rawType)
        }

        // Structural checks run before the sender is parsed. Ordering matters: parsing the
        // sender first would let a malformed identifier mask a length violation, and it
        // would mean doing work on a frame already known to be invalid.
        let timestamp = bytes.readBigEndian(UInt64.self, at: base + 19)
        let claimedLength = bytes.readBigEndian(UInt32.self, at: base + 27)

        guard claimedLength <= UInt32(maxCiphertextBytes) else {
            throw EnvelopeError.ciphertextTooLarge(Int(claimedLength))
        }
        guard claimedLength > 0 else { throw EnvelopeError.emptyCiphertext }

        // The declared length must account for exactly the remaining bytes. A shorter value
        // would let a server smuggle unparsed trailing data past the client; a longer one is
        // truncation. Either way the frame is not what it claims, so it is rejected rather
        // than repaired.
        let available = bytes.count - headerSize
        guard Int(claimedLength) == available else {
            throw EnvelopeError.lengthMismatch(declared: Int(claimedLength), available: available)
        }

        let sender = try decodeSender(Data(bytes[(base + 2)..<(base + 19)]))
        let ciphertext = Data(bytes[(base + headerSize)...])
        return try Envelope(type: type, sender: sender, timestamp: timestamp, ciphertext: ciphertext)
    }

    /// Reconstructs a `ServiceId` from libsignal's 17-byte fixed-width encoding.
    ///
    /// libsignal's own fixed-width parser is `internal`, and the public
    /// `parseFrom(serviceIdBinary:)` takes the *variable*-width form — 16 bytes for an ACI,
    /// which would defeat a fixed-offset layout. So the encoding is libsignal's
    /// (`serviceIdFixedWidthBinary`: `[kind][16 UUID bytes]`, per `ServiceId.swift:60-64`)
    /// while the decode is built from public initialisers. `testFixedWidthLayoutMatchesLibsignal`
    /// pins the two halves together, so an upstream layout change fails the suite rather
    /// than silently producing wrong identities.
    private static func decodeSender(_ bytes: Data) throws -> ServiceId {
        precondition(bytes.count == 17)
        let base = bytes.startIndex

        var raw = uuid_t(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        _ = withUnsafeMutableBytes(of: &raw) { dest in
            bytes[(base + 1)...].copyBytes(to: dest)
        }
        let uuid = UUID(uuid: raw)

        guard let kind = ServiceIdKind(rawValue: bytes[base]) else {
            throw EnvelopeError.invalidSender
        }
        switch kind {
        case .aci: return Aci(fromUUID: uuid)
        case .pni: return Pni(fromUUID: uuid)
        }
    }

    // MARK: - libsignal interop

    /// Maps libsignal's open `MessageType` onto our closed wire enum.
    ///
    /// `CiphertextMessage.MessageType` is a `RawRepresentable` struct, not an enum, so an
    /// unknown value is representable and must be handled. `.senderKey` is recognised and
    /// explicitly rejected: group messaging is out of scope this phase, and silently
    /// relaying a sender-key message would be worse than refusing it.
    public static func payloadType(
        for messageType: CiphertextMessage.MessageType
    ) throws -> PayloadType {
        switch messageType {
        case .preKey: return .preKey
        case .whisper: return .whisper
        case .plaintext: throw EnvelopeError.unauthenticatedPayloadRefused
        case .senderKey: throw EnvelopeError.groupMessagingNotSupported
        default: throw EnvelopeError.unknownPayloadType(messageType.rawValue)
        }
    }
}

// MARK: - Errors

public enum EnvelopeError: Error, Equatable, Sendable {
    case truncated(expected: Int, actual: Int)
    case unsupportedWireVersion(UInt8)
    case unknownPayloadType(UInt8)
    case lengthMismatch(declared: Int, available: Int)
    case ciphertextTooLarge(Int)
    case emptyCiphertext
    case invalidSender
    case groupMessagingNotSupported
    /// A `PlaintextContent` payload was refused because nothing authenticates its sender
    /// while sealed sender is deferred. See `Envelope.PayloadType`.
    case unauthenticatedPayloadRefused
}

// MARK: - Fixed-width helpers

private extension Data {
    mutating func append<T: FixedWidthInteger>(bigEndian value: T) {
        // Qualified: inside a Data extension, the bare name resolves to Data's own
        // instance method rather than the global function.
        Swift.withUnsafeBytes(of: value.bigEndian) { append(contentsOf: $0) }
    }

    /// Reads a big-endian integer without assuming any alignment of the backing buffer.
    func readBigEndian<T: FixedWidthInteger>(_: T.Type, at offset: Int) -> T {
        var value: T = 0
        for i in 0..<MemoryLayout<T>.size {
            value = (value << 8) | T(self[offset + i])
        }
        return value
    }
}
