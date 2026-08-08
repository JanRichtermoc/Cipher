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
///       1     1  type          1 = preKey, 2 = whisper, 4 = sealed; 3 reserved
///       2    17  sender        ServiceId.serviceIdFixedWidthBinary, or 17 zero bytes
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
/// - `wireVersion` plus a reserved `type` space is what let **sealed sender** arrive (P7.S01)
///   without a wire break: `.sealed` is a new type rather than a new version, so a peer on an
///   older build refuses only sealed messages instead of every message.
/// - `deviceId` is deliberately **absent** (single-device decision). Adding multi-device is
///   a breaking change requiring `wireVersion` 2 — recorded, not hidden.
/// - Timestamps are milliseconds, matching libsignal's convention for sessions and
///   certificates. (Group-send endorsements use seconds; no such value appears here.)
///
/// ## The sender field is absent on a sealed envelope, and that is checked
///
/// A `.sealed` frame keeps the fixed layout — so the relay's size bounds, its `CHECK`
/// constraint and this parser all stay exactly as they were — but the 17 sender bytes must be
/// **zero**, and `sender` decodes as `nil`. A non-zero value is refused rather than ignored:
/// ignoring it would leave a field a sending client could fill in by accident and a relay
/// could fill in on purpose, and "the byte is there but we promise not to read it" is not a
/// property anyone can verify from a seized database. Refusing costs an attacker a dropped
/// message, which is something they could achieve by not delivering it at all.
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
    /// the equivalent path is authenticated by a *server-issued* sealed-sender certificate.
    ///
    /// **P7.S01 did not change this.** Cipher has sealed sender now, but its certificate is
    /// issued by the sending account to itself (`CryptoEngine.selfIssuedSenderCertificate`),
    /// so the name in it is worth exactly what the cleartext field was worth. The reason to
    /// refuse value 3 is unchanged, and "we have sealed sender now" is not an argument for
    /// making it live.
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
        /// A sealed-sender container: one of the two above, wrapped so that only the
        /// recipient can see which it is and who sent it (P7.S01, AUDIT 3.4).
        ///
        /// The refusals above do **not** stop applying because the payload is sealed — they
        /// move inside it. `Messaging.swift` runs the *inner* type through
        /// `payloadType(for:)` after opening the container and before touching a session, so
        /// a sender-key or `PlaintextContent` payload is refused whether it arrives in the
        /// open or wrapped. A sealed container that skipped that check would be a bypass of
        /// both locked decisions at once, since sealing hides the inner type from every
        /// other layer.
        case sealed = 4
    }

    /// Reserved, not live. See `PayloadType`.
    internal static let reservedPlaintextType: UInt8 = 3

    /// The 17 bytes a sealed envelope carries where an addressed one carries a sender.
    ///
    /// Zero rather than random: a fixed value is checkable, and a random one would be a
    /// covert channel with a plausible excuse. It is not a valid identifier — it is the
    /// absence of one, spelled in a fixed-width layout that has no way to omit a field.
    internal static let absentSenderBytes = Data(repeating: 0, count: ServiceIdentifier.encodedSize)

    public static let wireVersion: UInt8 = 1
    public static let headerSize = 31

    /// Upper bound on a single relayed ciphertext.
    ///
    /// Attachments travel out of band as separately encrypted blobs, so an envelope only
    /// ever carries message text or control content. The cap exists so a hostile server
    /// cannot induce a large allocation by claiming an enormous length.
    public static let maxCiphertextBytes = 64 * 1024

    public let type: PayloadType
    /// Routing hint only, and `nil` on a sealed envelope. See the type-level warning — never
    /// trust this. Optional rather than a sentinel value so every caller has to decide what
    /// to do when the frame names nobody, instead of comparing against a magic identifier.
    public let sender: ServiceIdentifier?
    /// Untrusted, milliseconds since the Unix epoch.
    public let timestamp: UInt64
    public let ciphertext: Data

    public init(type: PayloadType, sender: ServiceIdentifier?, timestamp: UInt64, ciphertext: Data)
        throws {
        guard !ciphertext.isEmpty else { throw EnvelopeError.emptyCiphertext }
        guard ciphertext.count <= Self.maxCiphertextBytes else {
            throw EnvelopeError.ciphertextTooLarge(ciphertext.count)
        }
        // Enforced on construction as well as on decoding, so the invariant belongs to the
        // type rather than to the parser: an encoder cannot produce a frame the decoder
        // would refuse, which is the asymmetry that turns a wire rule into a live bug.
        switch (type, sender) {
        case (.sealed, .some): throw EnvelopeError.senderPresentOnSealedEnvelope
        case (.preKey, .none), (.whisper, .none): throw EnvelopeError.senderMissing
        default: break
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
        out.append(sender?.fixedWidthBinary ?? Self.absentSenderBytes)
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

        let senderBytes = Data(bytes[(base + 2)..<(base + 19)])
        let sender: ServiceIdentifier?
        switch type {
        case .sealed:
            // A sealed frame names nobody. The bytes are still read and still checked —
            // skipping the check would leave seventeen bytes a hostile relay could use as a
            // channel, and would make "sealed carries no sender" a claim about intent
            // rather than about the frame.
            guard senderBytes == absentSenderBytes else {
                throw EnvelopeError.senderPresentOnSealedEnvelope
            }
            sender = nil
        case .preKey, .whisper:
            sender = try ServiceIdentifier.decode(fixedWidth: senderBytes)
        }

        let ciphertext = Data(bytes[(base + headerSize)...])
        return try Envelope(type: type, sender: sender, timestamp: timestamp, ciphertext: ciphertext)
    }

    // MARK: - libsignal interop

    /// Maps libsignal's open `MessageType` onto our closed wire enum.
    ///
    /// `CiphertextMessage.MessageType` is a `RawRepresentable` struct, not an enum, so an
    /// unknown value is representable and must be handled. `.senderKey` is recognised and
    /// explicitly rejected: group messaging is out of scope this phase, and silently
    /// relaying a sender-key message would be worse than refusing it.
    ///
    /// `internal`: this is the one place a libsignal type meets our wire enum, so making it
    /// public would put `CiphertextMessage.MessageType` in this module's public API — the
    /// exact leak `Scripts/verify-api-boundary.sh` exists to prevent, and the one it caught.
    /// Nothing outside needs it: `CryptoEngine.encrypt` already returns an encoded envelope.
    ///
    /// It never returns `.sealed`, and cannot: sealing is our framing, not a libsignal
    /// message type. That is why the same call can be reused on the *inner* type of a sealed
    /// container — the two refusals it makes are about the payload, not about the wrapper.
    internal static func payloadType(
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
    /// A `PlaintextContent` payload was refused because nothing authenticates its sender.
    /// See `Envelope.PayloadType`.
    case unauthenticatedPayloadRefused
    /// A `.sealed` frame carried a sender where it must carry seventeen zero bytes.
    case senderPresentOnSealedEnvelope
    /// An addressed frame carried no sender. Only `.sealed` may omit one.
    case senderMissing
    /// A sealed certificate named a device other than the only one wire v1 can address.
    ///
    /// Locked decision §0.2.5: the wire has no `deviceId`, and libsignal's certificate does.
    /// Accepting a second device here would let multi-device arrive through the sealed
    /// container without the `wireVersion` 2 that decision requires.
    case sealedSenderDeviceRefused(UInt32)
    /// A sealed certificate named something other than a bare ACI — a PNI, a phone number,
    /// or an unparseable string. Locked decision §0.2.7: Cipher issues neither of the first
    /// two and must not learn to read one.
    case sealedSenderIdentifierRefused
    /// The sealed certificate's public key is not the key the session authenticated.
    ///
    /// Together with the check libsignal already makes — the certificate's key must be the
    /// key whose holder sealed the container, or it refuses with "sender certificate key does
    /// not match message key" — this says **the sealer is the session owner**. That is what
    /// stops a third party who holds a plaintext Signal ciphertext, such as a relay that
    /// captured an addressed frame, from wrapping it in a container of its own and having it
    /// delivered under a name it does not own.
    ///
    /// It is not a check on the *identifier*. Anyone can mint a certificate naming any
    /// account (see `CryptoEngine.selfIssuedSenderCertificate`); what they cannot do is make
    /// it carry a key they do not hold, or a key that opens somebody else's session.
    case sealedSenderKeyMismatch
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
