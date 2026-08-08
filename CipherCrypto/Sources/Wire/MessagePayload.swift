//
//  MessagePayload.swift
//  CipherCrypto
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

/// What is *inside* the ciphertext: the plaintext a peer actually sent.
///
/// ## Why this is a format and not just a `String`
///
/// `Envelope` describes the bytes the relay moves; this describes the bytes only the two
/// devices ever see. Sending bare UTF-8 would work exactly once — the first time a second
/// kind of message is needed (an attachment pointer, a read receipt, a reaction, a session
/// reset per locked decision §0.2.4) there would be no way to tell it from someone typing
/// that text, and the only available migration would be a heuristic. A one-byte discriminator
/// now costs nothing and makes every later addition a new case rather than a guess.
///
/// ## Everything here arrives from an authenticated but untrusted party
///
/// The ciphertext is authenticated by the Double Ratchet, so these bytes really were written
/// by the peer whose session decrypted them — but "the peer" is not "a well-behaved client".
/// A compromised or malicious peer chooses these bytes freely, so this decoder is a parser of
/// hostile input and behaves like one:
///
/// - An unknown version or type is **refused**, never rendered. Displaying an unrecognised
///   payload as text is how a future receipt type becomes a message a user reads as if a human
///   wrote it.
/// - Invalid UTF-8 is **refused**, not repaired. `String(decoding:as:)` substitutes U+FFFD,
///   which silently turns malformed input into content — and a caller cannot then tell a
///   damaged message from a message about replacement characters.
/// - Length is bounded here as well as at the envelope, so a payload that could never be sent
///   is rejected before it is built rather than after libsignal has encrypted it.
public struct MessagePayload: Sendable, Equatable {

    /// Wire discriminators. **Raw values are wire-visible**: changing one reinterprets every
    /// message in flight, and 0 is deliberately unused so an all-zero buffer is never a valid
    /// payload.
    internal enum ContentType: UInt8, CaseIterable {
        case text = 1
        /// Text that both devices delete when its timer runs out (P6.S03).
        case expiringText = 2
        /// A pointer to an out-of-band encrypted blob, and the key to open it (P6.S04).
        case attachment = 3
    }

    public enum Content: Sendable, Equatable {
        case text(String)
        /// Text carrying its own lifetime, in seconds from the moment it was sent.
        ///
        /// **The timer is on the message, not on the conversation**, and that is a deliberate
        /// choice rather than a simplification. A conversation-level timer is state that two
        /// devices have to agree about, and they cannot: there is no wire message that changes
        /// it, so the two copies would drift the first time one was set while the other device
        /// was offline — and a message that survives on one side because of a stale setting is
        /// the exact failure a disappearing-message feature exists to prevent. A message that
        /// states its own fate cannot disagree with itself.
        ///
        /// The visible consequence, which the UI has to say rather than hide: setting a timer
        /// governs **the messages you send**. It does not reach into what the other person
        /// sends you, because nothing here can make their client do anything.
        case expiringText(String, ttlSeconds: UInt32)
        /// Everything needed to fetch and open one encrypted attachment (P6.S04).
        case attachment(Attachment)
    }

    /// The pointer to an out-of-band blob, and the key that opens it.
    ///
    /// **This is the only place the attachment key ever exists on the wire**, and it is inside
    /// the Double Ratchet ciphertext. The relay sees the blob and never sees this, which is
    /// what makes its store a directory of opaque objects (`AttachmentCipher`).
    ///
    /// ## The timer is a field here rather than a second content type
    ///
    /// P6.S03 added `.expiringText` beside `.text` because `.text` had already shipped and its
    /// body had no room for a timer. This type is new, so the timer is simply part of it, with
    /// **zero meaning no timer**. That is unambiguous in a way it was not for text: there, a
    /// zero-second timer and an absent one would have been two readings of the same bytes, and
    /// a payload that can be read two ways is one that will be. Here the field is always
    /// present and only its value varies.
    ///
    /// One content type also costs less on the receive path of an older build: an unknown type
    /// is acknowledged and dropped, so every type added is a way for a message to be lost
    /// rather than delayed.
    public struct Attachment: Sendable, Equatable {
        /// The relay's blob id — 122 bits of randomness that *is* the capability to download
        /// it (`BACKEND.md` §2.8). Reaching the recipient only in here is what keeps the
        /// relay from learning who is entitled to the bytes.
        public let blobId: UUID
        /// The AES-256 key for this attachment and no other.
        public let key: Data
        /// SHA-256 of the uploaded ciphertext, checked before the key is used.
        public let digest: Data
        /// Length of the original bytes, before encryption. Bounds the download and is
        /// re-checked against what actually decrypts.
        public let byteCount: Int
        /// Seconds this message lives, or nil for no timer. Same units, same ceiling and the
        /// same meaning as `.expiringText`.
        public let ttlSeconds: UInt32?

        public init(
            blobId: UUID, key: Data, digest: Data, byteCount: Int, ttlSeconds: UInt32?
        ) {
            self.blobId = blobId
            self.key = key
            self.digest = digest
            self.byteCount = byteCount
            self.ttlSeconds = ttlSeconds
        }
    }

    /// The longest lifetime a peer may name: four weeks.
    ///
    /// A bound rather than a policy. Anything larger is refused at the boundary so a hostile
    /// peer cannot hand over a value that overflows a date computation downstream; anything
    /// this size or under is honoured even if no UI offers it, because refusing a legal-looking
    /// timer from a future build would drop the message rather than the timer.
    ///
    /// There is deliberately **no minimum**. A peer who sets a one-second timer makes their own
    /// message unreadable, which is theirs to do; enforcing a floor here would refuse the
    /// message outright and lose content to protect the reader from an inconvenience.
    public static let maxExpirySeconds: UInt32 = 4 * 7 * 24 * 60 * 60

    /// Format version. A payload written by a newer build is refused rather than guessed at.
    public static let version: UInt8 = 1

    /// Ceiling on the encoded payload.
    ///
    /// Well below `Envelope.maxCiphertextBytes` (64 KiB) so a payload that passes here cannot
    /// fail at the envelope after the ratchet has already been stepped — a send that fails
    /// *after* encryption has consumed a chain key is a message the sender cannot retry
    /// identically. 32 KiB is tens of thousands of characters of prose.
    public static let maxEncodedBytes = 32 * 1024

    private static let headerSize = 2
    /// Width of the big-endian timer that precedes the text in an `.expiringText` body, and
    /// that opens an `.attachment` body.
    private static let expirySize = 4

    /// Width of the raw UUID an attachment names its blob by. The 16 bytes, not the 36-character
    /// string: a rendering is a second thing two builds could disagree about.
    private static let blobIdSize = 16
    /// Width of the big-endian plaintext length that closes an `.attachment` body.
    private static let byteCountSize = 4

    /// An `.attachment` body is fixed width, so a parser can refuse a wrong length outright
    /// instead of reading fields out of a buffer that may not hold them.
    internal static let attachmentBodySize =
        expirySize + blobIdSize + AttachmentCipher.keyBytes
        + AttachmentCipher.digestBytes + byteCountSize

    public let content: Content

    public init(content: Content) {
        self.content = content
    }

    /// `[version][type][body…]`
    public func encode() throws -> Data {
        let body: Data
        let type: ContentType

        switch content {
        case .text(let text):
            type = .text
            body = Data(text.utf8)
        case .expiringText(let text, let ttlSeconds):
            guard ttlSeconds > 0, ttlSeconds <= Self.maxExpirySeconds else {
                throw MessagePayloadError.invalidExpiry(ttlSeconds)
            }
            type = .expiringText
            var encoded = Data(capacity: Self.expirySize + text.utf8.count)
            withUnsafeBytes(of: ttlSeconds.bigEndian) { encoded.append(contentsOf: $0) }
            encoded.append(Data(text.utf8))
            body = encoded
        case .attachment(let attachment):
            // The same bounds the decoder applies to a peer's values, applied to our own. A
            // pointer that could be built here and refused there would be a message the
            // recipient loses for a reason the sender never saw.
            if let ttlSeconds = attachment.ttlSeconds {
                guard ttlSeconds > 0, ttlSeconds <= Self.maxExpirySeconds else {
                    throw MessagePayloadError.invalidExpiry(ttlSeconds)
                }
            }
            guard attachment.key.count == AttachmentCipher.keyBytes,
                  attachment.digest.count == AttachmentCipher.digestBytes,
                  attachment.byteCount > 0,
                  attachment.byteCount <= AttachmentCipher.maxPlaintextBytes
            else {
                throw MessagePayloadError.malformedAttachment
            }

            type = .attachment
            var encoded = Data(capacity: Self.attachmentBodySize)
            withUnsafeBytes(of: (attachment.ttlSeconds ?? 0).bigEndian) {
                encoded.append(contentsOf: $0)
            }
            withUnsafeBytes(of: attachment.blobId.uuid) { encoded.append(contentsOf: $0) }
            encoded.append(attachment.key)
            encoded.append(attachment.digest)
            withUnsafeBytes(of: UInt32(attachment.byteCount).bigEndian) {
                encoded.append(contentsOf: $0)
            }
            body = encoded
        }

        let total = Self.headerSize + body.count
        guard total <= Self.maxEncodedBytes else {
            throw MessagePayloadError.tooLarge(total)
        }

        var out = Data(capacity: total)
        out.append(Self.version)
        out.append(type.rawValue)
        out.append(body)
        return out
    }

    public static func decode(_ bytes: Data) throws -> MessagePayload {
        guard bytes.count >= headerSize else { throw MessagePayloadError.malformed }
        guard bytes.count <= maxEncodedBytes else {
            throw MessagePayloadError.tooLarge(bytes.count)
        }

        // From `startIndex`: a `Data` sliced out of a larger buffer does not start at zero.
        let base = bytes.startIndex

        guard bytes[base] == version else {
            throw MessagePayloadError.unsupportedVersion(bytes[base])
        }
        guard let type = ContentType(rawValue: bytes[base + 1]) else {
            throw MessagePayloadError.unsupportedContent(bytes[base + 1])
        }

        let body = bytes[(base + headerSize)...]

        switch type {
        case .text:
            // Strict: `String(data:encoding:)` returns nil on malformed input where
            // `String(decoding:as:)` would substitute U+FFFD and hand back "content".
            guard let text = String(data: Data(body), encoding: .utf8) else {
                throw MessagePayloadError.malformed
            }
            return MessagePayload(content: .text(text))
        case .expiringText:
            // Four bytes of timer, then the text. A body too short to hold the timer is
            // malformed rather than treated as a zero-length one: the alternative is reading a
            // message with no lifetime as one that never expires, which turns a truncated
            // payload into a message that outlives what its sender asked for.
            guard body.count >= Self.expirySize else { throw MessagePayloadError.malformed }
            let start = body.startIndex

            var ttlSeconds: UInt32 = 0
            for offset in 0..<Self.expirySize {
                ttlSeconds = (ttlSeconds << 8) | UInt32(body[start + offset])
            }
            // The same bounds the encoder enforces, applied to an attacker-chosen value. Zero
            // is refused because it is the one value that would be ambiguous with `.text`, and
            // a payload that can be read two ways is a payload that will be.
            guard ttlSeconds > 0, ttlSeconds <= Self.maxExpirySeconds else {
                throw MessagePayloadError.invalidExpiry(ttlSeconds)
            }

            guard let text = String(
                data: Data(body[(start + Self.expirySize)...]), encoding: .utf8)
            else {
                throw MessagePayloadError.malformed
            }
            return MessagePayload(content: .expiringText(text, ttlSeconds: ttlSeconds))
        case .attachment:
            // Fixed width, so anything else is malformed before a single field is read. Every
            // value below is chosen by the peer, so each is bounded here rather than by
            // whatever eventually uses it.
            guard body.count == Self.attachmentBodySize else {
                throw MessagePayloadError.malformedAttachment
            }
            var cursor = body.startIndex

            func take(_ count: Int) -> Data {
                defer { cursor += count }
                return Data(body[cursor..<(cursor + count)])
            }
            func takeBigEndian32() -> UInt32 {
                take(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            }

            let rawTtl = takeBigEndian32()
            // Zero is "no timer" for an attachment; see `Attachment`. Anything positive is
            // held to the same ceiling as an expiring text.
            guard rawTtl <= Self.maxExpirySeconds else {
                throw MessagePayloadError.invalidExpiry(rawTtl)
            }

            let blobId = take(Self.blobIdSize).withUnsafeBytes {
                UUID(uuid: $0.loadUnaligned(as: uuid_t.self))
            }
            let key = take(AttachmentCipher.keyBytes)
            let digest = take(AttachmentCipher.digestBytes)
            let byteCount = takeBigEndian32()

            // Refused *before* anything is fetched: this is the number that would size a
            // download and a buffer, and it arrives from an untrusted party.
            guard byteCount > 0, byteCount <= UInt32(AttachmentCipher.maxPlaintextBytes) else {
                throw MessagePayloadError.malformedAttachment
            }

            return MessagePayload(content: .attachment(Attachment(
                blobId: blobId, key: key, digest: digest, byteCount: Int(byteCount),
                ttlSeconds: rawTtl == 0 ? nil : rawTtl)))
        }
    }
}

public enum MessagePayloadError: Error, Equatable, Sendable {
    /// Too short to hold a header, or the body was not valid UTF-8.
    case malformed
    /// A version this build does not implement. Refused rather than interpreted.
    case unsupportedVersion(UInt8)
    /// A content type this build does not implement — a newer peer, or a peer probing.
    /// Refused rather than rendered as text.
    ///
    /// **This is where a build predating P6.S03 meets an expiring message**, and the cost is
    /// worth naming: the receive path acknowledges a payload it cannot parse and drops it, so
    /// that message is lost rather than delayed. The alternative was bumping `version`, which
    /// would have done the same thing to *every* message instead of only timed ones.
    case unsupportedContent(UInt8)
    case tooLarge(Int)
    /// A timer of zero, or longer than `MessagePayload.maxExpirySeconds`.
    case invalidExpiry(UInt32)
    /// An attachment pointer of the wrong width, or naming a key, digest or plaintext length
    /// this build will not act on. Refused before any blob is fetched.
    case malformedAttachment
}
