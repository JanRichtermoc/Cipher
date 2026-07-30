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
    internal enum ContentType: UInt8 {
        case text = 1
    }

    public enum Content: Sendable, Equatable {
        case text(String)
    }

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
    case unsupportedContent(UInt8)
    case tooLarge(Int)
}
