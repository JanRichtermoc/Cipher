//
//  MessagePadding.swift
//  CipherCrypto
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

/// Rounds a plaintext up to one of a small fixed set of sizes before it is encrypted, so the
/// length of a relayed frame says as little as possible about the length of the message
/// (P7.S02, `THREAT_MODEL.md` §3.5).
///
/// ## Why it is applied to the plaintext and not to the ciphertext
///
/// The step is written as "pad ciphertext to fixed buckets", and padding the ciphertext is the
/// one place this cannot go. A Signal ciphertext is authenticated: bytes appended to it do not
/// decrypt, they fail. Making them strippable would mean carrying the real length beside the
/// padded one — in the envelope, in cleartext, which is the exact number the padding exists to
/// hide. Padding *inside* the encryption has neither problem: the recipient recovers the
/// length from bytes only they can read, and the ciphertext length follows the padded plaintext
/// through a fixed per-message overhead, so bucketing the input buckets the output.
///
/// ## The scheme
///
/// `plaintext || 0x80 || 0x00…` up to the next bucket. Stripping scans back over the zero bytes
/// and requires the first non-zero byte to be the terminator. This is Signal's own padding
/// construction, and it is framing rather than cryptography: it adds no secrecy and is not
/// relied on for any, which is why using it here is not "inventing" anything.
///
/// A terminator is needed because the alternative — a length prefix — puts an attacker-chosen
/// number in front of a buffer, and every parser that has ever trusted one has had to learn not
/// to. Here a malformed padding costs the message and nothing else.
///
/// ## What this buys, and what it does not
///
/// It hides *how long a message is within its bucket*: a one-word reply and a paragraph both
/// leave as 256 bytes of plaintext. It does **not** hide that a message was sent, when it was
/// sent, how many were sent, or the difference between a first message and a later one — a
/// session-establishing payload carries prekeys and is visibly larger regardless of padding.
/// It is a cost increase for an observer who is counting bytes, not a defence against one who
/// is watching the link. Against a global passive adversary it does nothing worth claiming, and
/// the roadmap says so in as many words.
internal enum MessagePadding {

    /// The byte that marks the end of the real content. Non-zero on purpose: the padding it
    /// terminates is zeros, so scanning back for the first non-zero byte finds exactly it.
    internal static let terminator: UInt8 = 0x80

    /// Every size a padded plaintext may take.
    ///
    /// Doubling from 256 rather than a fine-grained ladder: nine values across the whole legal
    /// range is few enough that a length is close to uninformative, and the cost is bounded —
    /// at worst a message is sent at twice its size, and the smallest possible message costs
    /// 256 bytes on a link that is already carrying a ~350-byte sealed-sender container.
    ///
    /// The last entry is not a doubling. It exists because the largest legal payload
    /// (`MessagePayload.maxEncodedBytes`, 32 KiB) needs at least one byte more than the bucket
    /// below it to hold its terminator, and a scheme whose top bucket cannot fit the largest
    /// message it must carry is one that refuses valid messages at the ceiling.
    internal static let buckets: [Int] = [
        256, 512, 1024, 2048, 4096, 8192, 16384, 32768,
        MessagePayload.maxEncodedBytes + 256,
    ]

    /// The largest plaintext that can be padded at all.
    internal static var maxPlaintextBytes: Int { (buckets.last ?? 0) - 1 }

    /// Rounds `plaintext` up to the smallest bucket that can hold it and its terminator.
    internal static func pad(_ plaintext: Data) throws -> Data {
        // Strictly greater: a plaintext that exactly fills a bucket still needs somewhere to
        // put the terminator, and silently promoting it to the next bucket is correct — quietly
        // dropping the terminator would make the length unrecoverable.
        guard let bucket = buckets.first(where: { $0 > plaintext.count }) else {
            throw MessagingError.messageTooLarge(plaintext.count)
        }

        var out = Data(capacity: bucket)
        out.append(plaintext)
        out.append(terminator)
        out.append(Data(repeating: 0, count: bucket - out.count))
        return out
    }

    /// Recovers the original plaintext, refusing anything that is not this scheme's output.
    ///
    /// These bytes come from a peer whose session authenticated them, which makes them genuine
    /// and not necessarily well-formed: a compromised peer chooses them freely. Every failure
    /// here is refused rather than repaired, because the repair — returning the buffer as if it
    /// were content — hands the caller trailing NUL bytes that are valid UTF-8 and would be
    /// rendered as a message.
    internal static func strip(_ padded: Data) throws -> Data {
        // From `startIndex`: a `Data` sliced out of a larger buffer does not start at zero.
        guard let end = padded.lastIndex(where: { $0 != 0 }) else {
            // All zeros, or empty. Neither can be this scheme's output, which always contains
            // the terminator.
            throw MessagingError.malformedPadding
        }
        guard padded[end] == terminator else { throw MessagingError.malformedPadding }
        return Data(padded[padded.startIndex..<end])
    }
}
