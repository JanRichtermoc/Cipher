//
//  PeerIdentityRecord.swift
//  CipherCrypto
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import LibSignalClient

/// What is known about one peer's identity key, and whether the user still owes it a look.
///
/// This is the state a "safety number changed" banner is rendered from, so its integrity
/// matters as much as any key: an attacker who could clear `needsAcknowledgement` would
/// suppress the only warning the user ever sees. It is sealed with the rest of the record
/// store and bound to its slot by the AEAD's authenticated data.
internal struct PeerIdentityRecord: Equatable {

    /// ```text
    ///  offset  size  field
    ///       0     1  version              always 0x01
    ///       1     1  flags                bit 0 = change awaiting acknowledgement
    ///                                     bit 1 = user has verified the safety number
    ///       2     8  firstSeenMs          UInt64, milliseconds since the Unix epoch
    ///      10     8  changedAtMs          UInt64, 0 when the key has never changed
    ///      18     N  identityKey          IdentityKey.serialize()
    /// ```
    private static let version: UInt8 = 1
    private static let headerSize = 18
    private static let acknowledgementPendingFlag: UInt8 = 0x01
    private static let verifiedFlag: UInt8 = 0x02

    /// Every flag bit this version understands. A record carrying anything outside this mask
    /// is refused rather than read with the unknown bits dropped.
    ///
    /// The *verified* bit this comment used to name hypothetically is now bit 1 (P5.S12), and
    /// the reasoning it was written to protect is exactly why it is declared here rather than
    /// bolted on: a record carrying a flag this build does not understand is refused, so a
    /// build that predates the bit reads a verified peer as unreadable rather than as
    /// unverified. Refusing is the direction that cannot mislead — a discarded verification
    /// would show a *weaker* trust state than the one recorded, which sounds safe and is not:
    /// it silently retracts a claim the user made after comparing digits out of band, and the
    /// obvious next step for them is to re-verify against whatever key is present now.
    ///
    /// The cost is a downgrade path that loses peer identity records. That is the correct
    /// trade here and is bounded: `saveIdentity` treats an unreadable record as first contact,
    /// so the peer is re-recorded and sending is blocked until the key is accepted again.
    private static let knownFlags: UInt8 = acknowledgementPendingFlag | verifiedFlag

    internal let identityKey: IdentityKey
    /// When this peer's key was first recorded. Untrusted clocks never write here — it is
    /// this device's clock, used only for display.
    internal let firstSeenMs: UInt64
    /// When the key last changed, or `nil` if it never has.
    internal let changedAtMs: UInt64?
    /// True once the key has changed and the user has not yet accepted the new one.
    ///
    /// While this is set, `isTrustedIdentity` refuses the *sending* direction. Receiving is
    /// unaffected — see `CipherProtocolStore` for why the two directions differ.
    internal let needsAcknowledgement: Bool
    /// True once the user has compared this peer's safety number out of band and said it
    /// matched (P5.S12, AUDIT 2.5).
    ///
    /// This is a claim about **this exact `identityKey`** and nothing else. It is not stored
    /// separately from the key for that reason: there is no record of "this peer is verified"
    /// that could outlive the key it was asserted about, so a key change cannot leave a stale
    /// verified badge behind. `saveIdentity` writes the new key with the bit clear, which is
    /// what makes "invalidate on identity change" a property of the format rather than of
    /// someone remembering to clear it.
    internal let isVerified: Bool

    internal init(
        identityKey: IdentityKey,
        firstSeenMs: UInt64,
        changedAtMs: UInt64?,
        needsAcknowledgement: Bool,
        isVerified: Bool = false
    ) {
        self.identityKey = identityKey
        self.firstSeenMs = firstSeenMs
        self.changedAtMs = changedAtMs
        self.needsAcknowledgement = needsAcknowledgement
        self.isVerified = isVerified
    }

    // MARK: - Coding

    internal func encode() -> Data {
        var out = Data(capacity: Self.headerSize + 33)
        out.append(Self.version)
        var flags: UInt8 = 0
        if needsAcknowledgement { flags |= Self.acknowledgementPendingFlag }
        if isVerified { flags |= Self.verifiedFlag }
        out.append(flags)
        out.append(bigEndian: firstSeenMs)
        out.append(bigEndian: changedAtMs ?? 0)
        out.append(identityKey.serialize())
        return out
    }

    internal static func decode(_ bytes: Data) throws -> PeerIdentityRecord {
        guard bytes.count > headerSize else { throw ProtocolStoreError.malformedPeerIdentity }

        // Index from `startIndex`; a `Data` decrypted out of a larger buffer need not
        // start at zero.
        let base = bytes.startIndex

        guard bytes[base] == version else { throw ProtocolStoreError.malformedPeerIdentity }

        let flags = bytes[base + 1]
        guard flags & ~knownFlags == 0 else { throw ProtocolStoreError.malformedPeerIdentity }

        let firstSeenMs = bytes.readBigEndianUInt64(at: base + 2)
        let rawChangedAt = bytes.readBigEndianUInt64(at: base + 10)

        let identityKey: IdentityKey
        do {
            identityKey = try IdentityKey(bytes: Data(bytes[(base + headerSize)...]))
        } catch {
            throw ProtocolStoreError.malformedPeerIdentity
        }

        return PeerIdentityRecord(
            identityKey: identityKey,
            firstSeenMs: firstSeenMs,
            changedAtMs: rawChangedAt == 0 ? nil : rawChangedAt,
            needsAcknowledgement: flags & acknowledgementPendingFlag != 0,
            isVerified: flags & verifiedFlag != 0)
    }
}

// MARK: - Fixed-width helpers

/// File-private, matching `Envelope.swift`. Keeping these scoped to the file that defines a
/// wire layout means no module-wide `Data` overload can silently change how an existing
/// format is encoded.
private extension Data {
    mutating func append(bigEndian value: UInt64) {
        // Qualified: inside a Data extension the bare name resolves to Data's own method.
        Swift.withUnsafeBytes(of: value.bigEndian) { append(contentsOf: $0) }
    }

    /// Reads a big-endian `UInt64` without assuming any alignment of the backing buffer.
    func readBigEndianUInt64(at offset: Int) -> UInt64 {
        var value: UInt64 = 0
        for index in 0..<MemoryLayout<UInt64>.size {
            value = (value << 8) | UInt64(self[offset + index])
        }
        return value
    }
}
