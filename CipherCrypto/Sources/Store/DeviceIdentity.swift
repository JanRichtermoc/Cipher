//
//  DeviceIdentity.swift
//  CipherCrypto
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import LibSignalClient

/// This installation's long-term identity: the identity key pair every session is
/// authenticated against, and the registration id that distinguishes this installation
/// from a reinstall.
///
/// ## Why this is the most sensitive object in the app
///
/// The identity private key is what a safety number commits to. Anyone holding a copy can
/// impersonate this installation to any peer that has already verified it, and the peer
/// would see **no safety-number change** — the one signal a user is taught to check. It
/// therefore never leaves the Keychain in a form that can be backed up, synced, or
/// migrated: see `Keychain` for the attribute reasoning.
///
/// ## Creation is atomic, on purpose
///
/// The app and a future notification-service extension are separate processes over one
/// Keychain, and both can reach first launch. `SecretStorage.addOrLoad` resolves that race
/// in the Keychain rather than in this file; whichever process loses simply adopts the
/// winner's identity. A read-then-write here would let the loser overwrite the winner and
/// silently invalidate every session established in between — a failure that would surface
/// to users only as peers reporting a changed safety number.
///
/// Not `Sendable`: `IdentityKeyPair` wraps a Rust handle and is not `Sendable` either. Like
/// everything else in this module it is confined to the crypto domain.
internal struct DeviceIdentity {

    /// Keychain account holding the serialized identity record.
    internal static let account = "device-identity"

    /// Record layout, big-endian and fixed:
    ///
    /// ```text
    ///  offset  size  field
    ///       0     1  version         always 0x01
    ///       1     4  registrationId  UInt32
    ///       5     N  identityKeyPair IdentityKeyPair.serialize()
    /// ```
    private static let version: UInt8 = 1
    private static let headerSize = 5

    /// Registration ids are 14 bits on the wire, and 0 is avoided so "unset" and a real id
    /// are never the same value.
    private static let registrationIdRange: ClosedRange<UInt32> = 1...0x3FFF

    internal let identityKeyPair: IdentityKeyPair
    internal let registrationId: UInt32

    internal var identityKey: IdentityKey { identityKeyPair.identityKey }

    // MARK: - Lifecycle

    /// Returns the stored identity, creating one on first use.
    ///
    /// The identity is always decoded from whatever the Keychain reports as stored, never
    /// from the locally generated candidate. That keeps one parsing path and guarantees the
    /// returned value is the one on disk even when this process lost the creation race.
    internal static func loadOrCreate(secrets: SecretStorage) throws -> DeviceIdentity {
        CryptoActor.assertIsolated()

        if var existing = try secrets.load(account) {
            // The blob carries the identity private key. Wiping our copy is best-effort and
            // does not reach the Keychain's own — which is the point of the Keychain — but
            // it keeps the plaintext key out of a heap that a later crash report might
            // capture. The wipe copy-on-writes away from any storage the caller's secret
            // store still holds, so it cannot destroy the stored record.
            defer { existing.resetBytes(in: existing.startIndex..<existing.endIndex) }
            return try decode(existing)
        }

        // `UInt32.random(in:)` draws from the system CSPRNG and is free of modulo bias.
        let registrationId = UInt32.random(in: registrationIdRange)
        var candidate = try encode(identityKeyPair: IdentityKeyPair.generate(),
                                   registrationId: registrationId)
        defer { candidate.resetBytes(in: candidate.startIndex..<candidate.endIndex) }

        var stored = try secrets.addOrLoad(candidate, forKey: account)
        defer { stored.resetBytes(in: stored.startIndex..<stored.endIndex) }

        return try decode(stored)
    }

    /// Destroys the identity.
    ///
    /// This is not undoable and it is not partial: without the identity key every stored
    /// session is dead weight, so callers must clear the record store in the same
    /// operation. `CipherProtocolStore.destroyAllState` does both.
    internal static func destroy(secrets: SecretStorage) throws {
        CryptoActor.assertIsolated()
        try secrets.remove(account)
    }

    // MARK: - Coding

    private static func encode(identityKeyPair: IdentityKeyPair, registrationId: UInt32) throws
        -> Data {
        var serialized = identityKeyPair.serialize()
        // Best-effort: this copy is ours and is uniquely referenced. The Rust-side buffer
        // behind it is freed by a plain drop with no zeroization, which remains outside
        // this module's control and is recorded as a residual risk.
        defer { serialized.resetBytes(in: serialized.startIndex..<serialized.endIndex) }

        guard !serialized.isEmpty else { throw DeviceIdentityError.malformedRecord }

        var out = Data(capacity: headerSize + serialized.count)
        out.append(version)
        withUnsafeBytes(of: registrationId.bigEndian) { out.append(contentsOf: $0) }
        out.append(serialized)
        return out
    }

    private static func decode(_ bytes: Data) throws -> DeviceIdentity {
        guard bytes.count > headerSize else { throw DeviceIdentityError.malformedRecord }

        // Index from `startIndex`: a `Data` handed back by the Keychain need not start at 0.
        let base = bytes.startIndex

        guard bytes[base] == version else {
            throw DeviceIdentityError.unsupportedRecordVersion(bytes[base])
        }

        var registrationId: UInt32 = 0
        for offset in 1..<headerSize {
            registrationId = (registrationId << 8) | UInt32(bytes[base + offset])
        }
        guard registrationIdRange.contains(registrationId) else {
            throw DeviceIdentityError.malformedRecord
        }

        let identityKeyPair: IdentityKeyPair
        do {
            identityKeyPair = try IdentityKeyPair(bytes: Data(bytes[(base + headerSize)...]))
        } catch {
            throw DeviceIdentityError.malformedRecord
        }

        return DeviceIdentity(identityKeyPair: identityKeyPair, registrationId: registrationId)
    }
}

// MARK: - Errors

internal enum DeviceIdentityError: Error, Equatable {
    /// The stored record is not a well-formed identity.
    ///
    /// Deliberately **not** recoverable by regenerating: silently minting a new identity
    /// after a corrupt read would break every existing session and change the safety number
    /// with no user-visible cause, which is exactly what an attacker who can damage the
    /// Keychain would want. Recovery is a deliberate, user-initiated reset.
    case malformedRecord
    case unsupportedRecordVersion(UInt8)
}
