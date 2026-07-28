//
//  PeerKeyBundle.swift
//  CipherCrypto
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import LibSignalClient

/// A peer's published PQXDH key bundle, as fetched from the relay.
///
/// Every key is carried as its serialized form rather than as a libsignal handle, for the
/// reasons in `ServiceIdentifier`. That is also the shape it arrives in — the transport
/// hands over bytes — so nothing is converted twice.
///
/// ## This type validates structure, not authenticity
///
/// The relay is hostile (`THREAT_MODEL.md` §1.1), so every field here is attacker-supplied
/// and a well-formed bundle proves nothing. What makes a bundle trustworthy is that the
/// signed-prekey and kyber-prekey signatures verify **against the identity key in the same
/// bundle**, and that check belongs to libsignal's `processPreKeyBundle`, which performs it
/// on every use. Re-implementing it here would be a second, unreviewed copy of a signature
/// check — the one kind of duplication this module refuses.
///
/// That leaves the real question, which no signature can answer: whether the identity key
/// *is the peer's*. A relay can serve an entirely self-consistent bundle for a key it
/// controls. Nothing detects that except the user comparing a safety number out of band
/// (P5.S12); first contact is trust-on-first-use and is recorded as such.
public struct PeerKeyBundle: Sendable, Equatable {

    public let registrationId: UInt32
    public let deviceId: UInt32

    /// The peer's long-term public identity key.
    public let identityKey: Data

    public let preKeyId: UInt32
    public let preKey: Data

    public let signedPreKeyId: UInt32
    public let signedPreKey: Data
    public let signedPreKeySignature: Data

    public let kyberPreKeyId: UInt32
    public let kyberPreKey: Data
    public let kyberPreKeySignature: Data

    public init(
        registrationId: UInt32,
        deviceId: UInt32 = PeerAddress.primaryDevice,
        identityKey: Data,
        preKeyId: UInt32,
        preKey: Data,
        signedPreKeyId: UInt32,
        signedPreKey: Data,
        signedPreKeySignature: Data,
        kyberPreKeyId: UInt32,
        kyberPreKey: Data,
        kyberPreKeySignature: Data
    ) {
        self.registrationId = registrationId
        self.deviceId = deviceId
        self.identityKey = identityKey
        self.preKeyId = preKeyId
        self.preKey = preKey
        self.signedPreKeyId = signedPreKeyId
        self.signedPreKey = signedPreKey
        self.signedPreKeySignature = signedPreKeySignature
        self.kyberPreKeyId = kyberPreKeyId
        self.kyberPreKey = kyberPreKey
        self.kyberPreKeySignature = kyberPreKeySignature
    }
}

// MARK: - libsignal bridge

extension PeerKeyBundle {

    /// Parses into the library's bundle type.
    ///
    /// Only structural failures surface here — a key that is not a point on the curve, a
    /// truncated Kyber key. Signature verification happens later, inside
    /// `processPreKeyBundle`, and its failure is a different and more interesting error.
    internal func makePreKeyBundle() throws -> PreKeyBundle {
        CryptoActor.assertIsolated()
        do {
            return try PreKeyBundle(
                registrationId: registrationId,
                deviceId: deviceId,
                prekeyId: preKeyId,
                prekey: try PublicKey(preKey),
                signedPrekeyId: signedPreKeyId,
                signedPrekey: try PublicKey(signedPreKey),
                signedPrekeySignature: signedPreKeySignature,
                identity: try IdentityKey(bytes: identityKey),
                kyberPrekeyId: kyberPreKeyId,
                kyberPrekey: try KEMPublicKey(kyberPreKey),
                kyberPrekeySignature: kyberPreKeySignature)
        } catch {
            throw MessagingError.malformedKeyBundle
        }
    }
}
