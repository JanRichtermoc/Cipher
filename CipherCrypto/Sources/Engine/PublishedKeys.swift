//
//  PublishedKeys.swift
//  CipherCrypto
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import LibSignalClient

/// This installation's own prekey material, in the form the relay publishes.
///
/// Every field is a **public** key or a signature over one — the private halves stay in the
/// sealed record store and have no accessor anywhere. That is what makes it safe for this
/// type to leave the crypto domain and be encoded into a request body.
///
/// ## Kyber is not optional
///
/// PQXDH is a locked decision (plan §0.2), and both halves of it are represented here: a
/// last-resort Kyber prekey that is reused when the one-time pool is empty, and a pool of
/// one-time Kyber prekeys that are not. `BACKEND.md` §2.6 states the cost of the fallback —
/// sessions that land on the reused key share their KEM contribution — which is exactly why
/// the pool exists and why the relay refuses an upload without the last-resort key.
public struct PublishedKeys: Sendable, Equatable {

    /// A public key with its signature under this installation's identity key. The relay
    /// stores the signature and deliberately does not verify it (`BACKEND.md` §2.5); the
    /// *peer* verifies it inside `processPreKeyBundle` on every use, which is the only place
    /// a verification is worth anything under a hostile-relay model.
    public struct SignedKey: Sendable, Equatable {
        public let keyId: UInt32
        public let publicKey: Data
        public let signature: Data
    }

    public struct OneTimeKey: Sendable, Equatable {
        public let keyId: UInt32
        public let publicKey: Data
    }

    public let signedPreKey: SignedKey
    public let kyberLastResort: SignedKey
    public let kyberPreKeys: [SignedKey]
    public let oneTimePreKeys: [OneTimeKey]
}

extension CryptoEngine {

    /// How many one-time keys of each kind a fresh publication carries.
    ///
    /// A pool size is a policy, not a constant of nature: every session another device starts
    /// with this one consumes one curve prekey and one Kyber prekey, and when the Kyber pool
    /// empties the relay falls back to the reused last-resort key. The relay caps an upload at
    /// 200 of each (`api.maxPreKeysPerUpload`) and limits publication to 6 per day, so this is
    /// sized to be replenished rarely rather than to be minimal. Replenishment on a threshold
    /// is P6.S01; until then this is the whole pool an installation ever has.
    public static let defaultOneTimePreKeyCount = 100

    /// Generates a fresh set of prekeys, **persists the private halves**, and returns the
    /// public halves to publish.
    ///
    /// ## The order is the security property
    ///
    /// Private halves are stored before this returns, so the caller cannot publish keys whose
    /// private halves do not exist locally. Reversed, a crash between publishing and storing
    /// would leave peers fetching a bundle this device cannot answer: their first message would
    /// arrive addressed to a prekey that was never saved and would fail to decrypt, for good.
    /// A crash *before* publishing costs nothing but a few unused records.
    ///
    /// ## Ids come from the monotonic counter, never from what is on disk
    ///
    /// `reservePreKeyIds` advances a stored counter, so an id is never reissued even though
    /// libsignal deletes a one-time prekey the moment it is consumed. Reusing one would let a
    /// replayed prekey message be matched against a brand-new private key.
    ///
    /// - Parameter oneTimeCount: how many one-time curve *and* Kyber prekeys to mint.
    public func generatePublishedKeys(
        oneTimeCount: Int = CryptoEngine.defaultOneTimePreKeyCount
    ) throws -> PublishedKeys {
        try requireLive()
        precondition(oneTimeCount > 0, "a publication with no one-time prekeys is not one")

        let context = NullContext()
        let identity = try store.identityKeyPair(context: context)
        let timestamp = now()

        // One reservation for everything: the signed prekey, the last-resort Kyber key, the
        // Kyber pool and the curve pool. Ids only have to be unique within their own store
        // namespace, and one counter for all of them cannot produce a collision in any of
        // them — while two counters could drift apart and be reconciled wrongly.
        let ids = try store.reservePreKeyIds(count: 2 + oneTimeCount * 2)
        var next = ids.lowerBound

        func take() -> UInt32 {
            defer { next += 1 }
            return next
        }

        // --- signed prekey -------------------------------------------------------------
        let signedPreKeyId = take()
        let signedPrivate = PrivateKey.generate()
        let signedPublic = signedPrivate.publicKey
        let signedSignature = identity.privateKey.generateSignature(
            message: signedPublic.serialize())
        try store.storeSignedPreKey(
            try SignedPreKeyRecord(
                id: signedPreKeyId, timestamp: timestamp,
                privateKey: signedPrivate, signature: signedSignature),
            id: signedPreKeyId, context: context)

        // --- Kyber last resort ---------------------------------------------------------
        let lastResortId = take()
        let lastResortPair = KEMKeyPair.generate()
        let lastResortSignature = identity.privateKey.generateSignature(
            message: lastResortPair.publicKey.serialize())
        try store.storeKyberPreKey(
            try KyberPreKeyRecord(
                id: lastResortId, timestamp: timestamp,
                keyPair: lastResortPair, signature: lastResortSignature),
            id: lastResortId, context: context)

        // --- one-time Kyber prekeys ----------------------------------------------------
        var kyberPreKeys: [PublishedKeys.SignedKey] = []
        kyberPreKeys.reserveCapacity(oneTimeCount)
        for _ in 0..<oneTimeCount {
            let id = take()
            let pair = KEMKeyPair.generate()
            let signature = identity.privateKey.generateSignature(
                message: pair.publicKey.serialize())
            try store.storeKyberPreKey(
                try KyberPreKeyRecord(
                    id: id, timestamp: timestamp, keyPair: pair, signature: signature),
                id: id, context: context)
            kyberPreKeys.append(
                PublishedKeys.SignedKey(
                    keyId: id, publicKey: pair.publicKey.serialize(),
                    signature: Data(signature)))
        }

        // --- one-time curve prekeys ----------------------------------------------------
        var oneTimePreKeys: [PublishedKeys.OneTimeKey] = []
        oneTimePreKeys.reserveCapacity(oneTimeCount)
        for _ in 0..<oneTimeCount {
            let id = take()
            let priv = PrivateKey.generate()
            let pub = priv.publicKey
            try store.storePreKey(
                try PreKeyRecord(id: id, privateKey: priv), id: id, context: context)
            oneTimePreKeys.append(
                PublishedKeys.OneTimeKey(keyId: id, publicKey: pub.serialize()))
        }

        CipherLog.keys.info("generated a prekey publication")

        return PublishedKeys(
            signedPreKey: PublishedKeys.SignedKey(
                keyId: signedPreKeyId, publicKey: signedPublic.serialize(),
                signature: Data(signedSignature)),
            kyberLastResort: PublishedKeys.SignedKey(
                keyId: lastResortId, publicKey: lastResortPair.publicKey.serialize(),
                signature: Data(lastResortSignature)),
            kyberPreKeys: kyberPreKeys,
            oneTimePreKeys: oneTimePreKeys)
    }

    /// How many unused one-time curve prekeys remain locally.
    ///
    /// Local, not the relay's count: the relay reports its own remaining pool on publication,
    /// and the two diverge the moment a bundle is dispensed. Replenishment (P6.S01) has to
    /// reconcile both; this is the half that cannot be lied about by a hostile relay.
    public var remainingOneTimePreKeys: Int {
        get throws {
            try requireLive()
            return try store.remainingPreKeyCount()
        }
    }
}
