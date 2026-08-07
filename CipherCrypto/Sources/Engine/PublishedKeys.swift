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
    /// sized to be replenished rarely rather than to be minimal. `MessageRepository.maintainKeys`
    /// (P6.S01) owns *when* a pool is topped back up to this size, and by how much — this module
    /// mints what it is asked for and has no opinion about the schedule.
    public static let defaultOneTimePreKeyCount = 100

    /// How long a superseded signed prekey or last-resort Kyber key stays usable.
    ///
    /// Rotation cannot delete the key it replaces on the spot. A peer that fetched this
    /// account's bundle a moment before the rotation still holds the *old* signed prekey id,
    /// and their first message names it; deleting the private half immediately turns that
    /// message into a permanent `invalidKeyIdentifier` for a peer who did nothing wrong.
    /// Thirty days is far longer than a bundle stays in a sender's hands in practice, and it
    /// bounds what accumulates — which is the other half of rotation being an improvement
    /// rather than a leak.
    public static let retiredPreKeyRetentionMs: UInt64 = 30 * 24 * 60 * 60 * 1000

    /// Generates a fresh set of prekeys, **persists the private halves**, and returns the
    /// public halves to publish.
    ///
    /// ## Publishing *is* rotating (P6.S01)
    ///
    /// There is no publish-without-rotate path, because the relay has no upload shape for one:
    /// `validate()` refuses a body missing `signed_prekey` or `kyber_last_resort`
    /// (`BACKEND.md` §2.5/§2.6), so every publication carries a signed prekey and a last-resort
    /// Kyber key and replaces the stored ones. This mints new ones rather than re-sending the
    /// live pair, which is what makes a periodic top-up also bound the lifetime of a
    /// compromised prekey — the whole of AUDIT 2.4.
    ///
    /// The pair this replaces is **retired, not deleted** (see ``retiredPreKeyRetentionMs``),
    /// and pairs whose retention has elapsed are pruned here, so the record set stays bounded
    /// without a second scheduler.
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
    /// replayed prekey message be matched against a brand-new private key. Rotation makes that
    /// property load-bearing rather than incidental: it is now normal for this device to hold
    /// several signed prekeys at once, and two of them sharing an id would resolve to whichever
    /// record was written last.
    ///
    /// - Parameter oneTimeCount: how many one-time curve *and* Kyber prekeys to mint. **Zero is
    ///   legal and means "rotate only"** — a rotation that falls due while the relay-side pool
    ///   is still full has nothing to top up, and minting a hundred keypairs to satisfy a
    ///   signature would be the tail wagging the dog.
    public func generatePublishedKeys(
        oneTimeCount: Int = CryptoEngine.defaultOneTimePreKeyCount
    ) throws -> PublishedKeys {
        try requireLive()
        precondition(oneTimeCount >= 0, "a negative pool size is a caller bug")

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

        // Retire the pair this replaces and prune anything past its retention, in that order:
        // the record has to name the outgoing ids before they stop being the live ones, or a
        // crash here would leave them unreferenced and therefore never pruned.
        try store.recordPreKeyRotation(
            signedPreKeyId: signedPreKeyId, kyberLastResortId: lastResortId, at: timestamp,
            retention: Self.retiredPreKeyRetentionMs)

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
    /// and the two diverge the moment a bundle is dispensed. Replenishment (P6.S01) reconciles
    /// both; this is the half that cannot be lied about by a hostile relay.
    public var remainingOneTimePreKeys: Int {
        get throws {
            try requireLive()
            return try store.remainingPreKeyCount()
        }
    }

    /// What the scheduler needs to decide whether to publish, and nothing else.
    ///
    /// Read rather than inferred: "when did this installation last rotate" cannot be derived
    /// from the record store, because there is deliberately no key enumeration and a prekey id
    /// carries no timestamp. It is persisted beside the keys it describes, so it is destroyed
    /// with them — a rotation timestamp that outlived the identity would tell the next
    /// installation it had just rotated when it has never published at all.
    public var preKeyState: PreKeyState {
        get throws {
            try requireLive()
            let rotation = try store.preKeyRotation()
            return PreKeyState(
                remainingOneTimePreKeys: try store.remainingPreKeyCount(),
                lastRotationMs: rotation?.rotatedAtMs,
                signedPreKeyId: rotation?.signedPreKeyId,
                retiredPreKeyCount: rotation?.retired.count ?? 0)
        }
    }
}

/// This installation's prekey maintenance state, in a form that can leave the crypto domain.
///
/// Counts and ids only: no key material, and nothing a caller could hand back into an FFI call.
public struct PreKeyState: Sendable, Equatable {
    /// Unused one-time curve prekeys held **locally**. Never below the relay's own count, since
    /// a dispensed key is consumed here only when the peer actually sends.
    public let remainingOneTimePreKeys: Int
    /// When this installation last minted a signed prekey, or `nil` if it never has.
    public let lastRotationMs: UInt64?
    /// The live signed prekey's id, or `nil` before the first publication.
    public let signedPreKeyId: UInt32?
    /// How many superseded signed/last-resort records are still inside their retention window.
    public let retiredPreKeyCount: Int
}
