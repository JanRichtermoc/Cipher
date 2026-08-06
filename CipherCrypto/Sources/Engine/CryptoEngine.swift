//
//  CryptoEngine.swift
//  CipherCrypto
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import LibSignalClient

/// The app's handle on the crypto module.
///
/// This is the only type outside this module's own files that anything else is meant to
/// hold, and it is the boundary the isolation argument is built around: it is
/// `@CryptoActor`-isolated, the non-`Sendable` protocol store lives in its storage and never
/// escapes it, and every libsignal call made through it therefore runs on the crypto queue.
/// `IsolationContract` is the compile-time proof that this arrangement is legal; the
/// `assertIsolated` calls throughout the store are the runtime proof that it holds.
///
/// Session and message APIs are not here yet. What is here is everything the app needs to
/// establish, inspect, and destroy this installation's cryptographic identity, which is
/// what the rest depends on.
@CryptoActor
public final class CryptoEngine {

    /// The store owns the record store and the secret storage; the engine holds neither
    /// separately, so there is exactly one object that can reach persistence.
    ///
    /// `internal` rather than `private` only so `Messaging.swift` can reach it. It is not
    /// `public` and never will be: handing a `CipherProtocolStore` out would hand out every
    /// libsignal store protocol at once, and with them the ability to call into the FFI from
    /// wherever the caller happens to be.
    internal let store: CipherProtocolStore

    /// Milliseconds since the Unix epoch, injectable so a test can assert on the timestamp a
    /// message carries rather than around it.
    internal let now: () -> UInt64

    /// Set by `destroyAllState`. Every operation refuses afterwards.
    ///
    /// Without this the engine would keep working from an identity that no longer exists in
    /// the Keychain and a record key that has been deleted: messages would encrypt, records
    /// would be sealed under an orphaned key, and the next launch would mint a fresh
    /// identity and find none of it readable. The failure would appear a launch later, as
    /// peers reporting a changed safety number.
    private enum Lifecycle {
        case live
        case erasing
        case destroyed
    }

    private var lifecycle = Lifecycle.live

    /// Opens the engine, creating this installation's identity on first use.
    ///
    /// - Parameter container: where records live. Defaults to a private directory under
    ///   Application Support — not Documents, which is user-visible and file-sharable, and
    ///   not Caches, which the system may delete out from under a live session.
    public static func open(container: URL? = nil) throws -> CryptoEngine {
        CipherCryptoBootstrap.start()

        let root = try container ?? Self.defaultContainer()
        return try CryptoEngine(root: root, secrets: Keychain.shared)
    }

    internal init(
        root: URL, secrets: SecretStorage,
        now: @escaping () -> UInt64 = { UInt64(Date().timeIntervalSince1970 * 1000) }
    ) throws {
        CryptoActor.assertIsolated()
        self.now = now

        let legacyRecords = try EncryptedFileRecordStore(root: root, secrets: secrets)
        // Built from `records` rather than from `secrets`: its keys are derived from the record
        // encryption key, so there is still exactly one Keychain item whose deletion is a
        // cryptographic erase of every session, prekey, trust decision, conversation and
        // message body at once. See `EncryptedFileRecordStore.deriveSubkey`.
        let database = try SealedRecordDatabase(root: root, keys: legacyRecords)
        let records = DatabaseRecordStore(database: database, legacy: legacyRecords)
        let identity = try DeviceIdentity.loadOrCreate(secrets: secrets)

        self.store = CipherProtocolStore(
            deviceIdentity: identity, records: records, database: database, secrets: secrets)

        CipherLog.store.info("crypto engine opened")
    }

    private static func defaultContainer() throws -> URL {
        try FileManager.default
            .url(for: .applicationSupportDirectory, in: .userDomainMask,
                 appropriateFor: nil, create: true)
            .appendingPathComponent("CipherCrypto", isDirectory: true)
    }

    internal func requireLive() throws {
        guard lifecycle == .live else { throw CryptoEngineError.destroyed }
    }

    // MARK: - Identity

    /// This installation's registration id.
    public var localRegistrationId: UInt32 {
        get throws {
            try requireLive()
            return try store.localRegistrationId(context: NullContext())
        }
    }

    /// The **public** half of this installation's identity key, serialized.
    ///
    /// Public by definition — it is what peers use to compute a safety number — so returning
    /// it does not widen the secret surface. The private half has no accessor at all, in
    /// this type or any other.
    public var localIdentityKey: Data {
        get throws {
            try requireLive()
            return try store.identityKeyPair(context: NullContext()).identityKey.serialize()
        }
    }

    // MARK: - Trust

    /// The stored trust state for a peer, if any.
    public func peerIdentityState(name: String, deviceId: UInt32) throws -> PeerIdentityState? {
        try requireLive()
        let address = try ProtocolAddress(name: name, deviceId: deviceId)
        guard let record = try store.peerIdentity(for: address) else { return nil }
        return PeerIdentityState(
            identityKey: record.identityKey.serialize(),
            firstSeenMs: record.firstSeenMs,
            changedAtMs: record.changedAtMs,
            needsAcknowledgement: record.needsAcknowledgement,
            isVerified: record.isVerified)
    }

    /// Records that the user has seen and accepted `identityKey` for this peer, unblocking
    /// the sending direction.
    ///
    /// - Returns: `false` if the stored key is no longer the one being accepted. The caller
    ///   must then re-present the current key rather than retrying.
    @discardableResult
    public func acceptPeerIdentity(_ identityKey: Data, name: String, deviceId: UInt32) throws
        -> Bool {
        try requireLive()
        let address = try ProtocolAddress(name: name, deviceId: deviceId)
        return try store.acceptIdentity(IdentityKey(bytes: identityKey), for: address)
    }

    /// Records, or withdraws, the user's out-of-band comparison of this peer's safety number.
    ///
    /// Names the key for the same reason `acceptPeerIdentity` does: the digits the user
    /// compared are a function of that exact key, so a verification that did not name it could
    /// be applied to a key they never saw.
    ///
    /// - Returns: `false` if the stored key is no longer the one being verified.
    @discardableResult
    public func setPeerVerified(
        _ verified: Bool, identityKey: Data, name: String, deviceId: UInt32
    ) throws -> Bool {
        try requireLive()
        let address = try ProtocolAddress(name: name, deviceId: deviceId)
        return try store.setIdentityVerified(
            verified, IdentityKey(bytes: identityKey), for: address)
    }

    // MARK: - Trust, addressed the way the app addresses peers
    //
    // The `name:deviceId:` forms above are the primitive; these are what callers outside this
    // module use. The difference is not convenience: `ServiceIdentifier.canonicalString` is
    // internal, so without these an app-side caller would have to reconstruct the address
    // string itself — reimplementing an encoding the store keys records by, in a module that
    // cannot see the definition. `PeerAddress` is already the type the messaging API takes.

    /// The stored trust state for a peer, if any.
    public func peerIdentityState(for address: PeerAddress) throws -> PeerIdentityState? {
        try peerIdentityState(
            name: address.serviceId.canonicalString, deviceId: address.deviceId)
    }

    /// Records that the user has seen and accepted `identityKey` for this peer.
    @discardableResult
    public func acceptPeerIdentity(_ identityKey: Data, for address: PeerAddress) throws -> Bool {
        try acceptPeerIdentity(
            identityKey, name: address.serviceId.canonicalString, deviceId: address.deviceId)
    }

    /// Records, or withdraws, the user's out-of-band comparison of this peer's safety number.
    @discardableResult
    public func setPeerVerified(
        _ verified: Bool, identityKey: Data, for address: PeerAddress
    ) throws -> Bool {
        try setPeerVerified(
            verified, identityKey: identityKey,
            name: address.serviceId.canonicalString, deviceId: address.deviceId)
    }

    // MARK: - Safety numbers (P5.S12, AUDIT 2.5)

    /// The safety number for a conversation, as the sixty digits both sides must read the same.
    ///
    /// # What it is
    ///
    /// libsignal's numeric fingerprint over the two identity keys and the two addresses. It is
    /// the only thing in Cipher that lets two people detect a substituted key, because the
    /// relay chooses what to serve and the app cannot tell a real first contact from a
    /// manufactured one (AUDIT 3.8). Comparing digits is out-of-band by construction: the
    /// channel the number protects cannot be the channel it travels over.
    ///
    /// # Both sides compute the same string
    ///
    /// The generator orders the two halves canonically, so A-about-B and B-about-A produce
    /// identical digits. `testTwoEnginesAgreeOnTheSafetyNumber` pins that, because the entire
    /// ritual is worthless if the two screens can differ for an honest pair — users would learn
    /// that a mismatch means nothing.
    ///
    /// # Parameters chosen, not defaulted
    ///
    /// `iterations` is the work factor libsignal applies while deriving the digits, and
    /// `version` selects the identifier scheme. Both are fixed here rather than passed in: they
    /// are part of the format, and two builds disagreeing on either produce different numbers
    /// for the same pair of keys, which users would read as an attack.
    ///
    /// - Parameters:
    ///   - peerIdentityKey: the peer's serialized public identity key, as shown on screen.
    ///   - localAci: this account's ACI, the local identifier half.
    ///   - peerAci: the peer's ACI.
    /// - Returns: the formatted digits, or throws if either key or identifier is malformed.
    public func safetyNumber(
        peerIdentityKey: Data, localAci: UUID, peerAci: UUID
    ) throws -> String {
        try requireLive()

        let localKey = try store.identityKeyPair(context: NullContext()).identityKey
        let peerKey = try IdentityKey(bytes: peerIdentityKey)

        let fingerprint = try Self.fingerprintGenerator.create(
            version: Self.fingerprintVersion,
            localIdentifier: Self.identifierBytes(localAci),
            localKey: localKey.publicKey,
            remoteIdentifier: Self.identifierBytes(peerAci),
            remoteKey: peerKey.publicKey)

        return fingerprint.displayable.formatted
    }

    /// 5200 iterations and version 2, matching the parameters libsignal's own callers use.
    ///
    /// Not tunable. A safety number is only useful if every build computes it identically, so
    /// these are format constants rather than settings — lowering the work factor would not be
    /// a performance change, it would silently produce a different number for every pair.
    private static let fingerprintGenerator = NumericFingerprintGenerator(iterations: 5200)
    private static let fingerprintVersion = 2

    /// The 16 raw bytes of a UUID, which is what version 2 fingerprints identify parties by.
    ///
    /// Raw bytes rather than the hyphenated string: the string is a rendering, and two
    /// implementations that disagreed about case or hyphens would produce different digits from
    /// the same account.
    private static func identifierBytes(_ id: UUID) -> Data {
        withUnsafeBytes(of: id.uuid) { Data($0) }
    }

    // MARK: - Destruction

    /// Destroys every session, prekey, trust decision, and the identity itself.
    ///
    /// Not reversible and not partial. Because the record store is sealed under a Keychain
    /// key that this also deletes, anything that survives on disk afterwards is ciphertext
    /// no key can open.
    ///
    /// The engine refuses every subsequent operation. Callers must discard it after cleanup;
    /// an interrupted erase is completed by the persisted account-cleanup path below before a
    /// new installation may be opened.
    public func destroyAllState() throws {
        switch lifecycle {
        case .destroyed:
            throw CryptoEngineError.destroyed
        case .live:
            // Refuse every other operation from this point, including if physical cleanup has
            // to be retried. The object still holds in-memory key material until released; it
            // must never use it after destruction begins.
            lifecycle = .erasing
        case .erasing:
            // A previous attempt erased the Keychain but could not finish unlinking files. The
            // same engine can retry its closed/partially removed container idempotently.
            break
        }

        try store.destroyAllState()
        lifecycle = .destroyed
    }

    /// Finishes an interrupted account erase without opening ciphertext or minting replacement
    /// keys. This is only for the persisted `.destroying` account-cleanup gate: normal callers
    /// open an engine and use the instance method so its in-memory handles are invalidated too.
    public static func destroyPersistedState() throws {
        CipherCryptoBootstrap.start()
        let root = try Self.defaultContainer()
        try destroyPersistedState(root: root, secrets: Keychain.shared)
    }

    internal static func destroyPersistedState(root: URL, secrets: SecretStorage) throws {
        CryptoActor.assertIsolated()
        // First irreversible action, and a single Keychain query covering both the identity and
        // record key. Once it returns, any file-removal failure leaves only unrecoverable bytes.
        try secrets.removeAll()
        try SealedRecordDatabase.destroyContainer(root: root)
    }
}

public enum CryptoEngineError: Error, Equatable, Sendable {
    /// The engine's state was destroyed. Discard it and `open` a new one.
    case destroyed
}

/// A peer's trust state, in a form that can safely leave the crypto domain.
///
/// Plain values only: no libsignal handle crosses this boundary, so nothing the UI holds
/// can be handed back into an FFI call from the wrong thread.
public struct PeerIdentityState: Sendable, Equatable {
    /// The peer's serialized **public** identity key.
    public let identityKey: Data
    public let firstSeenMs: UInt64
    public let changedAtMs: UInt64?
    /// True while the key has changed and the user has not accepted the new one. Sending is
    /// refused until they do.
    public let needsAcknowledgement: Bool
    /// True once the user has compared the safety number for **this** key out of band.
    ///
    /// Distinct from `needsAcknowledgement` being false, and the distinction is the point:
    /// accepting a changed key unblocks sending, verifying asserts the key was checked with
    /// the person. A key change clears this, so it can never describe a key the user has not
    /// seen.
    public let isVerified: Bool
}
