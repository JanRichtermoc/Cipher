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
            needsAcknowledgement: record.needsAcknowledgement)
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
}
