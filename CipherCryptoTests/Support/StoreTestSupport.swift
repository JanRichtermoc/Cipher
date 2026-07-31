//
//  StoreTestSupport.swift
//  CipherCryptoTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//
//  Test doubles and fixtures for the persistence layer. These live in the test target on
//  purpose: nothing here may ever be reachable from the shipping framework, which is the
//  same reason Scripts/verify-app-target-manifest.sh exists for the app.
//

import Foundation
import LibSignalClient
import Synchronization
import XCTest

@testable import CipherCrypto

// MARK: - Secret storage double

/// A `SecretStorage` that never touches the real Keychain.
///
/// The Keychain itself is covered by `KeychainTests`; everything else uses this so a test
/// run cannot leave items behind on the simulator or observe items another run left.
///
/// Genuinely `Sendable` via `Mutex` rather than `@unchecked`: the real Keychain is a
/// process-wide store that outlives any one crypto-domain object, and a restart test has to
/// carry the same secrets across two separate hops onto the actor. A double that could not
/// be shared would be modelling something the real thing is not.
internal final class InMemorySecretStorage: SecretStorage, Sendable {

    private struct State: Sendable {
        var items: [String: Data] = [:]
        var lostRaces = 0
    }

    private let state = Mutex(State())

    /// Every `addOrLoad` that found something already present. The identity race is only
    /// safe because that path is taken, so tests can assert on it rather than assume it.
    internal var lostRaces: Int { state.withLock { $0.lostRaces } }

    internal func load(_ key: String) throws -> Data? {
        state.withLock { $0.items[key] }
    }

    internal func addOrLoad(_ value: Data, forKey key: String) throws -> Data {
        state.withLock { state in
            if let existing = state.items[key] {
                state.lostRaces += 1
                return existing
            }
            state.items[key] = value
            return value
        }
    }

    internal func remove(_ key: String) throws {
        state.withLock { _ = $0.items.removeValue(forKey: key) }
    }

    internal func removeAll() throws {
        state.withLock { $0.items.removeAll() }
    }
}

// MARK: - Record store spy

/// Wraps a real `RecordStore` and records, at the deepest point of every libsignal
/// callback, whether the crypto queue was the current queue.
///
/// This is the empirical half of the module's central concurrency claim. `IsolationContract`
/// proves the arrangement type-checks and the `assertIsolated` calls trap if it does not
/// hold; this shows the callbacks are actually taken, and taken on the right queue, during a
/// real decrypt.
internal final class RecordStoreSpy: RecordStore {
    private let wrapped: RecordStore

    internal private(set) var isolationObservations: [Bool] = []
    internal private(set) var loads: [RecordKind: Int] = [:]
    internal private(set) var stores: [RecordKind: Int] = [:]
    internal private(set) var removals: [RecordKind: Int] = [:]

    internal init(_ wrapped: RecordStore) {
        self.wrapped = wrapped
    }

    private func observe() {
        isolationObservations.append(CryptoActor.isCurrent)
    }

    internal func load(_ kind: RecordKind, _ key: String) throws -> Data? {
        observe()
        loads[kind, default: 0] += 1
        return try wrapped.load(kind, key)
    }

    internal func store(_ kind: RecordKind, _ key: String, _ value: Data) throws {
        observe()
        stores[kind, default: 0] += 1
        try wrapped.store(kind, key, value)
    }

    internal func remove(_ kind: RecordKind, _ key: String) throws {
        observe()
        removals[kind, default: 0] += 1
        try wrapped.remove(kind, key)
    }

    internal func count(_ kind: RecordKind) throws -> Int {
        observe()
        return try wrapped.count(kind)
    }

    internal func removeAll() throws {
        observe()
        try wrapped.removeAll()
    }
}

// MARK: - Temporary containers

internal enum TestContainer {
    /// A fresh directory under the system temporary directory. Never the real Application
    /// Support container: a test must not be able to destroy a developer's simulator state.
    internal static func make() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("CipherCryptoTests-\(UUID().uuidString)", isDirectory: true)
    }

    internal static func remove(_ url: URL) {
        try? FileManager.default.removeItem(at: url)
    }
}

// MARK: - Fixtures

/// One local installation: its Keychain double, its record store, and the protocol store
/// built on both.
///
/// Everything is constructed inside the crypto domain because the store's initialisers
/// assert it — which is itself part of the contract being tested.
@CryptoActor
internal struct LocalFixture {
    internal let secrets: InMemorySecretStorage
    internal let spy: RecordStoreSpy
    internal let store: CipherProtocolStore
    internal let address: ProtocolAddress

    internal init(root: URL, secrets: InMemorySecretStorage = InMemorySecretStorage()) throws {
        let files = try EncryptedFileRecordStore(root: root, secrets: secrets)
        let identity = try DeviceIdentity.loadOrCreate(secrets: secrets)
        // Keyed from `files`, not from `spy`: the spy counts record-store traffic, and the
        // database derives its subkeys from the real store's Keychain-backed master key. Same
        // wiring as `CryptoEngine.init`, which is the point of a fixture.
        let database = try SealedRecordDatabase(root: root, keys: files)
        let spy = RecordStoreSpy(DatabaseRecordStore(database: database, legacy: files))

        self.secrets = secrets
        self.spy = spy
        self.store = CipherProtocolStore(
            deviceIdentity: identity, records: spy, database: database, secrets: secrets)
        self.address = try ProtocolAddress(name: UUID().uuidString.lowercased(), deviceId: 1)
    }
}

/// A peer with a published PQXDH bundle, backed by libsignal's own in-memory store.
///
/// The peer deliberately does **not** use `CipherProtocolStore`: a round trip is only
/// meaningful if at least one side is the reference implementation.
@CryptoActor
internal struct PeerFixture {
    internal let store: InMemorySignalProtocolStore
    internal let address: ProtocolAddress
    internal let identity: IdentityKeyPair

    internal static let preKeyId: UInt32 = 7001
    internal static let signedPreKeyId: UInt32 = 7002
    internal static let kyberPreKeyId: UInt32 = 7003

    internal init(address: ProtocolAddress) throws {
        let store = InMemorySignalProtocolStore()
        self.store = store
        self.address = address
        self.identity = try store.identityKeyPair(context: NullContext())
    }

    /// Publishes a fresh bundle and persists the private halves, exactly as a real client
    /// would after uploading keys to a server.
    internal func makeBundle() throws -> PreKeyBundle {
        try publish().libsignal
    }

    /// The same published bundle in the boundary form the engine's API takes.
    ///
    /// Separate from `makeBundle` rather than converted from it: `PreKeyBundle` exposes no
    /// accessors for the values it was built from, and reaching back through the FFI to
    /// recover them would test the recovery rather than the bundle.
    internal func makeCipherBundle() throws -> PeerKeyBundle {
        try publish().cipher
    }

    private func publish() throws -> (libsignal: PreKeyBundle, cipher: PeerKeyBundle) {
        let context = NullContext()

        let preKey = PrivateKey.generate()
        let signedPreKey = PrivateKey.generate()
        let kyber = KEMKeyPair.generate()

        let signedPreKeySignature = identity.privateKey.generateSignature(
            message: signedPreKey.publicKey.serialize())
        let kyberSignature = identity.privateKey.generateSignature(
            message: kyber.publicKey.serialize())

        let bundle = try PreKeyBundle(
            registrationId: try store.localRegistrationId(context: context),
            deviceId: address.deviceId,
            prekeyId: Self.preKeyId,
            prekey: preKey.publicKey,
            signedPrekeyId: Self.signedPreKeyId,
            signedPrekey: signedPreKey.publicKey,
            signedPrekeySignature: signedPreKeySignature,
            identity: identity.identityKey,
            kyberPrekeyId: Self.kyberPreKeyId,
            kyberPrekey: kyber.publicKey,
            kyberPrekeySignature: kyberSignature)

        try store.storePreKey(
            PreKeyRecord(id: Self.preKeyId, privateKey: preKey),
            id: Self.preKeyId, context: context)
        try store.storeSignedPreKey(
            SignedPreKeyRecord(
                id: Self.signedPreKeyId, timestamp: 1000,
                privateKey: signedPreKey, signature: signedPreKeySignature),
            id: Self.signedPreKeyId, context: context)
        try store.storeKyberPreKey(
            KyberPreKeyRecord(
                id: Self.kyberPreKeyId, timestamp: 1000,
                keyPair: kyber, signature: kyberSignature),
            id: Self.kyberPreKeyId, context: context)

        let cipher = PeerKeyBundle(
            registrationId: try store.localRegistrationId(context: context),
            deviceId: address.deviceId,
            identityKey: identity.identityKey.serialize(),
            preKeyId: Self.preKeyId,
            preKey: preKey.publicKey.serialize(),
            signedPreKeyId: Self.signedPreKeyId,
            signedPreKey: signedPreKey.publicKey.serialize(),
            signedPreKeySignature: Data(signedPreKeySignature),
            kyberPreKeyId: Self.kyberPreKeyId,
            kyberPreKey: kyber.publicKey.serialize(),
            kyberPreKeySignature: Data(kyberSignature))

        return (bundle, cipher)
    }

    /// Encrypts to `recipient` from this peer, returning wire bytes and the message type.
    internal func encrypt(_ text: String, to recipient: ProtocolAddress) throws
        -> (bytes: Data, type: CiphertextMessage.MessageType) {
        let message = try signalEncrypt(
            message: Array(text.utf8),
            for: recipient, localAddress: address,
            sessionStore: store, identityStore: store, context: NullContext())
        return (message.serialize(), message.messageType)
    }

    /// Decrypts a message that arrived from `sender`.
    internal func decrypt(
        _ bytes: Data, type: CiphertextMessage.MessageType, from sender: ProtocolAddress
    ) throws -> String {
        let context = NullContext()
        let plaintext: Data
        switch type {
        case .preKey:
            plaintext = try signalDecryptPreKey(
                message: try PreKeySignalMessage(bytes: bytes),
                from: sender, localAddress: address,
                sessionStore: store, identityStore: store,
                preKeyStore: store, signedPreKeyStore: store,
                kyberPreKeyStore: store, context: context)
        default:
            plaintext = try signalDecrypt(
                message: try SignalMessage(bytes: bytes),
                from: sender, to: address,
                sessionStore: store, identityStore: store, context: context)
        }
        return String(decoding: plaintext, as: UTF8.self)
    }
}

// MARK: - Local side helpers

@CryptoActor
internal enum Local {

    /// Establishes a session from the local store to `peer` using a freshly published bundle.
    internal static func establishSession(
        _ fixture: LocalFixture, with peerAddress: ProtocolAddress, bundle: PreKeyBundle
    ) throws {
        try processPreKeyBundle(
            bundle, for: peerAddress, ourAddress: fixture.address,
            sessionStore: fixture.store, identityStore: fixture.store, context: NullContext())
    }

    internal static func encrypt(
        _ fixture: LocalFixture, _ text: String, to peerAddress: ProtocolAddress
    ) throws -> (bytes: Data, type: CiphertextMessage.MessageType) {
        let message = try signalEncrypt(
            message: Array(text.utf8),
            for: peerAddress, localAddress: fixture.address,
            sessionStore: fixture.store, identityStore: fixture.store, context: NullContext())
        return (message.serialize(), message.messageType)
    }

    internal static func decrypt(
        _ fixture: LocalFixture, _ bytes: Data,
        type: CiphertextMessage.MessageType, from peerAddress: ProtocolAddress
    ) throws -> String {
        let context = NullContext()
        let plaintext: Data
        switch type {
        case .preKey:
            plaintext = try signalDecryptPreKey(
                message: try PreKeySignalMessage(bytes: bytes),
                from: peerAddress, localAddress: fixture.address,
                sessionStore: fixture.store, identityStore: fixture.store,
                preKeyStore: fixture.store, signedPreKeyStore: fixture.store,
                kyberPreKeyStore: fixture.store, context: context)
        default:
            plaintext = try signalDecrypt(
                message: try SignalMessage(bytes: bytes),
                from: peerAddress, to: fixture.address,
                sessionStore: fixture.store, identityStore: fixture.store, context: context)
        }
        return String(decoding: plaintext, as: UTF8.self)
    }
}
