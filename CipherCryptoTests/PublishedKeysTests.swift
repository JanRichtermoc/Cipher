//
//  PublishedKeysTests.swift
//  CipherCryptoTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//
//  What `generatePublishedKeys` has to get right is not that it returns keys — it is that the
//  private halves are *on disk* before the public ones are handed out, because a bundle whose
//  private half was never stored produces a first message that can never be decrypted, for good.
//

import Foundation
import LibSignalClient
import XCTest

@testable import CipherCrypto

final class PublishedKeysTests: XCTestCase {

    /// Static, and every test owns its own container: an instance method captured inside a
    /// `@CryptoActor` closure is `self` crossing an isolation boundary, which strict concurrency
    /// refuses — see `StoreEdgeTests` for the same shape.
    @CryptoActor
    private static func makeEngine(_ root: URL) throws -> CryptoEngine {
        try CryptoEngine(root: root, secrets: InMemorySecretStorage())
    }

    /// Exactly what the relay would dispense from a publication: the account's identity key and
    /// registration id, one one-time prekey, the signed prekey, and one Kyber prekey.
    ///
    /// Assembled here rather than fetched, so these tests exercise the *client's* published
    /// material end to end without a server in the loop.
    @CryptoActor
    private static func dispensed(
        _ published: PublishedKeys, from engine: CryptoEngine, oneTimeIndex: Int = 0
    ) throws -> PeerKeyBundle {
        PeerKeyBundle(
            registrationId: try engine.localRegistrationId,
            identityKey: try engine.localIdentityKey,
            preKeyId: published.oneTimePreKeys[oneTimeIndex].keyId,
            preKey: published.oneTimePreKeys[oneTimeIndex].publicKey,
            signedPreKeyId: published.signedPreKey.keyId,
            signedPreKey: published.signedPreKey.publicKey,
            signedPreKeySignature: published.signedPreKey.signature,
            kyberPreKeyId: published.kyberPreKeys[oneTimeIndex].keyId,
            kyberPreKey: published.kyberPreKeys[oneTimeIndex].publicKey,
            kyberPreKeySignature: published.kyberPreKeys[oneTimeIndex].signature)
    }

    // MARK: The property the whole step depends on

    func testAPeerCanStartASessionFromThePublishedBundleAndBeDecrypted() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root)
            let localAci = UUID()
            try engine.adoptLocalAddress(PeerAddress(aci: localAci))

            // A modest pool: the point is the wiring, and 100 ML-KEM keypairs per test run is
            // time spent proving the same thing three digits of times.
            let published = try engine.generatePublishedKeys(oneTimeCount: 2)

            // Assemble exactly what the relay would dispense from that publication, and drive a
            // real peer through it. If any private half were missing locally, this fails at
            // decrypt with `invalidKeyIdentifier` — which is the whole failure being guarded.
            let bundle = try Self.dispensed(published, from: engine)

            let peerAci = UUID()
            let peer = try PeerFixture(
                address: try PeerAddress(aci: peerAci).makeProtocolAddress())
            try processPreKeyBundle(
                try bundle.makePreKeyBundle(),
                for: try PeerAddress(aci: localAci).makeProtocolAddress(),
                ourAddress: peer.address,
                sessionStore: peer.store, identityStore: peer.store, context: NullContext())

            let sent = try peer.encrypt(
                "first contact", to: try PeerAddress(aci: localAci).makeProtocolAddress())
            let envelope = try Envelope(
                type: try Envelope.payloadType(for: sent.type),
                sender: ServiceIdentifier(kind: .aci, uuid: peerAci),
                timestamp: 1,
                ciphertext: sent.bytes).encode()

            let decrypted = try engine.decrypt(envelope)
            XCTAssertEqual(decrypted.plaintext, Data("first contact".utf8))
            XCTAssertTrue(decrypted.establishedSession)
        }.value
    }

    func testTheLastResortKyberKeyIsSignedAndUsableOnItsOwn() async throws {
        // The relay refuses an upload with no last-resort key (`BACKEND.md` §2.6), and it is the
        // key every session falls back to once the one-time pool empties — so it has to be a
        // fully usable bundle member, not a placeholder.
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root)
            let localAci = UUID()
            try engine.adoptLocalAddress(PeerAddress(aci: localAci))
            let published = try engine.generatePublishedKeys(oneTimeCount: 1)

            let bundle = PeerKeyBundle(
                registrationId: try engine.localRegistrationId,
                identityKey: try engine.localIdentityKey,
                preKeyId: published.oneTimePreKeys[0].keyId,
                preKey: published.oneTimePreKeys[0].publicKey,
                signedPreKeyId: published.signedPreKey.keyId,
                signedPreKey: published.signedPreKey.publicKey,
                signedPreKeySignature: published.signedPreKey.signature,
                // The last-resort key, not a one-time one.
                kyberPreKeyId: published.kyberLastResort.keyId,
                kyberPreKey: published.kyberLastResort.publicKey,
                kyberPreKeySignature: published.kyberLastResort.signature)

            let peer = try PeerFixture(address: try PeerAddress(aci: UUID()).makeProtocolAddress())
            XCTAssertNoThrow(
                try processPreKeyBundle(
                    try bundle.makePreKeyBundle(),
                    for: try PeerAddress(aci: localAci).makeProtocolAddress(),
                    ourAddress: peer.address,
                    sessionStore: peer.store, identityStore: peer.store, context: NullContext()))
        }.value
    }

    // MARK: Shape and ids

    func testEveryKeyIdIsDistinctAndTheCounterAdvances() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root)
            try engine.adoptLocalAddress(PeerAddress(aci: UUID()))

            let first = try engine.generatePublishedKeys(oneTimeCount: 3)
            let second = try engine.generatePublishedKeys(oneTimeCount: 3)

            let ids = [first, second].flatMap { published in
                [published.signedPreKey.keyId, published.kyberLastResort.keyId]
                    + published.kyberPreKeys.map(\.keyId)
                    + published.oneTimePreKeys.map(\.keyId)
            }
            // Reissuing an id would let a replayed prekey message be matched against a
            // brand-new private key, which is why ids come from a monotonic counter and never
            // from what happens to be on disk.
            XCTAssertEqual(Set(ids).count, ids.count)
            XCTAssertGreaterThan(second.signedPreKey.keyId, first.oneTimePreKeys.last!.keyId)
        }.value
    }

    func testPoolSizeIsHonouredAndCountedLocally() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root)
            try engine.adoptLocalAddress(PeerAddress(aci: UUID()))

            let published = try engine.generatePublishedKeys(oneTimeCount: 4)
            XCTAssertEqual(published.oneTimePreKeys.count, 4)
            XCTAssertEqual(published.kyberPreKeys.count, 4)
            // The local count, which a hostile relay cannot lie about.
            XCTAssertEqual(try engine.remainingOneTimePreKeys, 4)
        }.value
    }

    func testSignaturesVerifyUnderThisInstallationsIdentityKey() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root)
            try engine.adoptLocalAddress(PeerAddress(aci: UUID()))
            let published = try engine.generatePublishedKeys(oneTimeCount: 1)

            let identity = try IdentityKey(bytes: try engine.localIdentityKey)
            XCTAssertTrue(
                try identity.publicKey.verifySignature(
                    message: published.signedPreKey.publicKey,
                    signature: published.signedPreKey.signature))
            XCTAssertTrue(
                try identity.publicKey.verifySignature(
                    message: published.kyberLastResort.publicKey,
                    signature: published.kyberLastResort.signature))
            for kyber in published.kyberPreKeys {
                XCTAssertTrue(
                    try identity.publicKey.verifySignature(
                        message: kyber.publicKey, signature: kyber.signature))
            }
        }.value
    }

    // MARK: Refusals

    func testGenerationRefusesAfterStateIsDestroyed() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root)
            try engine.adoptLocalAddress(PeerAddress(aci: UUID()))
            try engine.destroyAllState()

            XCTAssertThrowsError(try engine.generatePublishedKeys(oneTimeCount: 1)) { error in
                XCTAssertEqual(error as? CryptoEngineError, .destroyed)
            }
        }.value
    }

    // MARK: The boundary error mapping (AUDIT 5.19)

    func testAnIdentityChangeSurfacesAsMessagingErrorNotAsALibsignalError() async throws {
        // Before P5.S10 this threw `SignalError.untrustedIdentity`, so the only way for the app
        // to tell "compare a safety number" from "the network is down" was to import
        // LibSignalClient — the boundary AUDIT 5.12 closed, reopened through `throws`, where
        // `verify-api-boundary.sh` cannot see it.
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root)
            let localAci = UUID()
            let peerAci = UUID()
            try engine.adoptLocalAddress(PeerAddress(aci: localAci))

            let published = try engine.generatePublishedKeys(oneTimeCount: 2)

            let peerAddress = PeerAddress(aci: peerAci)
            let first = try PeerFixture(address: try peerAddress.makeProtocolAddress())
            try engine.startSession(with: peerAddress, bundle: try first.makeCipherBundle())
            XCTAssertNoThrow(try engine.encrypt(Data("hello".utf8), to: peerAddress))

            // A second peer at the same address with a different identity key. It starts a
            // session *towards* the engine from the engine's own published bundle, which is what
            // a hostile relay handing out a substituted identity would look like from here.
            let impostor = try PeerFixture(address: try peerAddress.makeProtocolAddress())
            try processPreKeyBundle(
                try Self.dispensed(published, from: engine, oneTimeIndex: 1).makePreKeyBundle(),
                for: try PeerAddress(aci: localAci).makeProtocolAddress(),
                ourAddress: impostor.address,
                sessionStore: impostor.store, identityStore: impostor.store,
                context: NullContext())

            let intrusion = try impostor.encrypt(
                "new key", to: try PeerAddress(aci: localAci).makeProtocolAddress())
            let envelope = try Envelope(
                type: try Envelope.payloadType(for: intrusion.type),
                sender: ServiceIdentifier(kind: .aci, uuid: peerAci),
                timestamp: 1, ciphertext: intrusion.bytes).encode()
            _ = try engine.decrypt(envelope)

            XCTAssertThrowsError(try engine.encrypt(Data("reply".utf8), to: peerAddress)) { error in
                XCTAssertEqual(error as? MessagingError, .identityNotAccepted)
                XCTAssertFalse(
                    error is SignalError,
                    "a LibSignalClient error escaping through `throws` is the boundary hole")
            }

            // And accepting the exact key unblocks it, so the mapping did not turn a recoverable
            // refusal into a permanent one.
            XCTAssertTrue(
                try engine.acceptPeerIdentity(
                    impostor.identity.identityKey.serialize(),
                    name: ServiceIdentifier(kind: .aci, uuid: peerAci).canonicalString,
                    deviceId: PeerAddress.primaryDevice))
            XCTAssertNoThrow(try engine.encrypt(Data("reply".utf8), to: peerAddress))
        }.value
    }
}
