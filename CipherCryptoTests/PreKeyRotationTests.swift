//
//  PreKeyRotationTests.swift
//  CipherCryptoTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//
//  P6.S01, AUDIT 2.4. Rotation is only an improvement if both halves hold: the key it replaces
//  must stay usable long enough for a bundle already in a peer's hands, and it must eventually
//  go. Keep it forever and "rotation" is a growing pile of live private keys; delete it on the
//  spot and a peer who fetched a bundle a second earlier loses their first message permanently.
//

import Foundation
import LibSignalClient
import Synchronization
import XCTest

@testable import CipherCrypto

final class PreKeyRotationTests: XCTestCase {

    /// A clock the test moves. `Sendable` through `Mutex` for the reason
    /// `InMemorySecretStorage` is: the engine's `now` closure is called from inside the crypto
    /// domain, and the test that sets it is not.
    private final class TestClock: Sendable {
        private let millis: Mutex<UInt64>

        init(_ start: UInt64) { millis = Mutex(start) }

        var now: UInt64 { millis.withLock { $0 } }

        func advance(by interval: UInt64) { millis.withLock { $0 += interval } }

        /// A device whose clock moved backwards. Separate from a negative `advance`, which is
        /// not expressible: `UInt64` addition of a wrapped negative traps, and the first version
        /// of this type made that mistake — the test that used it started, died on the trap, and
        /// the suite still reported every *other* test passing.
        func rewind(by interval: UInt64) { millis.withLock { $0 -= interval } }
    }

    @CryptoActor
    private static func makeEngine(
        _ root: URL, secrets: InMemorySecretStorage, clock: TestClock
    ) throws -> CryptoEngine {
        try CryptoEngine(root: root, secrets: secrets, now: { clock.now })
    }

    /// Exactly what the relay would dispense from `published`: this account's identity and
    /// registration id, one of its one-time prekeys, its signed prekey, and one Kyber prekey.
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

    /// Drives a real peer through `bundle` and returns whether the engine could read what it
    /// sent. A fresh peer identity each time, so two calls never collide on trust state.
    @CryptoActor
    private static func peerCanReach(
        _ engine: CryptoEngine, localAci: UUID, bundle: PeerKeyBundle, text: String
    ) throws -> Bool {
        let peerAci = UUID()
        let peer = try PeerFixture(address: try PeerAddress(aci: peerAci).makeProtocolAddress())
        try processPreKeyBundle(
            try bundle.makePreKeyBundle(),
            for: try PeerAddress(aci: localAci).makeProtocolAddress(),
            ourAddress: peer.address,
            sessionStore: peer.store, identityStore: peer.store, context: NullContext())

        let sent = try peer.encrypt(text, to: try PeerAddress(aci: localAci).makeProtocolAddress())
        let envelope = try Envelope(
            type: try Envelope.payloadType(for: sent.type),
            sender: ServiceIdentifier(kind: .aci, uuid: peerAci),
            timestamp: 1,
            ciphertext: sent.bytes).encode()

        guard let decrypted = try? engine.decrypt(envelope) else { return false }
        return decrypted.plaintext == Data(text.utf8)
    }

    // MARK: - The pair a rotation replaces

    func testARotationMintsANewSignedPreKeyAndLastResortKey() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }
        let clock = TestClock(1_000_000)

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root, secrets: InMemorySecretStorage(), clock: clock)
            try engine.adoptLocalAddress(PeerAddress(aci: UUID()))

            let first = try engine.generatePublishedKeys(oneTimeCount: 1)
            clock.advance(by: 48 * 60 * 60 * 1000)
            let second = try engine.generatePublishedKeys(oneTimeCount: 1)

            XCTAssertNotEqual(second.signedPreKey.keyId, first.signedPreKey.keyId)
            XCTAssertNotEqual(second.kyberLastResort.keyId, first.kyberLastResort.keyId)
            // Ids come from the monotonic counter, never from what is on disk. Rotation makes
            // that load-bearing: this device now holds several signed prekeys at once, and two
            // sharing an id would resolve to whichever record was written last.
            XCTAssertGreaterThan(second.signedPreKey.keyId, first.kyberLastResort.keyId)

            let state = try engine.preKeyState
            XCTAssertEqual(state.signedPreKeyId, second.signedPreKey.keyId)
            XCTAssertEqual(state.lastRotationMs, clock.now)
            // The pair that was replaced, still held.
            XCTAssertEqual(state.retiredPreKeyCount, 2)
        }.value
    }

    func testABundleFetchedBeforeTheRotationStillDecrypts() async throws {
        // The window this exists to protect: a peer fetched the bundle, the device rotated
        // before they sent, and their first message names the *old* signed prekey. Deleting it
        // on rotation turns that into a permanent `invalidKeyIdentifier` for a peer who did
        // nothing wrong — and they cannot retry into success, because the key is gone.
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }
        let clock = TestClock(1_000_000)

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root, secrets: InMemorySecretStorage(), clock: clock)
            let localAci = UUID()
            try engine.adoptLocalAddress(PeerAddress(aci: localAci))

            let first = try engine.generatePublishedKeys(oneTimeCount: 1)
            let stale = try Self.dispensed(first, from: engine)

            clock.advance(by: 48 * 60 * 60 * 1000)
            _ = try engine.generatePublishedKeys(oneTimeCount: 1)

            XCTAssertTrue(
                try Self.peerCanReach(
                    engine, localAci: localAci, bundle: stale, text: "sent before the rotation"))
        }.value
    }

    func testARetiredPairIsPrunedOnceItsRetentionHasElapsed() async throws {
        // The other half. Retention that never ends is not retention: every rotation would add
        // a signed prekey and an ML-KEM keypair the device keeps for good, which is the leak
        // that would make rotating often worse than not rotating at all.
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }
        let clock = TestClock(1_000_000)

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root, secrets: InMemorySecretStorage(), clock: clock)
            let localAci = UUID()
            try engine.adoptLocalAddress(PeerAddress(aci: localAci))

            let first = try engine.generatePublishedKeys(oneTimeCount: 2)
            let firstBundle = try Self.dispensed(first, from: engine)

            // The rotation that retires the first pair.
            clock.advance(by: 48 * 60 * 60 * 1000)
            let second = try engine.generatePublishedKeys(oneTimeCount: 2)
            let secondBundle = try Self.dispensed(second, from: engine)

            // The rotation that finds the first pair past its retention.
            clock.advance(by: CryptoEngine.retiredPreKeyRetentionMs + 1)
            _ = try engine.generatePublishedKeys(oneTimeCount: 2)

            // Only the second pair is still retired; the first was pruned, not accumulated.
            XCTAssertEqual(try engine.preKeyState.retiredPreKeyCount, 2)

            // And the prune is real, not bookkeeping: the pruned signed prekey can no longer
            // open a message addressed to it, while the pair still inside its window can.
            XCTAssertFalse(
                try Self.peerCanReach(
                    engine, localAci: localAci, bundle: firstBundle, text: "far too late"))
            XCTAssertTrue(
                try Self.peerCanReach(
                    engine, localAci: localAci, bundle: secondBundle, text: "still in window"))
        }.value
    }

    func testAClockThatMovedBackwardsKeepsARetiredPairRatherThanDroppingIt() async throws {
        // Erring toward keeping costs one stored keypair. Erring the other way costs a peer
        // their first message, permanently — so "not demonstrably older than the window" must
        // resolve to keep.
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }
        // Far enough from the epoch that subtracting several retention windows stays positive.
        let clock = TestClock(1_700_000_000_000)

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root, secrets: InMemorySecretStorage(), clock: clock)
            let localAci = UUID()
            try engine.adoptLocalAddress(PeerAddress(aci: localAci))

            let first = try engine.generatePublishedKeys(oneTimeCount: 1)
            let firstBundle = try Self.dispensed(first, from: engine)
            _ = try engine.generatePublishedKeys(oneTimeCount: 1)

            // The device's clock jumps back further than the whole retention window.
            clock.rewind(by: CryptoEngine.retiredPreKeyRetentionMs * 2)
            _ = try engine.generatePublishedKeys(oneTimeCount: 1)

            XCTAssertTrue(
                try Self.peerCanReach(
                    engine, localAci: localAci, bundle: firstBundle, text: "clock went backwards"))
        }.value
    }

    // MARK: - Across a restart

    func testTheRotationStateSurvivesAReopen() async throws {
        // "Rotation observed across a restart" is the step's own `Done when`. The scheduler
        // decides from this record and nothing else — an installation that lost it on relaunch
        // would either rotate on every launch, spending the relay's six-a-day budget, or never
        // rotate at all.
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }
        let secrets = InMemorySecretStorage()
        let clock = TestClock(1_000_000)

        let rotated: (signedPreKeyId: UInt32, at: UInt64) = try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root, secrets: secrets, clock: clock)
            try engine.adoptLocalAddress(PeerAddress(aci: UUID()))
            _ = try engine.generatePublishedKeys(oneTimeCount: 1)
            clock.advance(by: 48 * 60 * 60 * 1000)
            let second = try engine.generatePublishedKeys(oneTimeCount: 1)
            return (second.signedPreKey.keyId, clock.now)
        }.value

        // A second engine over the same container and the same secrets: the relaunch.
        try await Task { @CryptoActor in
            let reopened = try Self.makeEngine(root, secrets: secrets, clock: clock)
            let state = try reopened.preKeyState
            XCTAssertEqual(state.lastRotationMs, rotated.at)
            XCTAssertEqual(state.signedPreKeyId, rotated.signedPreKeyId)
            XCTAssertEqual(state.retiredPreKeyCount, 2)
        }.value
    }

    // MARK: - Rotating without topping up

    func testARotationOnlyPublicationMintsNoPoolKeys() async throws {
        // A rotation that falls due while the relay-side pool is still full has nothing to top
        // up. Minting a hundred keypairs to satisfy a signature would be the tail wagging the
        // dog, and the relay accepts a publication with empty pools — it requires only the
        // signed prekey and the last-resort Kyber key.
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }
        let clock = TestClock(1_000_000)

        try await Task { @CryptoActor in
            let engine = try Self.makeEngine(root, secrets: InMemorySecretStorage(), clock: clock)
            try engine.adoptLocalAddress(PeerAddress(aci: UUID()))

            let first = try engine.generatePublishedKeys(oneTimeCount: 3)
            clock.advance(by: 48 * 60 * 60 * 1000)
            let rotation = try engine.generatePublishedKeys(oneTimeCount: 0)

            XCTAssertTrue(rotation.oneTimePreKeys.isEmpty)
            XCTAssertTrue(rotation.kyberPreKeys.isEmpty)
            XCTAssertNotEqual(rotation.signedPreKey.keyId, first.signedPreKey.keyId)
            XCTAssertNotEqual(rotation.kyberLastResort.keyId, first.kyberLastResort.keyId)
            // The pool it did not touch is still the pool it had.
            XCTAssertEqual(try engine.preKeyState.remainingOneTimePreKeys, 3)
        }.value
    }

    // MARK: - The record itself

    func testAnUnreadableRotationRecordIsRefusedRatherThanReadAsNeverRotated() async throws {
        // A record this build cannot parse must fail loudly. Read as "never rotated" it would
        // silently republish over live keys; read as a *different* record it could name the
        // wrong ids and prune a key still in use.
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let fixture = try LocalFixture(root: root)
            try fixture.store.recordPreKeyRotation(
                signedPreKeyId: 11, kyberLastResortId: 12, at: 1_000, retention: 5_000)
            XCTAssertEqual(try fixture.store.preKeyRotation()?.signedPreKeyId, 11)

            // A version byte from a build that does not exist yet. The record key is written
            // out rather than shared: a rename that lost this test's target would leave it
            // unwrapping nil here, which fails, instead of quietly testing nothing.
            var corrupted = try XCTUnwrap(try fixture.spy.load(.metadata, "prekey-rotation"))
            corrupted[corrupted.startIndex] = 99
            try fixture.spy.store(.metadata, "prekey-rotation", corrupted)

            XCTAssertThrowsError(try fixture.store.preKeyRotation()) { error in
                XCTAssertEqual(error as? ProtocolStoreError, .malformedMetadata)
            }
        }.value
    }
}
