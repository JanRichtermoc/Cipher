//
//  SafetyNumberTests.swift
//  CipherCryptoTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//
//  P5.S12 / AUDIT 2.5. The safety number is the only thing in Cipher that lets two
//  people detect a substituted key: the relay chooses what to serve, and the app
//  cannot tell a genuine first contact from a manufactured one (AUDIT 3.8). The
//  block on sending was already real; this is the half that explains it.
//
//  Two properties carry the whole feature, and they fail in opposite directions:
//  an honest pair must see identical digits, or users learn that a mismatch means
//  nothing; and a substituted key must change them, or the comparison is theatre.
//  Both are tested against two real engines rather than one engine and a fixture,
//  because "two devices show the same number" is a claim about two devices.
//

import Foundation
import LibSignalClient
import XCTest

@testable import CipherCrypto

final class SafetyNumberTests: XCTestCase {

    // MARK: - Fixture

    /// One installation: a real engine with an adopted address.
    @CryptoActor
    private struct Party {
        let engine: CryptoEngine
        let aci: UUID

        init(root: URL) throws {
            engine = try CryptoEngine(root: root, secrets: InMemorySecretStorage())
            aci = UUID()
            try engine.adoptLocalAddress(PeerAddress(aci: aci))
        }

        /// What this party's screen would show about `other`.
        func safetyNumber(about other: Party) throws -> String {
            try engine.safetyNumber(
                peerIdentityKey: try other.engine.localIdentityKey,
                localAci: aci,
                peerAci: other.aci)
        }
    }

    // MARK: - The two properties the ritual depends on

    /// The plan's "Done when", first half: two devices show matching numbers.
    func testTwoEnginesAgreeOnTheSafetyNumber() async throws {
        let rootA = TestContainer.make()
        let rootB = TestContainer.make()
        defer { TestContainer.remove(rootA); TestContainer.remove(rootB) }

        try await Task { @CryptoActor in
            let alice = try Party(root: rootA)
            let bob = try Party(root: rootB)

            let asAliceSeesIt = try alice.safetyNumber(about: bob)
            let asBobSeesIt = try bob.safetyNumber(about: alice)

            // The generator orders the two halves canonically, so the roles cancel. If this
            // ever fails, the feature is worse than absent: two honest users comparing
            // digits would be told they are under attack, and the correct lesson for them
            // to draw would be to ignore the screen.
            XCTAssertEqual(
                asAliceSeesIt, asBobSeesIt,
                "an honest pair sees different safety numbers, which trains users to ignore a mismatch")
        }.value
    }

    /// The plan's "Done when", second half: a substituted identity visibly changes them.
    func testASubstitutedIdentityChangesTheSafetyNumber() async throws {
        let rootA = TestContainer.make()
        let rootB = TestContainer.make()
        let rootImpostor = TestContainer.make()
        defer {
            TestContainer.remove(rootA)
            TestContainer.remove(rootB)
            TestContainer.remove(rootImpostor)
        }

        try await Task { @CryptoActor in
            let alice = try Party(root: rootA)
            let bob = try Party(root: rootB)
            let impostor = try Party(root: rootImpostor)

            let genuine = try alice.safetyNumber(about: bob)

            // The attack this exists to catch: a hostile relay serves the impostor's identity
            // key under Bob's address, so everything Alice can see about the conversation is
            // unchanged except the key. The ACI is Bob's; only the key differs.
            let substituted = try alice.engine.safetyNumber(
                peerIdentityKey: try impostor.engine.localIdentityKey,
                localAci: alice.aci,
                peerAci: bob.aci)

            XCTAssertNotEqual(
                genuine, substituted,
                "a substituted identity key produces the same digits, so the comparison proves nothing")
        }.value
    }

    /// The digits must be stable across calls, or a user comparing over a phone call is
    /// reading something that changes while they read it.
    func testTheSafetyNumberIsStableAndAllDigits() async throws {
        let rootA = TestContainer.make()
        let rootB = TestContainer.make()
        defer { TestContainer.remove(rootA); TestContainer.remove(rootB) }

        try await Task { @CryptoActor in
            let alice = try Party(root: rootA)
            let bob = try Party(root: rootB)

            let first = try alice.safetyNumber(about: bob)
            let second = try alice.safetyNumber(about: bob)
            XCTAssertEqual(first, second, "the safety number is not deterministic")

            // Sixty decimal digits: the format the user is asked to read aloud. Asserted
            // because the UI groups them for legibility, and a renderer that grouped a
            // different length would silently show a truncated number.
            XCTAssertEqual(first.count, 60, "unexpected safety-number length: \(first.count)")
            XCTAssertTrue(
                first.allSatisfy(\.isNumber),
                "the safety number contains something other than digits")
        }.value
    }

    /// A malformed peer key is refused rather than producing digits from nothing.
    func testAMalformedPeerKeyIsRefused() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let alice = try Party(root: root)
            XCTAssertThrowsError(
                try alice.engine.safetyNumber(
                    peerIdentityKey: Data([0x00, 0x01, 0x02]),
                    localAci: alice.aci,
                    peerAci: UUID()),
                "a malformed identity key produced a safety number")
        }.value
    }

    // MARK: - Verification state

    /// Verification is a claim about one exact key, so a key change must retract it.
    ///
    /// This is the assertion that matters most in the file. A verified badge surviving a
    /// key change would be the most dangerous lie the app could tell: it would state that
    /// the substitution had been checked.
    func testVerificationIsClearedWhenTheIdentityChanges() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let engine = try CryptoEngine(root: root, secrets: InMemorySecretStorage())
            let local = PeerAddress(aci: UUID())
            let remote = PeerAddress(aci: UUID())
            try engine.adoptLocalAddress(local)

            let original = IdentityKeyPair.generate()
            let replacement = IdentityKeyPair.generate()
            let address = try remote.makeProtocolAddress()

            // First sight, then the user compares digits and says they matched.
            _ = try engine.store.saveIdentity(
                original.identityKey, for: address, context: NullContext())
            XCTAssertTrue(
                try engine.setPeerVerified(
                    true,
                    identityKey: original.identityKey.serialize(),
                    name: remote.serviceId.canonicalString,
                    deviceId: remote.deviceId))

            let verified = try XCTUnwrap(
                try engine.peerIdentityState(
                    name: remote.serviceId.canonicalString, deviceId: remote.deviceId))
            XCTAssertTrue(verified.isVerified, "the verification was not recorded")

            // The key changes underneath them.
            _ = try engine.store.saveIdentity(
                replacement.identityKey, for: address, context: NullContext())

            let afterChange = try XCTUnwrap(
                try engine.peerIdentityState(
                    name: remote.serviceId.canonicalString, deviceId: remote.deviceId))
            XCTAssertFalse(
                afterChange.isVerified,
                "a verified badge survived an identity change, asserting that a substitution was checked")
            XCTAssertTrue(
                afterChange.needsAcknowledgement,
                "the change did not block sending")
        }.value
    }

    /// Accepting a changed key unblocks sending. It must not also mark the peer verified.
    ///
    /// The two are different claims — "I want to keep talking" and "I compared the digits
    /// with this person" — and collapsing them is AUDIT 5.4 undone: the badge would then
    /// mean nothing more than that someone dismissed a warning.
    func testAcceptingAChangedKeyDoesNotVerifyIt() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let engine = try CryptoEngine(root: root, secrets: InMemorySecretStorage())
            let remote = PeerAddress(aci: UUID())
            try engine.adoptLocalAddress(PeerAddress(aci: UUID()))

            let original = IdentityKeyPair.generate()
            let replacement = IdentityKeyPair.generate()
            let address = try remote.makeProtocolAddress()

            _ = try engine.store.saveIdentity(
                original.identityKey, for: address, context: NullContext())
            _ = try engine.store.saveIdentity(
                replacement.identityKey, for: address, context: NullContext())

            XCTAssertTrue(
                try engine.acceptPeerIdentity(
                    replacement.identityKey.serialize(),
                    name: remote.serviceId.canonicalString,
                    deviceId: remote.deviceId))

            let state = try XCTUnwrap(
                try engine.peerIdentityState(
                    name: remote.serviceId.canonicalString, deviceId: remote.deviceId))
            XCTAssertFalse(state.needsAcknowledgement, "accepting did not unblock sending")
            XCTAssertFalse(
                state.isVerified,
                "accepting a changed key marked the peer verified, so the badge means only that a warning was dismissed")
        }.value
    }

    /// A verification that names a key the store has moved past is refused.
    ///
    /// Same reasoning as `acceptIdentity`'s: the digits the user compared are a function of
    /// one exact key, so a well-timed change between the screen being drawn and the tap must
    /// not be able to collect a verification for a key nobody looked at.
    func testVerifyingRefusesAStaleKey() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let engine = try CryptoEngine(root: root, secrets: InMemorySecretStorage())
            let remote = PeerAddress(aci: UUID())
            try engine.adoptLocalAddress(PeerAddress(aci: UUID()))

            let shown = IdentityKeyPair.generate()
            let current = IdentityKeyPair.generate()
            let address = try remote.makeProtocolAddress()

            _ = try engine.store.saveIdentity(shown.identityKey, for: address, context: NullContext())
            _ = try engine.store.saveIdentity(current.identityKey, for: address, context: NullContext())

            XCTAssertFalse(
                try engine.setPeerVerified(
                    true,
                    identityKey: shown.identityKey.serialize(),
                    name: remote.serviceId.canonicalString,
                    deviceId: remote.deviceId),
                "a verification naming a superseded key was accepted")

            let state = try XCTUnwrap(
                try engine.peerIdentityState(
                    name: remote.serviceId.canonicalString, deviceId: remote.deviceId))
            XCTAssertFalse(state.isVerified, "the stale verification was recorded anyway")
        }.value
    }

    /// The user can withdraw a verification without the key having changed.
    func testVerificationCanBeWithdrawn() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        try await Task { @CryptoActor in
            let engine = try CryptoEngine(root: root, secrets: InMemorySecretStorage())
            let remote = PeerAddress(aci: UUID())
            try engine.adoptLocalAddress(PeerAddress(aci: UUID()))

            let key = IdentityKeyPair.generate()
            _ = try engine.store.saveIdentity(
                key.identityKey, for: try remote.makeProtocolAddress(), context: NullContext())

            let name = remote.serviceId.canonicalString
            XCTAssertTrue(
                try engine.setPeerVerified(
                    true, identityKey: key.identityKey.serialize(),
                    name: name, deviceId: remote.deviceId))
            XCTAssertTrue(
                try engine.setPeerVerified(
                    false, identityKey: key.identityKey.serialize(),
                    name: name, deviceId: remote.deviceId))

            let state = try XCTUnwrap(
                try engine.peerIdentityState(name: name, deviceId: remote.deviceId))
            XCTAssertFalse(state.isVerified, "the verification could not be withdrawn")
        }.value
    }

    // MARK: - The record format

    /// The verified bit survives a round trip, and an unknown flag is still refused.
    ///
    /// The refusal is the load-bearing half. `PeerIdentityRecord` was written to reject a
    /// record carrying flags it does not understand *specifically* so that a build predating
    /// this feature reads a verified peer as unreadable rather than as unverified — a
    /// discarded verification looks conservative and is not, because it silently retracts a
    /// claim the user made after comparing digits.
    func testTheVerifiedBitRoundTripsAndUnknownFlagsAreRefused() throws {
        let key = IdentityKeyPair.generate().identityKey
        let record = PeerIdentityRecord(
            identityKey: key,
            firstSeenMs: 1_700_000_000_000,
            changedAtMs: 1_700_000_001_000,
            needsAcknowledgement: true,
            isVerified: true)

        let decoded = try PeerIdentityRecord.decode(record.encode())
        XCTAssertEqual(decoded, record)
        XCTAssertTrue(decoded.isVerified)
        XCTAssertTrue(decoded.needsAcknowledgement)

        // A record from a future build that added a third flag.
        var future = record.encode()
        future[future.startIndex + 1] |= 0x04
        XCTAssertThrowsError(try PeerIdentityRecord.decode(future)) { error in
            guard case ProtocolStoreError.malformedPeerIdentity = error else {
                return XCTFail("expected malformedPeerIdentity, got \(error)")
            }
        }
    }
}
