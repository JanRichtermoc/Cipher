//
//  ConversationQuotaTests.swift
//  CipherTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//
//  AUDIT 4.14: a peer with a valid session must not be able to fill this device.
//
//  The bound itself is the easy half. The properties that make it safe are the ones worth
//  testing, and each is a way this could have been written that would have been worse than not
//  bounding anything at all:
//
//    * Eviction must never delete the message whose own append triggered it.
//    * Eviction must take from the LARGEST conversation, so a flooding peer evicts its own
//      history — the alternative hands an attacker a remote delete primitive for someone else's.
//    * Being at the cap must never stop an EXISTING conversation from receiving.
//    * Nothing may be acknowledged that did not become durable, which is the property the whole
//      receive path is built on.
//

import CipherCrypto
import Foundation
import XCTest

@testable import Cipher

final class ConversationQuotaTests: XCTestCase {

    private var container: URL!

    override func setUp() {
        super.setUp()
        container = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("quota-\(UUID().uuidString)", isDirectory: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: container)
        super.tearDown()
    }

    /// A quota small enough to reach in a test. The shipping one needs 192 MiB written before it
    /// does anything, which is not a thing a suite can afford — and an untested quota is an
    /// assumption, not a control.
    private static func quota(
        maxConversations: Int = 256,
        maxMessagesPerConversation: Int = 5_000,
        maxDatabaseBytes: Int = 192 * 1024 * 1024,
        evictionTargetBytes: Int = 160 * 1024 * 1024,
        minRetainedPerConversation: Int = 8
    ) -> ConversationArchive.StorageQuota {
        ConversationArchive.StorageQuota(
            maxConversations: maxConversations,
            maxMessagesPerConversation: maxMessagesPerConversation,
            maxDatabaseBytes: maxDatabaseBytes,
            evictionTargetBytes: evictionTargetBytes,
            minRetainedPerConversation: minRetainedPerConversation,
            maxEvictionRounds: 4_096)
    }

    private func makeArchive(
        _ quota: ConversationArchive.StorageQuota
    ) async throws -> (ConversationArchive, CryptoEngine) {
        let engine = try await CryptoEngine.open(container: container)
        return (ConversationArchive(engine: engine, quota: quota), engine)
    }

    // MARK: - Per-conversation retention

    func testAConversationIsTrimmedToItsCapAndKeepsTheNewestMessages() async throws {
        let (archive, _) = try await makeArchive(Self.quota(maxMessagesPerConversation: 10))
        let peer = UUID()

        for index in 0..<25 {
            _ = try await archive.append(
                to: peer, direction: .incoming, text: "m\(index)",
                timestampMs: UInt64(1_000 + index), state: .received)
        }

        let stored = try await archive.messages(peer)
        XCTAssertEqual(stored.count, 10, "the cap bounds what is kept")
        XCTAssertEqual(
            stored.map(\.text), (15..<25).map { "m\($0)" },
            "retention keeps the newest, and drops the oldest")
    }

    /// The floor moves; the counter does not. Reusing an ordinal would file a new message in a
    /// slot whose AEAD-bound predecessor might still exist, and the read would then return the
    /// old message under the new one's identity.
    func testTrimmingRaisesTheFloorAndNeverRewindsTheCounter() async throws {
        let (archive, _) = try await makeArchive(Self.quota(maxMessagesPerConversation: 5))
        let peer = UUID()

        for index in 0..<12 {
            _ = try await archive.append(
                to: peer, direction: .incoming, text: "m\(index)",
                timestampMs: UInt64(index), state: .received)
        }

        let loaded = try await archive.conversation(peer)
        let record = try XCTUnwrap(loaded)
        XCTAssertEqual(record.nextOrdinal, 12, "the counter counts what was appended, ever")
        XCTAssertEqual(record.firstOrdinal, 7, "the floor is raised to leave exactly the cap")
        let ordinals = try await archive.messages(peer).map(\.ordinal)
        XCTAssertEqual(ordinals, Array(7..<12))

        // Unread cannot outlive the messages it counts.
        XCTAssertGreaterThanOrEqual(record.lastReadOrdinal, record.firstOrdinal)

        // And the next append still gets a fresh ordinal above everything ever used.
        let next = try await archive.append(
            to: peer, direction: .outgoing, text: "after", timestampMs: 99, state: .sending)
        XCTAssertEqual(next.ordinal, 12)
    }

    // MARK: - The aggregate byte quota

    /// The fairness property, and the reason this is a control rather than a liability.
    ///
    /// A peer that floods the device makes its own conversation the largest, so eviction takes
    /// from it. If eviction picked the oldest conversation, or the least recently active, or
    /// simply the first it found, then filling the store would be a way to delete *somebody
    /// else's* messages remotely — strictly worse than the disk exhaustion it was added to stop.
    func testEvictionTakesFromTheLargestConversationNotTheQuietOne() async throws {
        // Small enough that a few hundred rows crosses it.
        let (archive, _) = try await makeArchive(
            Self.quota(
                maxMessagesPerConversation: 5_000,
                maxDatabaseBytes: 256 * 1024,
                evictionTargetBytes: 192 * 1024,
                minRetainedPerConversation: 4))

        let quiet = UUID()
        let flooder = UUID()
        let body = String(repeating: "x", count: 512)

        // A short, real conversation.
        for index in 0..<6 {
            _ = try await archive.append(
                to: quiet, direction: .incoming, text: "quiet-\(index)",
                timestampMs: UInt64(index), state: .received)
        }
        let quietBefore = try await archive.messages(quiet).map(\.text)
        XCTAssertEqual(quietBefore.count, 6)

        // Then a peer that will not stop.
        for index in 0..<600 {
            _ = try await archive.append(
                to: flooder, direction: .incoming, text: "\(body)-\(index)",
                timestampMs: UInt64(index), state: .received)
        }

        let quietAfter = try await archive.messages(quiet).map(\.text)
        let flooderAfter = try await archive.messages(flooder)

        XCTAssertEqual(
            quietAfter, quietBefore,
            "the flooding peer must not be able to evict another conversation's history")
        XCTAssertLessThan(
            flooderAfter.count, 600,
            "the flood must have been trimmed, or the quota did nothing")
        XCTAssertFalse(flooderAfter.isEmpty, "eviction stops at the retention floor")
    }

    /// Eviction runs in the same transaction as the append that triggered it, and the message
    /// being appended is the newest in its conversation — so the one thing it must never do is
    /// delete the message it was called for. That is what makes acknowledging it honest.
    func testTheMessageThatTriggeredEvictionIsAlwaysStillThere() async throws {
        let (archive, _) = try await makeArchive(
            Self.quota(
                maxDatabaseBytes: 128 * 1024,
                evictionTargetBytes: 96 * 1024,
                minRetainedPerConversation: 4))

        let peer = UUID()
        let body = String(repeating: "y", count: 512)
        for index in 0..<400 {
            let appended = try await archive.append(
                to: peer, direction: .incoming, text: "\(body)-\(index)",
                timestampMs: UInt64(index), state: .received)

            // Read it back immediately: after any eviction its own append may have caused.
            let stored = try await archive.messages(peer)
            XCTAssertTrue(
                stored.contains(where: { $0.ordinal == appended.ordinal }),
                "message \(index) was evicted by the very append that stored it")
        }
    }

    // MARK: - The conversation cap

    /// The **user-initiated** half of the cap. The inbound half cannot be reached from here —
    /// it needs a real envelope to decrypt — and lives in `MessageRepositoryTests` as
    /// `testAMessageRefusedByTheConversationCapIsStillAcknowledged` and
    /// `testAnEstablishedConversationStillReceivesWhileAtTheConversationCap`.
    ///
    /// Split deliberately, and the split was found by negative testing rather than planned: an
    /// earlier version of this file asserted the inbound behaviour through `append`, which does
    /// not run the inbound check at all. It passed with the check deleted — a test green against
    /// the defect it named, which is AUDIT §0 R2 exactly.
    func testANewConversationPastTheCapIsRefusedRatherThanCreated() async throws {
        let (archive, _) = try await makeArchive(Self.quota(maxConversations: 3))

        for _ in 0..<3 {
            _ = try await archive.append(
                to: UUID(), direction: .incoming, text: "hello", timestampMs: 1,
                state: .received)
        }
        let atCap = try await archive.conversationIds().count
        XCTAssertEqual(atCap, 3)

        // The user-initiated path refuses rather than silently capping: it has a caller to tell.
        do {
            _ = try await archive.ensureConversation(UUID(), nowMs: 2)
            XCTFail("a new conversation past the cap must be refused")
        } catch {
            XCTAssertEqual(error as? ArchiveError, .conversationLimitReached)
        }
        let afterRefusal = try await archive.conversationIds().count
        XCTAssertEqual(afterRefusal, 3, "a refused conversation left nothing behind")
    }

    /// Existing conversations are never evicted to make room for a new peer. This is the
    /// property that keeps the cap from being a remote delete primitive: the loss lands on a
    /// correspondent this device has never spoken to, never on one it has.
    func testTheConversationCapNeverEvictsAnExistingConversation() async throws {
        let (archive, _) = try await makeArchive(Self.quota(maxConversations: 2))
        let established = UUID()

        _ = try await archive.append(
            to: established, direction: .incoming, text: "keep me", timestampMs: 1,
            state: .received)
        _ = try await archive.append(
            to: UUID(), direction: .incoming, text: "second", timestampMs: 2, state: .received)

        for _ in 0..<5 {
            _ = try? await archive.ensureConversation(UUID(), nowMs: 3)
        }

        let survived = try await archive.messages(established).map(\.text)
        XCTAssertEqual(survived, ["keep me"])
        let ids = try await archive.conversationIds()
        XCTAssertTrue(ids.contains(established))
        XCTAssertEqual(ids.count, 2)
    }
}
