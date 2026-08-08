//
//  ConversationArchiveTests.swift
//  CipherTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//
//  The archive is what makes "acknowledge only what is durable" possible, so its ordinal
//  bookkeeping is a correctness property and not an implementation detail: a lost ordinal is a
//  message the relay has already deleted.
//

import CipherCrypto
import Foundation
import XCTest

@testable import Cipher

final class ConversationArchiveTests: XCTestCase {

    private var container: URL!

    override func setUp() {
        super.setUp()
        container = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("archive-\(UUID().uuidString)", isDirectory: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: container)
        super.tearDown()
    }

    private func makeArchive() async throws -> (ConversationArchive, CryptoEngine) {
        let engine = try await CryptoEngine.open(container: container)
        return (ConversationArchive(engine: engine), engine)
    }

    // MARK: Round trip

    func testAppendAndReadBack() async throws {
        let (archive, _) = try await makeArchive()
        let peer = UUID()

        let first = try await archive.append(
            to: peer, direction: .outgoing, text: "one", timestampMs: 1000, state: .sending)
        let second = try await archive.append(
            to: peer, direction: .incoming, text: "two", timestampMs: 2000, state: .received,
            senderIdentityKey: Data([1, 2, 3]), establishedSession: true)

        XCTAssertEqual(first.ordinal, 0)
        XCTAssertEqual(second.ordinal, 1)

        let stored = try await archive.messages(peer)
        XCTAssertEqual(stored.map(\.text), ["one", "two"])
        XCTAssertEqual(stored[1].senderIdentityKey, Data([1, 2, 3]))
        XCTAssertTrue(stored[1].establishedSession)

        // The conversation is indexed, so it survives a relaunch — the archive offers no key
        // enumeration, exactly like the record store it sits on.
        let ids = try await archive.conversationIds()
        XCTAssertEqual(ids, [peer])
        let loaded = try await archive.conversation(peer)
        let conversation = try XCTUnwrap(loaded)
        XCTAssertEqual(conversation.nextOrdinal, 2)
    }

    func testUnreadIsDerivedFromOrdinalsRatherThanStoredSeparately() async throws {
        let (archive, _) = try await makeArchive()
        let peer = UUID()

        _ = try await archive.append(
            to: peer, direction: .incoming, text: "hi", timestampMs: 1, state: .received)
        var loaded = try await archive.conversation(peer)
        var conversation = try XCTUnwrap(loaded)
        XCTAssertEqual(conversation.nextOrdinal - conversation.lastReadOrdinal, 1)

        // Sending marks the conversation read: nothing you sent is unread.
        _ = try await archive.append(
            to: peer, direction: .outgoing, text: "hello", timestampMs: 2, state: .sent)
        loaded = try await archive.conversation(peer)
        conversation = try XCTUnwrap(loaded)
        XCTAssertEqual(conversation.nextOrdinal - conversation.lastReadOrdinal, 0)
    }

    func testMessagesPersistAcrossAFreshArchiveOverTheSameContainer() async throws {
        let peer = UUID()
        do {
            let (archive, _) = try await makeArchive()
            _ = try await archive.append(
                to: peer, direction: .incoming, text: "durable", timestampMs: 1, state: .received)
        }
        // A second engine over the same container: this is the relaunch that makes
        // acknowledging safe. If it could not read the message back, the relay would have
        // deleted something this device cannot recover.
        let (reopened, _) = try await makeArchive()
        let reread = try await reopened.messages(peer)
        XCTAssertEqual(reread.map(\.text), ["durable"])
    }

    // MARK: The interleaving the gate exists to prevent

    func testConcurrentAppendsLoseNothing() async throws {
        let (archive, _) = try await makeArchive()
        let peer = UUID()
        let count = 25

        // Without `SerialGate` these read the same `nextOrdinal`, write to the same slot, and one
        // message is silently gone — with no error anywhere, because every write succeeded.
        await withTaskGroup(of: Void.self) { group in
            for index in 0..<count {
                group.addTask {
                    _ = try? await archive.append(
                        to: peer, direction: .incoming, text: "m\(index)",
                        timestampMs: UInt64(index), state: .received)
                }
            }
        }

        let stored = try await archive.messages(peer)
        XCTAssertEqual(stored.count, count)
        XCTAssertEqual(Set(stored.map(\.ordinal)).count, count, "an ordinal was reused")
        XCTAssertEqual(Set(stored.map(\.text)).count, count, "a message was overwritten")
    }

    // MARK: Deletion

    func testDeletingOneMessageLeavesAGapThatReadsSkip() async throws {
        let (archive, _) = try await makeArchive()
        let peer = UUID()

        for index in 0..<3 {
            _ = try await archive.append(
                to: peer, direction: .incoming, text: "m\(index)",
                timestampMs: UInt64(index), state: .received)
        }
        try await archive.removeMessage(ordinal: 1, in: peer)

        let stored = try await archive.messages(peer)
        XCTAssertEqual(stored.map(\.text), ["m0", "m2"])
        // The counter does not move backwards, so the next append cannot land in the hole.
        let next = try await archive.append(
            to: peer, direction: .incoming, text: "m3", timestampMs: 3, state: .received)
        XCTAssertEqual(next.ordinal, 3)
    }

    func testClearRaisesTheFloorAndNeverReusesAnOrdinal() async throws {
        let (archive, _) = try await makeArchive()
        let peer = UUID()

        for index in 0..<3 {
            _ = try await archive.append(
                to: peer, direction: .incoming, text: "m\(index)",
                timestampMs: UInt64(index), state: .received)
        }
        try await archive.clearMessages(in: peer)
        let cleared = try await archive.messages(peer)
        XCTAssertTrue(cleared.isEmpty)

        let after = try await archive.append(
            to: peer, direction: .outgoing, text: "fresh", timestampMs: 9, state: .sent)
        XCTAssertEqual(after.ordinal, 3, "an ordinal was reused after a clear")

        let loaded = try await archive.conversation(peer)
        let conversation = try XCTUnwrap(loaded)
        XCTAssertEqual(conversation.firstOrdinal, 3)
        let remaining = try await archive.messages(peer)
        XCTAssertEqual(remaining.map(\.text), ["fresh"])
    }

    func testRemovingAConversationRemovesItsMessagesAndItsIndexEntry() async throws {
        let (archive, engine) = try await makeArchive()
        let peer = UUID()

        _ = try await archive.append(
            to: peer, direction: .incoming, text: "gone", timestampMs: 1, state: .received)
        try await archive.removeConversation(peer)

        let remainingIds = try await archive.conversationIds()
        XCTAssertTrue(remainingIds.isEmpty)
        let record = try await archive.conversation(peer)
        XCTAssertNil(record)
        let messages = try await archive.messages(peer)
        XCTAssertTrue(messages.isEmpty)

        // And the sealed record itself is gone, not merely unreachable through the index — a
        // record that outlives the thing that referenced it is the retained copy this design
        // exists to avoid.
        let slot = "\(peer.uuidString.lowercased())/0"
        let sealed = try await engine.loadSealed(namespace: "msg", key: slot)
        XCTAssertNil(sealed)
    }

    // MARK: Flags and conversation state

    func testConversationFlagsRoundTrip() async throws {
        let (archive, _) = try await makeArchive()
        let peer = UUID()
        _ = try await archive.ensureConversation(peer, nowMs: 1)

        _ = try await archive.updateConversation(peer) {
            $0.isPinned = true
            $0.isBlocked = true
            $0.nickname = "Alice"
            $0.disappearingSeconds = 3600
        }

        let loaded = try await archive.conversation(peer)
        let conversation = try XCTUnwrap(loaded)
        XCTAssertTrue(conversation.isPinned)
        XCTAssertTrue(conversation.isBlocked)
        XCTAssertEqual(conversation.nickname, "Alice")
        XCTAssertEqual(conversation.disappearingSeconds, 3600)
    }

    func testThePublicationFlagDefaultsToFalseAndPersists() async throws {
        let (archive, _) = try await makeArchive()
        var flag = try await archive.flag(ConversationArchive.keysPublishedFlag)
        XCTAssertFalse(flag)
        try await archive.setFlag(ConversationArchive.keysPublishedFlag, true)
        flag = try await archive.flag(ConversationArchive.keysPublishedFlag)
        XCTAssertTrue(flag)

        let (reopened, _) = try await makeArchive()
        flag = try await reopened.flag(ConversationArchive.keysPublishedFlag)
        XCTAssertTrue(flag)
    }

    // MARK: Migration from the P5.S10 record layout

    /// Records written by a pre-P5.S11 build must survive the storage change.
    ///
    /// They are sealed under the same key, so they are perfectly readable — which is exactly
    /// why not moving them would have been a deletion presented as an empty conversation list,
    /// rather than a format change.
    func testRecordsWrittenInTheOldLayoutAreMigratedRatherThanLost() async throws {
        let engine = try await CryptoEngine.open(container: container)
        let peer = UUID()
        let key = peer.uuidString.lowercased()

        // Exactly what P5.S10 wrote: an index of peers, a conversation record, one record per
        // message, and the publication flag.
        let conversation = """
        {"schema":1,"peer":"\(peer.uuidString)","isPinned":false,"isMuted":false,\
        "isBlocked":false,"firstOrdinal":0,"nextOrdinal":2,"lastReadOrdinal":0,\
        "lastActivityMs":99}
        """
        try await engine.storeSealed(
            namespace: "conv-index", key: "conversations",
            value: Data("[\"\(peer.uuidString)\"]".utf8))
        try await engine.storeSealed(
            namespace: "conv", key: key, value: Data(conversation.utf8))
        for ordinal in 0..<2 {
            let message = """
            {"schema":1,"id":"\(UUID().uuidString)","ordinal":\(ordinal),"direction":"incoming",\
            "text":"old \(ordinal)","timestampMs":\(ordinal + 1),"state":"received",\
            "establishedSession":false}
            """
            try await engine.storeSealed(
                namespace: "msg", key: "\(key)/\(ordinal)", value: Data(message.utf8))
        }
        try await engine.storeSealed(namespace: "flag", key: "keys-published", value: Data([1]))

        // First read through the new archive triggers the migration.
        let archive = ConversationArchive(engine: engine)
        let messages = try await archive.messages(peer)
        XCTAssertEqual(messages.map(\.text), ["old 0", "old 1"])

        let stored = try await archive.conversation(peer)
        XCTAssertEqual(stored?.nextOrdinal, 2)
        XCTAssertEqual(stored?.lastActivityMs, 99)
        let ids = try await archive.conversationIds()
        XCTAssertEqual(ids, [peer])
        let flag = try await archive.flag(ConversationArchive.keysPublishedFlag)
        XCTAssertTrue(flag, "the publication flag must survive, or keys are published twice")

        // The originals are gone, so the plaintext-free database is the only copy and a future
        // read cannot pick up a stale record.
        let oldConversation = try await engine.loadSealed(namespace: "conv", key: key)
        XCTAssertNil(oldConversation, "the old conversation record was left behind")
        let oldMessage = try await engine.loadSealed(namespace: "msg", key: "\(key)/0")
        XCTAssertNil(oldMessage, "the old message record was left behind")
        let oldIndex = try await engine.loadSealed(namespace: "conv-index", key: "conversations")
        XCTAssertNil(oldIndex, "the old index record was left behind")

        // Appending afterwards continues the counter rather than restarting it, so a migrated
        // conversation cannot overwrite its own history.
        let appended = try await archive.append(
            to: peer, direction: .outgoing, text: "new", timestampMs: 100, state: .sent)
        XCTAssertEqual(appended.ordinal, 2)
        let all = try await archive.messages(peer)
        XCTAssertEqual(all.map(\.text), ["old 0", "old 1", "new"])
    }

    /// A container that never held the old layout must not be disturbed by the migration, and
    /// the migration must not run a second time.
    func testMigrationIsANoOpOnAFreshContainerAndDoesNotRepeat() async throws {
        let (archive, engine) = try await makeArchive()
        let peer = UUID()

        _ = try await archive.append(
            to: peer, direction: .outgoing, text: "first", timestampMs: 1, state: .sent)

        // A second archive over the same container re-checks and must leave everything alone.
        let reopened = ConversationArchive(engine: engine)
        let reopenedMessages = try await reopened.messages(peer).map(\.text)
        XCTAssertEqual(reopenedMessages, ["first"])

        _ = try await reopened.append(
            to: peer, direction: .outgoing, text: "second", timestampMs: 2, state: .sent)
        let afterAppend = try await reopened.messages(peer).map(\.text)
        XCTAssertEqual(afterAppend, ["first", "second"])
    }

    // MARK: Refusals

    func testARecordFromANewerSchemaIsRefusedRatherThanPartiallyRead() async throws {
        let (archive, engine) = try await makeArchive()
        let peer = UUID()
        _ = try await archive.append(
            to: peer, direction: .incoming, text: "ok", timestampMs: 1, state: .received)

        // A record a future build wrote. Defaulting the fields this build does not know about is
        // how a "migration" loses data it never knew was there, so it must throw.
        // One past what this build writes. Derived from `expectedSchema` rather than written as
        // a literal: the literal was 2, which P6.S03 made the *current* version, and the test
        // then asserted that a record this build writes must be refused. It failed, loudly,
        // which is the good outcome — but a version behind the current one would have been
        // silently accepted forever.
        let newerSchema = ConversationArchive.StoredMessage.expectedSchema + 1
        let future = """
        {"schema":\(newerSchema),"id":"\(UUID().uuidString)","ordinal":0,\
        "direction":"incoming","text":"from the future","timestampMs":1,"state":"received",\
        "establishedSession":false}
        """
        // Planted through the row store, which is where messages live since P5.S11. The
        // invariant is unchanged; only the address of a message record moved.
        try await engine.storeSealedRow(
            namespace: "msg", group: peer.uuidString.lowercased(), ordinal: 0,
            value: Data(future.utf8))

        do {
            _ = try await archive.messages(peer)
            XCTFail("a newer schema must not be read")
        } catch let error as ArchiveError {
            XCTAssertEqual(error, .unsupportedSchema(newerSchema))
        }
    }

    func testAnUnreadableRecordIsAFailureRatherThanAnEmptyConversation() async throws {
        let (archive, engine) = try await makeArchive()
        let peer = UUID()
        _ = try await archive.append(
            to: peer, direction: .incoming, text: "ok", timestampMs: 1, state: .received)

        try await engine.storeSealedRow(
            namespace: "msg", group: peer.uuidString.lowercased(), ordinal: 0,
            value: Data("not json".utf8))

        do {
            _ = try await archive.messages(peer)
            XCTFail("garbage must not read as an empty conversation")
        } catch let error as ArchiveError {
            XCTAssertEqual(error, .malformedRecord)
        }
    }
}
