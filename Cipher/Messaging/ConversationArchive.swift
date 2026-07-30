//
//  ConversationArchive.swift
//  Cipher
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import CipherCrypto
import Foundation

/// Conversations and message bodies, sealed in the crypto module's container.
///
/// ## Why this exists before the database (P5.S11)
///
/// The receive path forces the question. `THREAT_MODEL.md` §3.1 makes acknowledgement the
/// highest-value control on the server — the relay cannot delete a message until a client says
/// it has it — and libsignal makes an envelope decryptable exactly **once**: the ratchet
/// consumes the message key, and a second attempt on the same bytes fails by design. Those two
/// facts together leave no third option:
///
/// - Acknowledge with the plaintext held only in memory, and a crash or a relaunch loses the
///   message permanently — the relay has already deleted it, and the envelope cannot be
///   decrypted again.
/// - Do not acknowledge, and every launch re-fetches envelopes that can no longer be decrypted,
///   while ciphertext accumulates on a host that is assumed seizable for the full 30-day TTL.
///
/// So durable storage is a prerequisite for a correct receive loop, not a feature that can
/// follow it. This is the smallest thing that is actually correct: one sealed record per
/// message, one per conversation, and an index. **P5.S11 replaces the storage format** with a
/// queryable database — which is why nothing above this type knows how records are laid out,
/// and why `AUDIT.md` 4.3 stays open until then rather than being quietly declared closed.
///
/// ## Ordinals, and why there is no index rewrite per message
///
/// Each conversation owns a monotonic counter. A message is stored under
/// `<peer>/<ordinal>` and the counter is then advanced, so appending is two small writes
/// regardless of how long the conversation is — the alternative, an index blob listing every
/// message id, is rewritten on every message and grows without bound inside a record that has a
/// size ceiling.
///
/// The counter is **never rewound**, including by "clear chat", which moves a floor instead
/// (`firstOrdinal`). Reusing an ordinal would put a new message in a slot whose AEAD-bound
/// predecessor may still be on disk if its deletion failed, and the read would then return the
/// old message under the new one's identity.
///
/// ## Crash ordering
///
/// The message record is written **before** the counter that reveals it. A crash between the two
/// leaves an unreferenced record that the next append overwrites — invisible, and never a
/// counter pointing at a slot with nothing in it. Reads tolerate gaps regardless, because
/// deleting a single message leaves one.
actor ConversationArchive {

    private let engine: CryptoEngine
    /// Read-modify-write over an async store is not atomic under actor reentrancy. See
    /// ``SerialGate``.
    private let gate = SerialGate()

    init(engine: CryptoEngine) {
        self.engine = engine
    }

    // MARK: - Namespaces

    private enum Namespace {
        static let conversation = "conv"
        static let message = "msg"
        static let index = "conv-index"
        static let flag = "flag"
    }

    private static let indexKey = "conversations"

    // MARK: - Records

    /// Everything about a conversation that is not a message.
    ///
    /// The peer's local nickname lives here rather than in `UserDefaults`, where the profile
    /// fields still are (AUDIT 4.7): a list of who this device talks to is precisely the social
    /// graph the design refuses to hand the relay, and leaving it unencrypted in the app
    /// container would hand it to anything with container access instead.
    nonisolated struct StoredConversation: Codable, Sendable, Equatable, SchemaVersioned {
        /// Refused rather than migrated if it is not this build's. A record written by a newer
        /// build must never be half-understood — the fields this build would default are
        /// exactly the ones it does not know it is dropping.
        static let expectedSchema = 1

        var schema: Int = StoredConversation.expectedSchema
        /// The peer's ACI. Also the conversation's identity everywhere in the UI.
        var peer: UUID
        /// What the user calls them. Nil until they name them; the UI then shows the ACI,
        /// which is honest — the relay has no concept of a profile (`BACKEND.md` §2.1) and
        /// there is no directory to look a name up in.
        var nickname: String?
        var isPinned: Bool = false
        var isMuted: Bool = false
        var isBlocked: Bool = false
        var disappearingSeconds: Int?
        /// The oldest ordinal that may still exist. Raised by a clear, never lowered.
        var firstOrdinal: Int = 0
        /// The next ordinal to allocate. Only ever increases.
        var nextOrdinal: Int = 0
        /// Ordinals below this have been read. `nextOrdinal - lastReadOrdinal` is the unread
        /// count, so marking read cannot drift out of step with what exists.
        var lastReadOrdinal: Int = 0
        var lastActivityMs: UInt64 = 0
    }

    nonisolated struct StoredMessage: Codable, Sendable, Equatable, SchemaVersioned {
        static let expectedSchema = 1

        enum Direction: String, Codable, Sendable {
            case outgoing
            case incoming
        }

        /// Only states the client can actually observe. There are no delivery or read receipts
        /// on the wire, so there is no `delivered` and no `read` — a checkmark for either would
        /// be a claim about the recipient's device that nothing here can support.
        enum State: String, Codable, Sendable {
            /// Encrypted and stored, not yet accepted by the relay.
            case sending
            /// The relay returned 202. It has the ciphertext; nothing more is known.
            case sent
            /// The relay refused it or could not be reached. Retrying re-encrypts.
            case failed
            /// Received from a peer.
            case received
        }

        var schema: Int = StoredMessage.expectedSchema
        var id: UUID
        var ordinal: Int
        var direction: Direction
        var text: String
        var timestampMs: UInt64
        var state: State
        /// For an incoming message: the identity key of the session that authenticated it —
        /// the value a safety number is computed from, and the only attribution that is a fact
        /// (see `DecryptedMessage`). Nil for outgoing.
        var senderIdentityKey: Data?
        /// True when this message established the session. Held to a weaker standard: the
        /// address it arrived under is chosen by whoever relayed it (AUDIT 3.8).
        var establishedSession: Bool = false
    }

    // MARK: - Index

    func conversationIds() async throws -> [UUID] {
        guard let bytes = try await engine.loadSealed(
            namespace: Namespace.index, key: Self.indexKey) else { return [] }
        return try Self.decodeIndex(bytes)
    }

    private func addToIndex(_ peer: UUID) async throws {
        var ids = try await conversationIds()
        guard !ids.contains(peer) else { return }
        ids.append(peer)
        try await engine.storeSealed(
            namespace: Namespace.index, key: Self.indexKey, value: try Self.encode(ids))
    }

    private func removeFromIndex(_ peer: UUID) async throws {
        var ids = try await conversationIds()
        guard let at = ids.firstIndex(of: peer) else { return }
        ids.remove(at: at)
        try await engine.storeSealed(
            namespace: Namespace.index, key: Self.indexKey, value: try Self.encode(ids))
    }

    // MARK: - Conversations

    func conversation(_ peer: UUID) async throws -> StoredConversation? {
        guard let bytes = try await engine.loadSealed(
            namespace: Namespace.conversation, key: Self.key(peer)) else { return nil }
        return try Self.decode(StoredConversation.self, from: bytes)
    }

    func conversations() async throws -> [StoredConversation] {
        var out: [StoredConversation] = []
        for id in try await conversationIds() {
            if let record = try await conversation(id) { out.append(record) }
        }
        return out
    }

    /// Creates the conversation if it does not exist, and returns it either way.
    @discardableResult
    func ensureConversation(_ peer: UUID, nowMs: UInt64) async throws -> StoredConversation {
        try await gate.withExclusiveAccess {
            if let existing = try await conversation(peer) { return existing }
            let record = StoredConversation(peer: peer, lastActivityMs: nowMs)
            try await write(record)
            try await addToIndex(peer)
            return record
        }
    }

    /// Applies `change` to the stored conversation under exclusive access.
    ///
    /// Mutations go through here rather than through a load / edit / save the caller writes
    /// itself, so no caller can accidentally hold a stale copy across a suspension and write
    /// back a counter that has moved.
    @discardableResult
    func updateConversation(
        _ peer: UUID, _ change: @Sendable (inout StoredConversation) -> Void
    ) async throws -> StoredConversation? {
        try await gate.withExclusiveAccess {
            guard var record = try await conversation(peer) else { return nil }
            change(&record)
            try await write(record)
            return record
        }
    }

    /// Deletes a conversation and every message in it.
    func removeConversation(_ peer: UUID) async throws {
        try await gate.withExclusiveAccess {
            if let record = try await conversation(peer) {
                for ordinal in record.firstOrdinal..<record.nextOrdinal {
                    try await engine.removeSealed(
                        namespace: Namespace.message, key: Self.key(peer, ordinal))
                }
            }
            try await engine.removeSealed(
                namespace: Namespace.conversation, key: Self.key(peer))
            try await removeFromIndex(peer)
        }
    }

    // MARK: - Messages

    /// Stores a message and advances the conversation's counter.
    ///
    /// - Returns: the stored message, with the ordinal it was given.
    func append(
        to peer: UUID,
        direction: StoredMessage.Direction,
        text: String,
        timestampMs: UInt64,
        state: StoredMessage.State,
        senderIdentityKey: Data? = nil,
        establishedSession: Bool = false
    ) async throws -> StoredMessage {
        try await gate.withExclusiveAccess {
            var conversation = try await conversation(peer)
                ?? StoredConversation(peer: peer, lastActivityMs: timestampMs)

            let message = StoredMessage(
                id: UUID(),
                ordinal: conversation.nextOrdinal,
                direction: direction,
                text: text,
                timestampMs: timestampMs,
                state: state,
                senderIdentityKey: senderIdentityKey,
                establishedSession: establishedSession)

            // Message first, counter second. See the type comment: a crash between them
            // orphans a record, while the reverse would publish an ordinal with nothing in it.
            try await engine.storeSealed(
                namespace: Namespace.message,
                key: Self.key(peer, message.ordinal),
                value: try Self.encode(message))

            conversation.nextOrdinal += 1
            conversation.lastActivityMs = max(conversation.lastActivityMs, timestampMs)
            if direction == .outgoing {
                // Nothing you sent is unread.
                conversation.lastReadOrdinal = conversation.nextOrdinal
            }
            try await write(conversation)
            try await addToIndex(peer)

            return message
        }
    }

    /// Every message in the conversation, oldest first.
    ///
    /// Gaps are skipped rather than treated as corruption: deleting one message leaves its
    /// ordinal empty by design. A record that is *present but unreadable* is a different thing
    /// and throws, because that is tampering or a wrong key and must never read as absence.
    func messages(_ peer: UUID) async throws -> [StoredMessage] {
        guard let conversation = try await conversation(peer) else { return [] }

        var out: [StoredMessage] = []
        out.reserveCapacity(conversation.nextOrdinal - conversation.firstOrdinal)
        for ordinal in conversation.firstOrdinal..<conversation.nextOrdinal {
            guard let bytes = try await engine.loadSealed(
                namespace: Namespace.message, key: Self.key(peer, ordinal)) else { continue }
            out.append(try Self.decode(StoredMessage.self, from: bytes))
        }
        return out
    }

    /// Replaces a stored message in place. Used for the send status transition only.
    func updateMessage(_ message: StoredMessage, in peer: UUID) async throws {
        try await gate.withExclusiveAccess {
            try await engine.storeSealed(
                namespace: Namespace.message,
                key: Self.key(peer, message.ordinal),
                value: try Self.encode(message))
        }
    }

    func removeMessage(ordinal: Int, in peer: UUID) async throws {
        try await gate.withExclusiveAccess {
            try await engine.removeSealed(
                namespace: Namespace.message, key: Self.key(peer, ordinal))
        }
    }

    /// Deletes every message but keeps the conversation.
    ///
    /// The floor is raised **after** the removals succeed, so a failure part-way through leaves
    /// records that are still reachable rather than orphaned above an advanced floor.
    func clearMessages(in peer: UUID) async throws {
        try await gate.withExclusiveAccess {
            guard var record = try await conversation(peer) else { return }
            for ordinal in record.firstOrdinal..<record.nextOrdinal {
                try await engine.removeSealed(
                    namespace: Namespace.message, key: Self.key(peer, ordinal))
            }
            record.firstOrdinal = record.nextOrdinal
            record.lastReadOrdinal = record.nextOrdinal
            try await write(record)
        }
    }

    // MARK: - Installation flags

    /// A small durable boolean — currently only "the prekey publication succeeded".
    ///
    /// Sealed in the same container as everything else, which matters: it is destroyed together
    /// with the identity it describes, so a reset cannot leave a flag claiming keys were
    /// published for an identity that no longer exists.
    func flag(_ name: String) async throws -> Bool {
        guard let bytes = try await engine.loadSealed(
            namespace: Namespace.flag, key: name), let first = bytes.first else { return false }
        return first == 1
    }

    func setFlag(_ name: String, _ value: Bool) async throws {
        try await engine.storeSealed(
            namespace: Namespace.flag, key: name, value: Data([value ? 1 : 0]))
    }

    static let keysPublishedFlag = "keys-published"

    // MARK: - Coding

    private func write(_ record: StoredConversation) async throws {
        try await engine.storeSealed(
            namespace: Namespace.conversation,
            key: Self.key(record.peer),
            value: try Self.encode(record))
    }

    private static func key(_ peer: UUID) -> String { peer.uuidString.lowercased() }

    private static func key(_ peer: UUID, _ ordinal: Int) -> String {
        "\(peer.uuidString.lowercased())/\(ordinal)"
    }

    private static func encode<T: Encodable>(_ value: T) throws -> Data {
        try JSONEncoder().encode(value)
    }

    /// Decodes a versioned record, then refuses a schema this build does not implement.
    ///
    /// Constrained to `SchemaVersioned` rather than to `Decodable`, so a record type added
    /// without a version cannot be read through here at all. That is deliberate: the failure
    /// this avoids is not a missing check, it is a check that quietly stops covering half the
    /// store because someone added a type and never noticed it bypassed the switch.
    ///
    /// The comparison happens after decoding because `Codable` offers no cheap way to peek. It
    /// is still a refusal and not a repair — a record from a newer build has fields this one
    /// would silently default, and defaulting them is how a "migration" loses data it never
    /// knew was there.
    private static func decode<T: Decodable & SchemaVersioned>(
        _ type: T.Type, from bytes: Data
    ) throws -> T {
        let value: T
        do {
            value = try JSONDecoder().decode(type, from: bytes)
        } catch {
            throw ArchiveError.malformedRecord
        }
        guard value.schema == type.expectedSchema else {
            throw ArchiveError.unsupportedSchema(value.schema)
        }
        return value
    }

    /// The index is a bare array of ids with no schema of its own: there is nothing in it that
    /// a future version could reinterpret, and giving it a wrapper purely to carry a version
    /// would be ceremony rather than a control.
    private static func decodeIndex(_ bytes: Data) throws -> [UUID] {
        do {
            return try JSONDecoder().decode([UUID].self, from: bytes)
        } catch {
            throw ArchiveError.malformedRecord
        }
    }
}

// MARK: - Schema checking

nonisolated protocol SchemaVersioned {
    var schema: Int { get }
    static var expectedSchema: Int { get }
}

nonisolated enum ArchiveError: Error, Equatable {
    /// Not decodable at all: truncated, or written by something else entirely.
    case malformedRecord
    /// Written by a build with a newer format. Refused rather than partially believed.
    case unsupportedSchema(Int)
}
