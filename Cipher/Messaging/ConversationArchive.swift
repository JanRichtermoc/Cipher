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
/// ## Why durable storage is a prerequisite, not a feature
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
/// ## The storage format (P5.S11)
///
/// P5.S10 gave this type one sealed record per message, plus one per conversation and an index
/// listing them. That was correct and not queryable: reading a conversation was one record read
/// per message, deleting one was a loop of unlinks, and "what conversations exist?" could only
/// be answered by an index record kept in step by hand. `AUDIT.md` 4.3 recorded the residual
/// precisely — **query shape, not confidentiality**.
///
/// It is now `CryptoEngine`'s sealed row store: still in the crypto module's container, still
/// on the crypto queue, still AES-GCM under a key derived from the one Keychain item whose
/// deletion erases everything. What changed is that rows are addressed by
/// `(namespace, group, ordinal)` and can be listed, so a conversation is one query and a
/// deletion is one statement. **Nothing above this type noticed the change**, which is what the
/// P5.S10 comment meant by keeping layout knowledge here.
///
/// The peer never reaches disk as an identifier: the group is blinded to an HMAC tag inside the
/// crypto module (`SealedRecordDatabase.groupTag`), so the container still names nobody. The
/// index record is gone — conversations are recovered by listing the `conv` namespace and
/// reading each peer from *inside* the sealed value, so there is no longer a second thing that
/// can disagree with the first.
///
/// ## Ordinals
///
/// Each conversation owns a monotonic counter, and a message is stored at that ordinal. The
/// counter is **never rewound**, including by "clear chat", which moves a floor instead
/// (`firstOrdinal`). Reusing an ordinal would put a new message in a slot whose AEAD-bound
/// predecessor may still exist if its deletion failed, and the read would then return the old
/// message under the new one's identity.
///
/// ## Atomicity
///
/// Appending reads the counter, writes the message under it, and writes the counter back. That
/// sequence is now **one transaction**, so there is no window to survive rather than a window
/// arranged to be survivable. `SerialGate` stays regardless and is not made redundant by it:
/// the interleaving `AUDIT.md` 4.10 records is in this actor's read-modify-write across
/// `await`s, which no database transaction can see. Both, deliberately.
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
        static let flag = "flag"
        /// No writer any more — the conversation list is derived from the records themselves.
        /// Kept so the migration can still find a P5.S10 index and move what it points at.
        static let index = "conv-index"
    }

    /// Where a group's only row lives.
    ///
    /// A conversation record and a flag are each "the one row for this group"; messages are the
    /// only namespace in which the ordinal carries meaning. Naming it rather than writing `0` at
    /// nine call sites keeps that distinction visible.
    private static let singleton = 0

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

    // MARK: - Conversations

    /// Every peer with a conversation record.
    ///
    /// Derived from the records themselves rather than from an index beside them. The old
    /// layout had no choice — record filenames are hashes and the store offers no enumeration —
    /// so an index record listed the peers and every create and delete had to remember to
    /// update it. Deriving removes the possibility of the two disagreeing.
    func conversationIds() async throws -> [UUID] {
        try await conversations().map(\.peer)
    }

    func conversation(_ peer: UUID) async throws -> StoredConversation? {
        try await ensureMigrated()
        guard let bytes = try await engine.loadSealedRow(
            namespace: Namespace.conversation, group: Self.group(peer), ordinal: Self.singleton)
        else { return nil }
        return try Self.decode(StoredConversation.self, from: bytes)
    }

    func conversations() async throws -> [StoredConversation] {
        try await ensureMigrated()
        return try await engine.listSealedNamespace(namespace: Namespace.conversation)
            .map { try Self.decode(StoredConversation.self, from: $0) }
    }

    /// Creates the conversation if it does not exist, and returns it either way.
    @discardableResult
    func ensureConversation(_ peer: UUID, nowMs: UInt64) async throws -> StoredConversation {
        try await ensureMigrated()
        return try await gate.withExclusiveAccess {
            if let existing = try await conversation(peer) { return existing }
            let record = StoredConversation(peer: peer, lastActivityMs: nowMs)
            try await write(record)
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
        try await ensureMigrated()
        return try await gate.withExclusiveAccess {
            guard var record = try await conversation(peer) else { return nil }
            change(&record)
            try await write(record)
            return record
        }
    }

    /// Deletes a conversation and every message in it.
    ///
    /// Two statements and one transaction, where this was a loop over every ordinal the caller
    /// had to know about — and therefore a deletion that could stop half way and leave messages
    /// behind under a conversation that no longer existed.
    func removeConversation(_ peer: UUID) async throws {
        try await ensureMigrated()
        let group = Self.group(peer)
        try await gate.withExclusiveAccess {
            try await engine.withSealedTransaction { transaction in
                try transaction.removeGroup(namespace: Namespace.message, group: group)
                try transaction.remove(
                    namespace: Namespace.conversation, group: group, ordinal: Self.singleton)
            }
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
        try await ensureMigrated()
        let group = Self.group(peer)

        return try await gate.withExclusiveAccess {
            // Read, write, write — all three inside one transaction and one hop onto the crypto
            // actor, so nothing can observe or interleave with the intermediate state. The old
            // layout could not do this and compensated by *ordering* the two writes so that a
            // crash between them left an orphan rather than a counter pointing at nothing.
            try await engine.withSealedTransaction { transaction in
                var conversation = try transaction.load(
                    namespace: Namespace.conversation, group: group, ordinal: Self.singleton)
                    .map { try Self.decode(StoredConversation.self, from: $0) }
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

                try transaction.store(
                    namespace: Namespace.message, group: group, ordinal: message.ordinal,
                    value: try Self.encode(message))

                conversation.nextOrdinal += 1
                conversation.lastActivityMs = max(conversation.lastActivityMs, timestampMs)
                if direction == .outgoing {
                    // Nothing you sent is unread.
                    conversation.lastReadOrdinal = conversation.nextOrdinal
                }
                try transaction.store(
                    namespace: Namespace.conversation, group: group, ordinal: Self.singleton,
                    value: try Self.encode(conversation))

                return message
            }
        }
    }

    /// Every message in the conversation, oldest first.
    ///
    /// One ordered query. Gaps need no handling at all now — a deleted message is simply a row
    /// that is not there — where the old layout had to read every ordinal between the floor and
    /// the counter and skip the misses. A row that is *present but unreadable* still throws,
    /// because that is tampering or a wrong key and must never read as absence.
    func messages(_ peer: UUID) async throws -> [StoredMessage] {
        try await ensureMigrated()
        return try await engine.listSealedRows(
            namespace: Namespace.message, group: Self.group(peer))
            .map { try Self.decode(StoredMessage.self, from: $0.value) }
    }

    /// Replaces a stored message in place. Used for the send status transition only.
    func updateMessage(_ message: StoredMessage, in peer: UUID) async throws {
        try await ensureMigrated()
        try await gate.withExclusiveAccess {
            try await engine.storeSealedRow(
                namespace: Namespace.message,
                group: Self.group(peer),
                ordinal: message.ordinal,
                value: try Self.encode(message))
        }
    }

    func removeMessage(ordinal: Int, in peer: UUID) async throws {
        try await ensureMigrated()
        try await gate.withExclusiveAccess {
            try await engine.removeSealedRow(
                namespace: Namespace.message, group: Self.group(peer), ordinal: ordinal)
        }
    }

    /// Deletes every message but keeps the conversation.
    ///
    /// The removal and the raised floor are one transaction, so the two cannot disagree. The
    /// old layout had to order them — floor raised only *after* every removal succeeded — so
    /// that a failure part way through left messages still reachable rather than stranded above
    /// an advanced floor. There is no longer a part way through.
    func clearMessages(in peer: UUID) async throws {
        try await ensureMigrated()
        let group = Self.group(peer)
        try await gate.withExclusiveAccess {
            try await engine.withSealedTransaction { transaction in
                guard var record = try transaction.load(
                    namespace: Namespace.conversation, group: group, ordinal: Self.singleton)
                    .map({ try Self.decode(StoredConversation.self, from: $0) })
                else { return }

                try transaction.removeGroup(namespace: Namespace.message, group: group)
                record.firstOrdinal = record.nextOrdinal
                record.lastReadOrdinal = record.nextOrdinal
                try transaction.store(
                    namespace: Namespace.conversation, group: group, ordinal: Self.singleton,
                    value: try Self.encode(record))
            }
        }
    }

    // MARK: - Installation flags

    /// A small durable boolean — currently only "the prekey publication succeeded".
    ///
    /// Sealed in the same container as everything else, which matters: it is destroyed together
    /// with the identity it describes, so a reset cannot leave a flag claiming keys were
    /// published for an identity that no longer exists.
    func flag(_ name: String) async throws -> Bool {
        try await ensureMigrated()
        guard let bytes = try await engine.loadSealedRow(
            namespace: Namespace.flag, group: name, ordinal: Self.singleton),
            let first = bytes.first
        else { return false }
        return first == 1
    }

    func setFlag(_ name: String, _ value: Bool) async throws {
        try await ensureMigrated()
        try await engine.storeSealedRow(
            namespace: Namespace.flag, group: name, ordinal: Self.singleton,
            value: Data([value ? 1 : 0]))
    }

    static let keysPublishedFlag = "keys-published"

    // MARK: - Coding

    private func write(_ record: StoredConversation) async throws {
        try await engine.storeSealedRow(
            namespace: Namespace.conversation,
            group: Self.group(record.peer),
            ordinal: Self.singleton,
            value: try Self.encode(record))
    }

    /// A peer's group. Lowercased so one peer is one group whatever case a caller used; blinded
    /// to an HMAC tag inside the crypto module, so this string never reaches disk.
    private static func group(_ peer: UUID) -> String { peer.uuidString.lowercased() }

    private static func encode<T: Encodable>(_ value: T) throws -> Data {
        try ArchiveCoding.encode(value)
    }

    private static func decode<T: Decodable & SchemaVersioned>(
        _ type: T.Type, from bytes: Data
    ) throws -> T {
        try ArchiveCoding.decode(type, from: bytes)
    }

    /// The old index was a bare array of ids with no schema of its own. Read only by the
    /// migration now — nothing writes one any more.
    private static func decodeIndex(_ bytes: Data) throws -> [UUID] {
        do {
            return try JSONDecoder().decode([UUID].self, from: bytes)
        } catch {
            throw ArchiveError.malformedRecord
        }
    }

    // MARK: - Migration from the P5.S10 record layout

    /// Whether this instance has already checked. Per-instance, and that is enough: the check is
    /// idempotent and the marker it reads is durable, so a second instance re-reads one row and
    /// finds the work done.
    private var didMigrate = false

    /// Moves anything written in the old key-value layout into the database, once.
    ///
    /// **Why this exists at all when nothing has shipped:** the records are sealed under the
    /// same key, so they are perfectly readable — changing the storage format without moving
    /// them would not be a format change, it would be a deletion that presented as an empty
    /// conversation list. A developer build's history is not precious, but silently discarding
    /// data the app can still read is the wrong default to establish in the one place where
    /// "acknowledged means the relay deleted its copy" is true.
    ///
    /// **Called before the gate, never inside it.** `SerialGate` is a plain FIFO mutex with no
    /// reentrancy, so a nested acquire from the same task would deadlock. Every entry point
    /// calls this first, and after the first call it returns without touching the gate at all.
    private func ensureMigrated() async throws {
        if didMigrate { return }
        try await gate.withExclusiveAccess {
            // Re-checked inside the gate: several callers can arrive together, and only one of
            // them should do the work.
            if didMigrate { return }
            try await migrate()
            didMigrate = true
        }
    }

    private func migrate() async throws {
        // The marker lives in the database, so it is written by the same transaction as the
        // data it describes and cannot claim a migration that did not commit.
        if try await engine.loadSealedRow(
            namespace: Namespace.flag, group: Self.migratedFlag, ordinal: Self.singleton) != nil {
            return
        }

        // Read everything first. The old records can be enumerated despite the record store
        // offering no enumeration, because the archive kept its own index: the index names the
        // peers, and each conversation record carries the ordinal range of its messages.
        var conversations: [StoredConversation] = []
        var messages: [(group: String, message: StoredMessage)] = []

        if let indexBytes = try await engine.loadSealed(
            namespace: Namespace.index, key: Self.legacyIndexKey) {
            for peer in try Self.decodeIndex(indexBytes) {
                guard let bytes = try await engine.loadSealed(
                    namespace: Namespace.conversation, key: Self.legacyKey(peer)) else { continue }
                let conversation = try Self.decode(StoredConversation.self, from: bytes)
                conversations.append(conversation)

                for ordinal in conversation.firstOrdinal..<conversation.nextOrdinal {
                    guard let messageBytes = try await engine.loadSealed(
                        namespace: Namespace.message, key: Self.legacyKey(peer, ordinal))
                    else { continue }
                    messages.append((
                        Self.group(peer), try Self.decode(StoredMessage.self, from: messageBytes)))
                }
            }
        }

        let publishedFlag = try await engine.loadSealed(
            namespace: Namespace.flag, key: Self.keysPublishedFlag)

        // Write everything, and the marker, in one transaction. Either the new layout holds all
        // of it or none of it; there is no state in which half a conversation has moved.
        let conversationsToWrite = conversations
        let messagesToWrite = messages
        try await engine.withSealedTransaction { transaction in
            for conversation in conversationsToWrite {
                try transaction.store(
                    namespace: Namespace.conversation, group: Self.group(conversation.peer),
                    ordinal: Self.singleton, value: try Self.encode(conversation))
            }
            for entry in messagesToWrite {
                try transaction.store(
                    namespace: Namespace.message, group: entry.group,
                    ordinal: entry.message.ordinal, value: try Self.encode(entry.message))
            }
            if let publishedFlag {
                try transaction.store(
                    namespace: Namespace.flag, group: Self.keysPublishedFlag,
                    ordinal: Self.singleton, value: publishedFlag)
            }
            try transaction.store(
                namespace: Namespace.flag, group: Self.migratedFlag, ordinal: Self.singleton,
                value: Data([1]))
        }

        // Only now delete the originals, and deliberately *after* the commit rather than in it:
        // they are files, so they cannot join a database transaction, and an interruption here
        // leaves unreferenced records rather than losing a message. The marker is already
        // durable, so the next launch will not copy them a second time.
        for conversation in conversations {
            for ordinal in conversation.firstOrdinal..<conversation.nextOrdinal {
                try await engine.removeSealed(
                    namespace: Namespace.message,
                    key: Self.legacyKey(conversation.peer, ordinal))
            }
            try await engine.removeSealed(
                namespace: Namespace.conversation, key: Self.legacyKey(conversation.peer))
        }
        if !conversations.isEmpty || publishedFlag != nil {
            try await engine.removeSealed(namespace: Namespace.index, key: Self.legacyIndexKey)
            try await engine.removeSealed(namespace: Namespace.flag, key: Self.keysPublishedFlag)
        }
    }

    /// Namespace and keys used only by the migration. The `conv-index` namespace has no writer
    /// any more; it is named here so the reader of a record written by P5.S10 can find it.
    private static let legacyIndexKey = "conversations"
    private static let migratedFlag = "storage-migrated-v1"

    private static func legacyKey(_ peer: UUID) -> String { peer.uuidString.lowercased() }

    private static func legacyKey(_ peer: UUID, _ ordinal: Int) -> String {
        "\(peer.uuidString.lowercased())/\(ordinal)"
    }
}

// MARK: - Schema checking

nonisolated protocol SchemaVersioned {
    var schema: Int { get }
    static var expectedSchema: Int { get }
}

/// The one codec for everything sealed in this container.
///
/// **Shared rather than reimplemented per archive, on purpose.** The schema refusal below is a
/// security check, and a security check with two copies is one that will eventually exist in
/// only one of them — the same failure this project has already recorded twice, as AUDIT 5.7 (a
/// gate condition written in two places) and 5.14 (a guard list that covered one language). A
/// second archive was added by this step; it uses this, and so does the first.
nonisolated enum ArchiveCoding {

    static func encode<T: Encodable>(_ value: T) throws -> Data {
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
    static func decode<T: Decodable & SchemaVersioned>(
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
}

nonisolated enum ArchiveError: Error, Equatable {
    /// Not decodable at all: truncated, or written by something else entirely.
    case malformedRecord
    /// Written by a build with a newer format. Refused rather than partially believed.
    case unsupportedSchema(Int)
}
