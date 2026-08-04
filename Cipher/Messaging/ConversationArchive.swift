//
//  ConversationArchive.swift
//  Cipher
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import CipherCrypto
import Foundation
import os

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
    /// The bounds on what a peer can make this device store (AUDIT 4.14).
    private let quota: StorageQuota

    init(engine: CryptoEngine, quota: StorageQuota = .standard) {
        self.engine = engine
        self.quota = quota
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

    // MARK: - Storage quota (AUDIT 4.14)

    /// The bounds on what a peer can make this device store.
    ///
    /// **The vector.** Anyone who can fetch this account's published prekey bundle can establish
    /// a session, so inbound message volume is unauthenticated growth (the same shape as AUDIT
    /// 3.1's witness FIFO, which is bounded for exactly this reason). Individual records were
    /// already bounded — a payload is at most 32 KiB and a row at most 1 MiB — but nothing
    /// bounded their *number*, so a peer with a valid session could fill the device.
    ///
    /// **Three bounds, and why each is needed rather than implied by the others.**
    /// A per-conversation cap alone leaves `maxConversations × maxMessagesPerConversation ×
    /// 32 KiB` of headroom, which is far more disk than a phone has. A byte quota alone can be
    /// defeated by spreading one message across a great many conversations, because eviction
    /// then has nothing large to reclaim. So the count of conversations is bounded too, and the
    /// three together give a hard ceiling.
    ///
    /// **Eviction never fails the store.** Trimming happens inside the same transaction as the
    /// append that triggered it, so either both commit or neither does, and the receive path
    /// acknowledges only on that commit. Refusing to store instead would be worse than useless:
    /// the relay would redeliver the same envelope forever and `receiveExclusively` stops taking
    /// messages on a storage failure, so a full disk would wedge *all* delivery rather than
    /// bounding one conversation.
    ///
    /// **Whose history is trimmed.** Always the conversation holding the most, so a peer
    /// flooding this device evicts its own history before anybody else's. That is the property
    /// which keeps this from being a way to delete someone else's messages.
    ///
    /// **A value, not a set of global constants**, so the tests can drive eviction against a
    /// container of a few kilobytes rather than filling 192 MiB to reach the shipping limit. A
    /// quota too expensive to test is a quota nobody has watched work.
    nonisolated struct StorageQuota: Sendable, Equatable {
        /// Conversations. A private-circle messenger, so this is generous rather than tight.
        var maxConversations: Int

        /// Messages kept per conversation. The floor a trim moves, never a counter it rewinds.
        var maxMessagesPerConversation: Int

        /// Logical container size at which eviction starts.
        var maxDatabaseBytes: Int

        /// Eviction runs until the container is back under this. The gap from
        /// ``maxDatabaseBytes`` is deliberate hysteresis: evicting to exactly the limit would
        /// put the next append back over it, so every subsequent message would pay for an
        /// eviction pass.
        var evictionTargetBytes: Int

        /// A conversation is never trimmed below this, so eviction cannot empty one — and, more
        /// importantly, cannot remove the message whose own append triggered it.
        ///
        /// It also has to be small enough that the floor eviction cannot go below,
        /// `maxConversations × minRetainedPerConversation × 32 KiB` = 64 MiB, stays under
        /// ``evictionTargetBytes``. Otherwise eviction could not reach its target and would spin
        /// against a bound it can never satisfy.
        var minRetainedPerConversation: Int

        /// Termination bound, not an expected count. Each round at least halves one
        /// conversation's span, so the loop converges in far fewer; this exists so that a
        /// pathological container cannot make the receive path run unboundedly.
        var maxEvictionRounds: Int

        /// What ships.
        static let standard = StorageQuota(
            maxConversations: 256,
            maxMessagesPerConversation: 5_000,
            maxDatabaseBytes: 192 * 1024 * 1024,
            evictionTargetBytes: 160 * 1024 * 1024,
            minRetainedPerConversation: 8,
            maxEvictionRounds: 4_096)
    }

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

    /// The durable result of one inbound envelope. Unsupported payloads and blocked peers are
    /// intentionally distinct from storage failure: both still commit the ratchet and may be
    /// acknowledged, while a thrown error rolls everything back and must not be acknowledged.
    nonisolated enum IncomingDisposition: Sendable, Equatable {
        case stored
        case unsupportedPayload
        case blocked
        case undecryptable
        /// A first message from a new peer, refused because the conversation limit is reached
        /// (AUDIT 4.14).
        ///
        /// In the acknowledgeable family with `blocked` and `unsupportedPayload`, not with a
        /// thrown storage failure, and the distinction is the whole design. This is a *policy*
        /// decision taken with the ratchet committed, not a write that failed: the envelope
        /// decrypted, nothing about it is retryable, and refusing to acknowledge it would leave
        /// the relay redelivering it on every cycle while `receiveExclusively` refuses to take
        /// anything behind it. Existing conversations are never evicted to make room, so the
        /// loss is bounded to peers this device has never spoken to.
        case quotaExceeded
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
            // The same cap the inbound path enforces (AUDIT 4.14). Applied here too because the
            // aggregate byte quota can only converge while the number of conversations is
            // bounded: eviction reclaims by trimming long conversations, and a container of
            // very many short ones has nothing left to give. Refused rather than silently
            // capped, because this path is a deliberate user action and has a caller to tell.
            guard try await engine.sealedRowCount(namespace: Namespace.conversation)
                < quota.maxConversations
            else {
                throw ArchiveError.conversationLimitReached
            }
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

        let quota = self.quota
        return try await gate.withExclusiveAccess {
            // Read, write, write — all three inside one transaction and one hop onto the crypto
            // actor, so nothing can observe or interleave with the intermediate state. The old
            // layout could not do this and compensated by *ordering* the two writes so that a
            // crash between them left an orphan rather than a counter pointing at nothing.
            try await engine.withSealedTransaction { transaction in
                try Self.append(
                    to: peer, group: group, direction: direction, text: text,
                    timestampMs: timestampMs, state: state,
                    senderIdentityKey: senderIdentityKey,
                    establishedSession: establishedSession, quota: quota,
                    transaction: transaction)
            }
        }
    }

    /// Decrypts one envelope and files it with the ratchet advance in the same commit.
    ///
    /// A failure while decoding an existing archive record or writing the new one throws out of
    /// `withDecryptedMessageTransaction`, which rolls back the libsignal callbacks as well. The
    /// relay may then safely offer the exact envelope again.
    func storeIncoming(envelope: Data, timestampMs: UInt64) async throws -> IncomingDisposition {
        try await ensureMigrated()
        let quota = self.quota
        do {
            return try await gate.withExclusiveAccess {
                try await engine.withDecryptedMessageTransaction(envelope) {
                    decrypted, transaction in
                    let payload: MessagePayload
                    do {
                        payload = try MessagePayload.decode(decrypted.plaintext)
                    } catch {
                        return .unsupportedPayload
                    }

                    // Attribution comes from the session which authenticated the ciphertext,
                    // never from the relay-controlled sender field in the envelope.
                    let peer = decrypted.sender.serviceId.uuid
                    let group = Self.group(peer)
                    let existing = try transaction.load(
                        namespace: Namespace.conversation, group: group, ordinal: Self.singleton)
                        .map { try Self.decode(StoredConversation.self, from: $0) }
                    if existing?.isBlocked == true { return .blocked }

                    // A new correspondent, at the conversation cap (AUDIT 4.14). Refused here
                    // rather than by evicting somebody: an attacker who can push an existing
                    // conversation out of the store to make room for its own would have a
                    // remote delete primitive, which is a worse outcome than losing a first
                    // message from a peer this device has never spoken to. Counted, not
                    // enumerated — `rowCount` unseals nothing.
                    if existing == nil,
                        try transaction.rowCount(namespace: Namespace.conversation)
                            >= quota.maxConversations
                    {
                        return .quotaExceeded
                    }

                    let text: String
                    switch payload.content {
                    case .text(let value): text = value
                    }

                    _ = try Self.append(
                        to: peer, group: group, direction: .incoming, text: text,
                        timestampMs: timestampMs, state: .received,
                        senderIdentityKey: decrypted.senderIdentityKey,
                        establishedSession: decrypted.establishedSession, quota: quota,
                        transaction: transaction)
                    return .stored
                }
            }
        } catch let error as ArchiveError {
            throw error
        } catch is SealedStoreError {
            throw ArchiveError.storageUnavailable
        } catch MessagingError.storeUnavailable {
            throw ArchiveError.storageUnavailable
        } catch {
            // The same intentionally undifferentiated class as CryptoEngine.decrypt exposes:
            // replay, corrupt ciphertext and a rewritten routing hint all reveal nothing about
            // which one occurred. All database/archive failures were separated above.
            return .undecryptable
        }
    }

    @CryptoActor
    private static func append(
        to peer: UUID,
        group: String,
        direction: StoredMessage.Direction,
        text: String,
        timestampMs: UInt64,
        state: StoredMessage.State,
        senderIdentityKey: Data?,
        establishedSession: Bool,
        quota: StorageQuota,
        transaction: SealedRowTransaction
    ) throws -> StoredMessage {
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
            conversation.lastReadOrdinal = conversation.nextOrdinal
        }

        // Retention for this conversation, before its record is written, so the floor and the
        // rows it describes are stored by the same transaction that stored the message.
        try Self.trim(
            &conversation, toAtMost: quota.maxMessagesPerConversation, group: group,
            transaction: transaction)

        try transaction.store(
            namespace: Namespace.conversation, group: group, ordinal: Self.singleton,
            value: try Self.encode(conversation))

        // The aggregate bound, which may trim *other* conversations. Also inside this
        // transaction: a message is only ever acknowledged on its commit, so eviction cannot
        // leave the device claiming to hold something it dropped.
        try Self.evictToQuota(quota: quota, transaction: transaction)
        return message
    }

    /// Raises a conversation's retention floor to keep at most `limit` messages, deleting
    /// everything below it. Returns how many rows went.
    ///
    /// The floor only ever moves up — the same rule as "clear chat" — because `nextOrdinal` is
    /// never rewound and reusing an ordinal would file a new message in a slot whose
    /// AEAD-bound predecessor might still exist. `lastReadOrdinal` is carried up with the floor
    /// so the unread count stays a statement about messages that exist.
    @CryptoActor
    @discardableResult
    private static func trim(
        _ conversation: inout StoredConversation,
        toAtMost limit: Int,
        group: String,
        transaction: SealedRowTransaction
    ) throws -> Int {
        let floor = max(conversation.firstOrdinal, conversation.nextOrdinal - max(limit, 0))
        guard floor > conversation.firstOrdinal else { return 0 }

        let removed = try transaction.removeRowsBelow(
            namespace: Namespace.message, group: group, ordinal: floor)
        conversation.firstOrdinal = floor
        conversation.lastReadOrdinal = max(conversation.lastReadOrdinal, floor)
        return removed
    }

    /// Brings the container back under the byte quota by trimming the largest conversations.
    ///
    /// Reads the cheap measure first and returns immediately in the ordinary case, because this
    /// sits on the receive path: `usedBytes` is three header pragmas, while the enumeration
    /// below unseals every conversation record and must not run per message.
    ///
    /// Largest-first is the fairness property that makes this safe. A peer flooding the device
    /// makes *its own* conversation the largest, so it evicts its own history rather than
    /// anyone else's; conversations smaller than the floor are never touched at all.
    @CryptoActor
    private static func evictToQuota(
        quota: StorageQuota, transaction: SealedRowTransaction
    ) throws {
        var used = try transaction.usedBytes()
        guard used > quota.maxDatabaseBytes else { return }

        var records = try transaction.listNamespace(Namespace.conversation)
            .map { try Self.decode(StoredConversation.self, from: $0) }

        func span(_ record: StoredConversation) -> Int {
            max(0, record.nextOrdinal - record.firstOrdinal)
        }

        var rounds = 0
        while used > quota.evictionTargetBytes, rounds < quota.maxEvictionRounds {
            rounds += 1

            let trimmable = records.indices.filter {
                span(records[$0]) > quota.minRetainedPerConversation
            }
            guard let index = trimmable.max(by: { span(records[$0]) < span(records[$1]) })
            else { break }

            // Halve rather than shave: each round then reduces one span geometrically, so the
            // loop converges in a handful of passes instead of thousands of single-row deletes.
            let target = max(quota.minRetainedPerConversation, span(records[index]) / 2)
            let group = Self.group(records[index].peer)
            try Self.trim(&records[index], toAtMost: target, group: group, transaction: transaction)
            try transaction.store(
                namespace: Namespace.conversation, group: group, ordinal: Self.singleton,
                value: try Self.encode(records[index]))

            used = try transaction.usedBytes()
        }

        if used > quota.maxDatabaseBytes {
            // Everything is already at the retention floor. Nothing further can be reclaimed
            // without deleting conversations outright, which is exactly the primitive this
            // design refuses to give an attacker. The conversation cap is what keeps this
            // branch unreachable in practice; it is logged rather than thrown because the
            // append itself is still durable and still safe to acknowledge.
            AppLog.store.error("the local message store is at its floor and still over quota")
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
    /// The sealed container refused an operation during an atomic inbound receive.
    case storageUnavailable
    /// This device already holds `StorageQuota.maxConversations` conversations (AUDIT 4.14).
    /// Only the user-initiated path throws this; an inbound first message becomes
    /// `IncomingDisposition.quotaExceeded` instead, because nothing inbound may be retried.
    case conversationLimitReached
}
