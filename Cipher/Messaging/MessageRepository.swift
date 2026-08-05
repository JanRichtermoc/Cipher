//
//  MessageRepository.swift
//  Cipher
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import CipherCrypto
import Foundation
import OSLog

/// The real messaging path: encrypt before send, decrypt after fetch, persist sealed.
///
/// This is what closes C-02. Before it, every screen read `MockStore` — an in-memory array of
/// plaintext fixtures with no crypto and no network anywhere near it — so the app's entire
/// messaging behaviour was a drawing of a messenger. Nothing in this file has a plaintext
/// fallback: there is no path that stores a body outside the sealed container and no path that
/// sends bytes that were not produced by `CryptoEngine.encrypt`.
///
/// ## The three orderings that matter
///
/// 1. **Send: store, then encrypt, then transmit.** The message is durable before anything can
///    fail, so a crash mid-send leaves a message the user can see and retry rather than one that
///    silently never existed. Encryption steps the ratchet, so a failed transmission is retried
///    by re-encrypting — the old envelope is not resent, because a duplicate is undecryptable at
///    the far end and would look like success to the sender.
/// 2. **Receive: decrypt and store in one transaction, then acknowledge.** Acknowledgement
///    deletes the relay's copy (`THREAT_MODEL.md` §3.1) and an envelope decrypts exactly once,
///    so the ratchet advance and sealed plaintext must commit or roll back together.
/// 3. **Registration: adopt the address, then publish.** Publishing keys for an installation
///    that has not adopted its own address would advertise a bundle whose private halves this
///    device could not associate with anything.
///
/// ## What is *not* acknowledged
///
/// A message this device cannot decrypt or cannot understand **is** acknowledged and dropped:
/// retrying it can never succeed, and leaving it on the relay means ciphertext retained for the
/// full TTL and a permanent failure on every launch. A message that failed to *store* is not
/// acknowledged, because that one really is still waiting. `MessagingError.storeUnavailable`
/// exists to make those two distinguishable.
actor MessageRepository {

    private let engine: CryptoEngine
    private let archive: ConversationArchive
    private let directory: RelayKeyDirectory
    private let mailbox: RelayMailbox
    private let sessions: SessionStore
    private let now: @Sendable () -> Date
    /// Serialises operations which span the relay, crypto actor and archive. Actor isolation
    /// alone permits another call to interleave at each `await`.
    private let operationGate = SerialGate()

    /// Ceiling on how many pages one `receive()` will drain.
    ///
    /// The relay caps a batch at 100 and reports `more`, so without a bound a device returning
    /// after a long absence would loop until its queue emptied — holding this actor, and with it
    /// every send, for as long as that took. Twenty pages is 2000 messages; the caller simply
    /// calls again.
    private static let maxFetchPages = 20

    init(
        engine: CryptoEngine,
        archive: ConversationArchive? = nil,
        directory: RelayKeyDirectory = RelayKeyDirectory(),
        mailbox: RelayMailbox = RelayMailbox(),
        sessions: SessionStore = SessionStore(),
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.engine = engine
        self.archive = archive ?? ConversationArchive(engine: engine)
        self.directory = directory
        self.mailbox = mailbox
        self.sessions = sessions
        self.now = now
    }

    // MARK: - Errors

    enum Failure: Error, Equatable {
        /// No usable session credential. Either signed out, or holding a DEBUG development
        /// credential, whose random bytes are deliberately not a bearer token — a development
        /// build has no relay session and must not appear to have one.
        case notAuthenticated
        /// The relay rejected the token. The caller signs out; retrying cannot help.
        case sessionRejected
        /// This installation has not adopted its own address yet, so it can neither address a
        /// message nor be addressed. Redemption is what supplies it.
        case notRegistered
        /// The Keychain credential and the crypto identity belong to different accounts. Refused
        /// rather than reconciled: adopting a second address would orphan every existing
        /// session, and the failure would look like a network problem a launch later.
        case accountMismatch
        /// No bundle available for that peer — unknown, never published, or pool exhausted. The
        /// relay does not say which (no enumeration), and neither does this.
        case peerUnavailable
        /// Their identity key changed and the user has not accepted it. Sending stays refused
        /// until they do (locked decision §0.2.1).
        case identityNotAccepted
        /// The conversation is blocked locally. Nothing was sent.
        case blocked
        case messageTooLarge
        case rateLimited
        case unreachable
        /// The relay is answering but failing. Kept apart from ``unreachable`` so the UI does not
        /// tell someone to check a connection that is working.
        case relayUnavailable
        /// The relay refused the request itself, not the credential.
        case relayRefused
        /// The sealed container could not be read or written. Nothing was acknowledged.
        case storageUnavailable
    }

    // MARK: - Registration

    /// Binds this installation to the pending credential's ACI and publishes its prekeys, once.
    ///
    /// Idempotent and cheap after the first success: `adoptLocalAddress` is a no-op for the same
    /// address, and the publication flag means the hundred-keypair generation happens once per
    /// installation rather than once per launch. It is also *retried* on every launch until it
    /// succeeds, because an account whose keys never published is an account no peer can start a
    /// session with — and nothing else would ever notice.
    func register() async throws {
        try await operationGate.withExclusiveAccess {
            try await registerExclusively()
        }
    }

    private func registerExclusively() async throws {
        let credential = try registrationCredential()
        do {
            try await engine.adoptLocalAddress(PeerAddress(aci: credential.aci))
        } catch MessagingError.localAddressAlreadySet {
            throw Failure.accountMismatch
        } catch {
            throw Failure.storageUnavailable
        }
        guard await localAci() == credential.aci else { throw Failure.accountMismatch }
        try await publishKeysIfNeeded(token: credential.token)
    }

    /// The launch-time half of registration: this installation already has an address, so all
    /// that can be outstanding is the publication.
    ///
    /// Called on every launch rather than only after redemption, because a publication that
    /// failed the first time leaves an account no peer can start a session with, and the only
    /// symptom is other people's session setup returning 404.
    func resumeRegistration() async throws {
        try await operationGate.withExclusiveAccess {
            try await registerExclusively()
        }
    }

    private func publishKeysIfNeeded(token: String) async throws {
        do {
            if try await archive.flag(ConversationArchive.keysPublishedFlag) { return }
        } catch {
            throw Failure.storageUnavailable
        }

        let keys: PublishedKeys
        do {
            keys = try await engine.generatePublishedKeys()
        } catch {
            throw Failure.storageUnavailable
        }

        do {
            try await directory.publish(keys, token: token)
        } catch let failure as RelayKeyDirectory.Failure {
            throw Self.mapped(failure)
        }

        // Only after the relay has them. A flag set first would make a failed publication
        // permanent — the keys exist locally, nothing would ever try again, and every peer's
        // session setup would fail with a 404 that looks like the peer's problem.
        do {
            try await archive.setFlag(ConversationArchive.keysPublishedFlag, true)
        } catch {
            throw Failure.storageUnavailable
        }
        AppLog.keys.info("prekey publication accepted by the relay")
    }

    /// This installation's own address, if it has adopted one.
    func localAci() async -> UUID? {
        guard let address = try? await engine.localAddress else { return nil }
        return address.serviceId.uuid
    }

    // MARK: - Reading

    func conversations() async throws -> [ConversationArchive.StoredConversation] {
        do {
            return try await archive.conversations()
        } catch {
            throw Failure.storageUnavailable
        }
    }

    func messages(with peer: UUID) async throws -> [ConversationArchive.StoredMessage] {
        do {
            return try await archive.messages(peer)
        } catch {
            throw Failure.storageUnavailable
        }
    }

    // MARK: - Conversation state

    @discardableResult
    func startConversation(with peer: UUID, nickname: String?) async throws
        -> ConversationArchive.StoredConversation {
        do {
            let record = try await archive.ensureConversation(
                peer, nowMs: Self.milliseconds(now()))
            guard let nickname, !nickname.isEmpty else { return record }
            return try await archive.updateConversation(peer) { $0.nickname = nickname } ?? record
        } catch {
            throw Failure.storageUnavailable
        }
    }

    func setPinned(_ pinned: Bool, for peer: UUID) async throws {
        try await mutate(peer) { $0.isPinned = pinned }
    }

    func setMuted(_ muted: Bool, for peer: UUID) async throws {
        try await mutate(peer) { $0.isMuted = muted }
    }

    /// Blocking is local and real: it refuses sends and drops what arrives.
    ///
    /// An incoming message from a blocked peer is still decrypted before it is dropped — the
    /// ratchet has to advance or the session desynchronises and every later message from them
    /// fails even after unblocking. So "blocked" means the plaintext is discarded and the relay
    /// copy acknowledged, not that the ciphertext is left unopened.
    func setBlocked(_ blocked: Bool, for peer: UUID) async throws {
        try await mutate(peer) { $0.isBlocked = blocked }
    }

    func setNickname(_ nickname: String?, for peer: UUID) async throws {
        try await mutate(peer) { $0.nickname = nickname }
    }

    func markRead(_ peer: UUID) async throws {
        try await mutate(peer) { $0.lastReadOrdinal = $0.nextOrdinal }
    }

    /// Marks the conversation unread by one. There is no stored "unread" flag to set: unread is
    /// `nextOrdinal - lastReadOrdinal`, so this steps the read cursor back rather than inventing
    /// a second source of truth that could disagree with the messages that exist.
    func markUnread(_ peer: UUID) async throws {
        try await mutate(peer) {
            $0.lastReadOrdinal = max($0.firstOrdinal, min($0.lastReadOrdinal, $0.nextOrdinal - 1))
        }
    }

    func deleteConversation(_ peer: UUID) async throws {
        do {
            try await archive.removeConversation(peer)
        } catch {
            throw Failure.storageUnavailable
        }
    }

    func clearMessages(in peer: UUID) async throws {
        do {
            try await archive.clearMessages(in: peer)
        } catch {
            throw Failure.storageUnavailable
        }
    }

    func deleteMessage(ordinal: Int, in peer: UUID) async throws {
        do {
            try await archive.removeMessage(ordinal: ordinal, in: peer)
        } catch {
            throw Failure.storageUnavailable
        }
    }

    private func mutate(
        _ peer: UUID, _ change: @escaping @Sendable (inout ConversationArchive.StoredConversation) -> Void
    ) async throws {
        do {
            try await archive.updateConversation(peer, change)
        } catch {
            throw Failure.storageUnavailable
        }
    }

    // MARK: - Sending

    /// Encrypts `text` for `peer`, stores it, and hands the envelope to the relay.
    ///
    /// - Returns: the stored message, whose state says what actually happened.
    @discardableResult
    func send(text: String, to peer: UUID) async throws -> ConversationArchive.StoredMessage {
        try await operationGate.withExclusiveAccess {
            try await sendExclusively(text: text, to: peer)
        }
    }

    private func sendExclusively(text: String, to peer: UUID) async throws
        -> ConversationArchive.StoredMessage {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw Failure.relayRefused }

        let credential = try activeCredential()
        let token = credential.token
        guard await localAci() == credential.aci else { throw Failure.accountMismatch }

        let conversation = try await startConversation(with: peer, nickname: nil)
        guard !conversation.isBlocked else { throw Failure.blocked }

        let payload: Data
        do {
            payload = try MessagePayload(content: .text(trimmed)).encode()
        } catch MessagePayloadError.tooLarge {
            throw Failure.messageTooLarge
        } catch {
            throw Failure.relayRefused
        }

        // Durable first. See the type comment: everything after this point can fail, and a
        // message the user typed must not disappear because the network did.
        var stored: ConversationArchive.StoredMessage
        do {
            stored = try await archive.append(
                to: peer, direction: .outgoing, text: trimmed,
                timestampMs: Self.milliseconds(now()), state: .sending)
        } catch {
            throw Failure.storageUnavailable
        }

        do {
            try await establishSessionIfNeeded(with: peer, token: token)
            let envelope = try await engine.encrypt(payload, to: PeerAddress(aci: peer))
            try await mailbox.send(envelope: envelope, to: peer, token: token)
        } catch {
            stored.state = .failed
            // A failure to record the failure is not worth masking the original one with.
            try? await archive.updateMessage(stored, in: peer)
            throw Self.mapped(error)
        }

        stored.state = .sent
        do {
            try await archive.updateMessage(stored, in: peer)
        } catch {
            // The relay has it; only the local status is stale, and it corrects on the next
            // send. Reporting this as a send failure would be a lie in the other direction.
            AppLog.store.error("could not record a send as delivered to the relay")
        }
        return stored
    }

    /// Ensures a session exists, fetching the peer's bundle if not.
    ///
    /// The fetch is the expensive, rate-limited, pool-consuming operation (AUDIT 3.1), so it
    /// happens only when there is genuinely no session — never as a "refresh".
    private func establishSessionIfNeeded(with peer: UUID, token: String) async throws {
        let address = PeerAddress(aci: peer)
        if try await engine.hasSession(with: address) { return }

        let bundle: PeerKeyBundle
        do {
            bundle = try await directory.bundle(for: peer, token: token)
        } catch let failure as RelayKeyDirectory.Failure {
            throw Self.mapped(failure)
        }
        try await engine.startSession(with: address, bundle: bundle)
    }

    // MARK: - Receiving

    /// Collects everything waiting, stores it, and acknowledges what was stored.
    ///
    /// - Returns: how many messages were stored. Messages that were dropped — undecryptable,
    ///   unrecognised payload, or from a blocked peer — are acknowledged but not counted.
    @discardableResult
    func receive() async throws -> Int {
        try await operationGate.withExclusiveAccess {
            try await receiveExclusively()
        }
    }

    private func receiveExclusively() async throws -> Int {
        let credential = try activeCredential()
        let token = credential.token
        guard await localAci() == credential.aci else { throw Failure.accountMismatch }

        var storedCount = 0

        for _ in 0..<Self.maxFetchPages {
            let batch: RelayMailbox.Batch
            do {
                batch = try await mailbox.fetch(token: token)
            } catch let failure as RelayMailbox.Failure {
                throw Self.mapped(failure)
            }
            if batch.messages.isEmpty { return storedCount }

            var acknowledge: [UUID] = []
            var storageFailed = false

            for pending in batch.messages {
                let outcome = await store(pending)
                switch outcome {
                case .stored:
                    storedCount += 1
                    acknowledge.append(pending.id)
                case .dropped:
                    acknowledge.append(pending.id)
                case .storageFailed:
                    // Stop taking messages, but still acknowledge the ones already durable —
                    // abandoning those would have the relay serve them again, and they can no
                    // longer be decrypted.
                    storageFailed = true
                }
                if storageFailed { break }
            }

            try await acknowledgeAll(acknowledge, token: token)

            if storageFailed { throw Failure.storageUnavailable }
            if !batch.more { return storedCount }
        }

        return storedCount
    }

    private enum StoreOutcome {
        case stored
        case dropped
        case storageFailed
    }

    /// Decrypts one envelope and files it. Never throws: the caller needs the three-way
    /// outcome, and collapsing "cannot decrypt" into an error would lose the distinction that
    /// decides whether the relay's copy is acknowledged.
    private func store(_ pending: RelayMailbox.Pending) async -> StoreOutcome {
        do {
            // The receive time, not the relay-controlled envelope timestamp. Decryption and
            // archive persistence share one SQLite commit inside this call.
            switch try await archive.storeIncoming(
                envelope: pending.envelope, timestampMs: Self.milliseconds(now()))
            {
            case .stored:
                return .stored
            case .unsupportedPayload:
                AppLog.session.error("a decrypted payload was not one this build understands")
                return .dropped
            case .blocked:
                return .dropped
            case .quotaExceeded:
                // Acknowledged deliberately. The ratchet advanced and committed, so this
                // envelope can never decrypt again; leaving it unacknowledged would have the
                // relay serve it every cycle and stop every message behind it (AUDIT 4.14).
                AppLog.store.error(
                    "the conversation limit is reached; a message from a new peer was dropped")
                return .dropped
            case .undecryptable:
                // Deliberately unqualified. Revealing replay versus corruption would let a
                // hostile relay probe which messages this device has already seen.
                AppLog.session.error("an envelope could not be decrypted; dropping it")
                return .dropped
            }
        } catch {
            AppLog.store.error("the receive transaction failed; not acknowledging")
            return .storageFailed
        }
    }

    /// Acknowledges in chunks the relay will accept, and treats a failure as fatal for the
    /// cycle: an unacknowledged message is ciphertext left on a box that is assumed seizable.
    private func acknowledgeAll(_ ids: [UUID], token: String) async throws {
        guard !ids.isEmpty else { return }
        var remaining = ids[...]
        while !remaining.isEmpty {
            let chunk = remaining.prefix(RelayMailbox.maxAcknowledgeBatch)
            do {
                try await mailbox.acknowledge(ids: Array(chunk), token: token)
            } catch let failure as RelayMailbox.Failure {
                throw Self.mapped(failure)
            }
            remaining = remaining.dropFirst(chunk.count)
        }
    }

    // MARK: - Credentials

    /// The bearer token, read from the Keychain on every call.
    ///
    /// Not cached. A cached token would outlive a sign-out for the lifetime of this actor, and
    /// "the app forgot it was signed out" is the failure mode the whole credential design exists
    /// to prevent (AUDIT 5.2).
    private func activeCredential() throws -> (token: String, aci: UUID) {
        guard let credential = sessions.current(),
              credential.phase == .active,
              !credential.isExpired(at: now()),
              let token = credential.bearerToken else { throw Failure.notAuthenticated }
        return (token, credential.aci)
    }

    private func registrationCredential() throws -> (token: String, aci: UUID) {
        guard let credential = sessions.current(),
              credential.phase == .registering,
              !credential.isExpired(at: now()),
              let token = credential.bearerToken else { throw Failure.notAuthenticated }
        return (token, credential.aci)
    }

    private static func milliseconds(_ date: Date) -> UInt64 {
        UInt64(max(0, date.timeIntervalSince1970) * 1000)
    }

    // MARK: - Error mapping

    private static func mapped(_ error: Error) -> Failure {
        if let failure = error as? Failure { return failure }

        if let failure = error as? RelayKeyDirectory.Failure {
            switch failure {
            case .unauthenticated: return .sessionRejected
            case .unavailable: return .peerUnavailable
            case .rateLimited: return .rateLimited
            case .unreachable: return .unreachable
            case .serverUnavailable: return .relayUnavailable
            case .malformedResponse: return .relayRefused
            }
        }

        if let failure = error as? RelayMailbox.Failure {
            switch failure {
            case .unauthenticated: return .sessionRejected
            case .rateLimited: return .rateLimited
            case .unreachable: return .unreachable
            case .serverUnavailable: return .relayUnavailable
            case .malformedResponse, .rejected: return .relayRefused
            }
        }

        if let failure = error as? MessagingError {
            switch failure {
            case .identityNotAccepted: return .identityNotAccepted
            case .storeUnavailable: return .storageUnavailable
            case .messageTooLarge: return .messageTooLarge
            case .localAddressNotSet: return .notRegistered
            case .malformedKeyBundle, .sessionSetupFailed: return .peerUnavailable
            default: return .relayRefused
            }
        }

        if error is ArchiveError { return .storageUnavailable }

        // Anything left is a libsignal error or a store failure this module does not name. It
        // is reported as a refusal rather than guessed at — and never as success.
        return .relayRefused
    }
}

/// Log handles for the app side of the messaging path.
///
/// Named `AppLog` rather than reusing `CipherLog`, which is internal to the crypto module and redacts
/// everything libsignal emits. The rule is the same one `THREAT_MODEL.md` §4.6 states: no
/// plaintext, no addresses, no tokens — every line here says *what* happened and never *to
/// whom*, because a log survives every deletion the retention policy performs.
nonisolated enum AppLog {
    static let store = Logger(subsystem: "cz.janrichtermoc.Cipher", category: "store")
    static let session = Logger(subsystem: "cz.janrichtermoc.Cipher", category: "session")
    static let keys = Logger(subsystem: "cz.janrichtermoc.Cipher", category: "keys")
}
