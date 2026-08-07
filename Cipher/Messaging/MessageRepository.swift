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

    /// How many operations are queued behind the one currently running.
    ///
    /// `nonisolated` so a reader does not have to enter this actor — which a test observing a
    /// *blocked* operation cannot rely on being able to do promptly. See
    /// ``SerialGate/queuedWaiterCount`` for why it exists: the serialisation tests asserted
    /// "the second call has not reached the relay" after a fixed sleep, which on a slow machine
    /// is also true when the second call has not started yet, so the assertion held without
    /// exercising the path it names.
    nonisolated var queuedOperationWaiters: Int { operationGate.queuedWaiterCount }

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
    /// Idempotent and cheap after the first success: `adoptAddress` is a no-op for the same
    /// address, and the publication flag means the hundred-keypair generation happens once per
    /// installation rather than once per launch. `maintainKeys` retries it on every foreground
    /// for as long as it has not succeeded, because an account whose keys never published is an
    /// account no peer can start a session with — and nothing else would ever notice.
    func register() async throws {
        try await operationGate.withExclusiveAccess {
            let credential = try registrationCredential()
            try await adoptAddress(credential.aci)
            try await publishKeysIfNeeded(token: credential.token)
        }
    }

    /// Binds this installation to `aci`, and refuses if it is already bound to another.
    ///
    /// Refused rather than reconciled: adopting a second address orphans every existing session,
    /// and the failure would surface a launch later as peers reporting a changed safety number.
    private func adoptAddress(_ aci: UUID) async throws {
        do {
            try await engine.adoptLocalAddress(PeerAddress(aci: aci))
        } catch MessagingError.localAddressAlreadySet {
            throw Failure.accountMismatch
        } catch {
            throw Failure.storageUnavailable
        }
        guard await localAci() == aci else { throw Failure.accountMismatch }
    }

    /// The launch-time half of registration and the prekey scheduler, in one entry point.
    ///
    /// Called when the app reaches the main UI and on every return to the foreground. It does
    /// three things, in order, each a no-op when it is not needed:
    ///
    /// 1. Re-adopts this installation's address — idempotent, and the precondition for the rest.
    /// 2. Retries a publication that never succeeded. An account whose keys never reached the
    ///    relay is one no peer can start a session with, and the only symptom is *other people*
    ///    seeing 404s, so nothing on this device would ever notice.
    /// 3. Rotates and replenishes when either is due (AUDIT 2.4).
    ///
    /// **This is the launch hook that AUDIT 5.36 records as missing.** `resumeRegistration`
    /// claimed in its own documentation to run on every launch and had no caller outside the
    /// tests, so step 2 has never happened in a shipped build — and it could not have, because
    /// it asked for a `.registering` credential, which an onboarded account no longer holds.
    /// Rotation needs the same hook, so the two are one method rather than two things a future
    /// caller could wire up half of.
    ///
    /// Failures propagate. The caller decides whether they are worth showing: a rotation that
    /// could not reach the relay is retried on the next foreground and is not something a user
    /// can act on.
    func maintainKeys() async throws {
        try await operationGate.withExclusiveAccess {
            let credential = try maintenanceCredential()
            try await adoptAddress(credential.aci)
            try await publishKeysIfNeeded(token: credential.token)
            try await rotateKeysIfDue(token: credential.token)
        }
    }

    // MARK: - Prekey rotation and replenishment (P6.S01, AUDIT 2.4)

    /// How long a signed prekey and last-resort Kyber key stay live.
    ///
    /// Rotation is what bounds the damage of a compromised prekey: a private half that leaks is
    /// useful for establishing sessions only until the relay stops serving its public half.
    /// Two days is Signal's own cadence and sits far inside the relay's six-publications-a-day
    /// limit, leaving room for threshold replenishment on the same budget.
    static let preKeyRotationInterval: TimeInterval = 48 * 60 * 60

    /// Below this, the pool is topped up without waiting for the rotation to fall due.
    ///
    /// A quarter of the target, so an ordinary week of session setup never reaches it and a
    /// drain does. Set too high, every launch republishes and spends the daily budget on
    /// nothing; too low, the pool empties between checks and peers cannot start a session at
    /// all — which is the residual AUDIT 3.1 describes and P6.S02 closes.
    static let replenishThreshold = 25

    /// The floor between two publications, whatever else is due.
    ///
    /// The threshold path reads a count the relay reported when it accepted the *last* upload,
    /// so a pool that is genuinely drained stays reported as drained until the next publication
    /// changes it. Without a floor, an attacker draining the pool would get one publication per
    /// foreground — six in as many minutes, the whole daily allowance spent before lunch, and
    /// then a full day in which a *rotation* could not publish either. An hour spreads the same
    /// six attempts across the day the limit is measured over, which is the better failure: a
    /// drained pool blocks session setup with this account and nothing else.
    static let minimumPublishInterval: TimeInterval = 60 * 60

    /// Publishes a fresh signed prekey, last-resort Kyber key and pool top-up when either the
    /// rotation interval has elapsed or a pool has fallen below the threshold.
    ///
    /// ## Which count decides
    ///
    /// Both, and the **lower** of them. They measure different things and neither is sufficient:
    ///
    /// - The relay's count, reported when it accepted the last publication, is the pool an
    ///   attacker drains — every bundle fetch consumes a key there. It is stale the moment it
    ///   arrives and can only have gone down since, so it is a ceiling.
    /// - The local count falls only when a peer actually *sends*, so it misses a drain entirely.
    ///   It is the half a hostile relay cannot lie about.
    ///
    /// Taking the minimum means a relay understating the pool costs an extra publication, and a
    /// relay overstating it is caught by the local count once the keys are genuinely used.
    ///
    /// ## Why an empty pool is still bounded by the interval
    ///
    /// A pool drained to zero between two checks is not observable here: nothing tells this
    /// device that a bundle was dispensed. The rotation interval is therefore also the ceiling
    /// on how long that lasts, which is why rotation runs on a schedule rather than only on a
    /// threshold. `BACKEND.md` §5 states the residual; it closes with AUDIT 3.1 in P6.S02.
    private func rotateKeysIfDue(token: String) async throws {
        let published: ConversationArchive.StoredKeyPublication?
        let localRemaining: Int
        do {
            published = try await archive.keyPublication()
            localRemaining = try await engine.preKeyState.remainingOneTimePreKeys
        } catch {
            throw Failure.storageUnavailable
        }

        // No record means the publication that would have written one has not been accepted
        // yet, and `publishKeysIfNeeded` above owns that retry. Rotating on top of it would
        // spend a second daily token to replace keys that were just minted.
        guard let published else { return }

        let effectivePool = min(published.relayOneTimePreKeys, localRemaining)
        let elapsed = now().timeIntervalSince1970
            - Double(published.publishedAtMs) / 1000
        let rotationDue = elapsed >= Self.preKeyRotationInterval
        let poolLow = effectivePool < Self.replenishThreshold
            || published.relayKyberPreKeys < Self.replenishThreshold

        guard rotationDue || (poolLow && elapsed >= Self.minimumPublishInterval) else { return }

        // Only the shortfall, never a full pool every time. The relay adds one-time keys rather
        // than replacing them (`BACKEND.md` §2.4), so republishing the full target on every
        // rotation would grow both pools without bound — and the private halves grow with them,
        // on the device. Computed from the ceiling above, so it can over-mint by whatever was
        // consumed since the last publication and never under-mint into a pool that is fuller
        // than it appears. Zero is a legal publication: a rotation that falls due against a full
        // pool replaces the two long-lived keys and adds nothing.
        let target = await CryptoEngine.defaultOneTimePreKeyCount
        let topUp = max(0, min(target - effectivePool, target))

        AppLog.keys.info("rotating this installation's published prekeys")
        try await publishKeys(token: token, oneTimeCount: topUp)
    }

    private func publishKeysIfNeeded(token: String) async throws {
        do {
            if try await archive.flag(ConversationArchive.keysPublishedFlag) { return }
        } catch {
            throw Failure.storageUnavailable
        }

        try await publishKeys(
            token: token, oneTimeCount: await CryptoEngine.defaultOneTimePreKeyCount)

        // Only after the relay has them. A flag set first would make a failed publication
        // permanent — the keys exist locally, nothing would ever try again, and every peer's
        // session setup would fail with a 404 that looks like the peer's problem.
        do {
            try await archive.setFlag(ConversationArchive.keysPublishedFlag, true)
        } catch {
            throw Failure.storageUnavailable
        }
    }

    /// Mints, publishes, and records the result. The one path that talks to the directory, so
    /// the first publication and every rotation cannot diverge in what they persist.
    ///
    /// The order is the same one `generatePublishedKeys` documents and for the same reason: the
    /// private halves are on disk before the public halves are handed to the relay, and the
    /// record of *when* is written only after the relay has accepted them. A record written
    /// first would make a failed publication look like a completed rotation, and nothing would
    /// try again until the interval elapsed.
    private func publishKeys(token: String, oneTimeCount: Int) async throws {
        let keys: PublishedKeys
        do {
            keys = try await engine.generatePublishedKeys(oneTimeCount: oneTimeCount)
        } catch {
            throw Failure.storageUnavailable
        }

        let counts: RelayKeyDirectory.PoolCounts
        do {
            counts = try await directory.publish(keys, token: token)
        } catch let failure as RelayKeyDirectory.Failure {
            throw Self.mapped(failure)
        }

        do {
            try await archive.setKeyPublication(
                ConversationArchive.StoredKeyPublication(
                    publishedAtMs: Self.milliseconds(now()),
                    relayOneTimePreKeys: counts.oneTimePreKeys,
                    relayKyberPreKeys: counts.kyberPreKeys))
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

    // MARK: - Identity and safety numbers (P5.S12)

    /// A peer's trust state, or `nil` if this device has never seen a key for them.
    ///
    /// `nil` is not "untrusted" — it is "no session yet". The distinction matters at the call
    /// site: a conversation with no key cannot show a safety number, and must not show an
    /// unverified badge either, because there is nothing to have verified.
    func peerIdentity(with peer: UUID) async -> PeerIdentityState? {
        try? await engine.peerIdentityState(for: PeerAddress(aci: peer))
    }

    /// The digits both sides compare, or `nil` when there is no key for this peer yet.
    ///
    /// Computed on demand rather than cached with the conversation. It is a pure function of
    /// two identity keys and two addresses, so a cache would buy nothing and could serve a
    /// number derived from a key that has since changed — which is precisely the case the
    /// screen exists to reveal.
    func safetyNumber(with peer: UUID) async -> String? {
        guard let identity = await peerIdentity(with: peer) else { return nil }
        guard let localAci = await localAci() else { return nil }
        return try? await engine.safetyNumber(
            peerIdentityKey: identity.identityKey, localAci: localAci, peerAci: peer)
    }

    /// Records the user's out-of-band comparison, naming the key it applies to.
    ///
    /// The key is passed through from the state the screen was drawn from rather than re-read
    /// here. That is the whole guarantee: if it changed while the screen was open, the engine
    /// refuses and the caller re-presents, so a verification can never land on a key nobody saw.
    @discardableResult
    func setVerified(_ verified: Bool, peer: UUID, identityKey: Data) async -> Bool {
        return (try? await engine.setPeerVerified(
            verified, identityKey: identityKey, for: PeerAddress(aci: peer))) ?? false
    }

    /// Accepts a changed key, unblocking the send direction (locked decision §0.2.1).
    ///
    /// Separate from `setVerified` because they are separate claims, and a screen that offered
    /// one button for both would make the badge mean "a warning was dismissed".
    @discardableResult
    func acceptIdentity(peer: UUID, identityKey: Data) async -> Bool {
        return (try? await engine.acceptPeerIdentity(
            identityKey, for: PeerAddress(aci: peer))) ?? false
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

    /// A credential good enough to publish this installation's **own** keys.
    ///
    /// Deliberately wider than either accessor above, because key maintenance is the one
    /// operation that has to keep working across the whole life of an account: the publication
    /// that failed during onboarding is retried while the credential is still `.registering`,
    /// and a rotation two years later runs against an `.active` one. Requiring one phase is
    /// what made the launch retry dead code rather than merely uncalled (AUDIT 5.36).
    ///
    /// `.destroying` is excluded. An account being erased must not put fresh keys into a
    /// directory it is about to disappear from — they would outlive the account by whatever the
    /// erase left unfinished, and peers would keep fetching bundles for it.
    private func maintenanceCredential() throws -> (token: String, aci: UUID) {
        guard let credential = sessions.current(),
              credential.phase != .destroying,
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
