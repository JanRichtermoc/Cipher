//
//  ConversationStore.swift
//  Cipher
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import CipherCrypto
import Foundation
import os
import SwiftUI

/// What the screens read. The production replacement for `MockStore`.
///
/// `MockStore` was an array of plaintext fixtures with hardcoded names, hardcoded verification
/// flags, and a `sendText` that appended a struct — AUDIT 5.3. Every view in the app read it, so
/// "the UI is not wired to the crypto" was not a missing feature but the entire architecture.
/// This type presents the same shapes (`Chat`, `Message`, `Contact`) so the views did not have
/// to be rewritten, and derives every one of them from the sealed archive and the relay.
///
/// ## What it deliberately cannot show
///
/// - **A display name it was not given** — see below. Verification *is* now real (P5.S12):
///   `isVerified` is true only where the user compared a safety number out of band and the
///   key has not changed since, which is why it is read from the record store on every
///   refresh rather than held here.
/// - **A display name it was not given.** There is no directory and no server-side profile
///   (`BACKEND.md` §2.1, `THREAT_MODEL.md` §3.4), so a peer is shown by a short form of their
///   Cipher ID until the user names them locally. A name the app made up would be worse.
/// - **Online state, typing state, delivery or read receipts.** None of them exist on the wire.
///   `Contact.isOnline` is always false rather than randomised for effect.
///
/// ## Failures are surfaced, never swallowed
///
/// Every operation records `failure` on the way out. A messenger that silently drops a send is
/// indistinguishable from one that delivered it, and the user acts on that difference.
@MainActor
@Observable
final class ConversationStore {

    // MARK: - Observable state

    private(set) var chats: [Chat] = []
    /// One per conversation. There is no contact list independent of conversations, because
    /// there is nowhere to get one from.
    private(set) var contacts: [Contact] = []
    private(set) var blockedContactIDs: Set<UUID> = []
    /// This installation's own ACI, once it has adopted one.
    private(set) var localAci: UUID?
    /// The last operation's failure, or nil. Cleared by the next successful operation.
    private(set) var failure: MessageRepository.Failure?
    /// True while a fetch or send is in flight, so the UI can say so rather than look frozen.
    private(set) var isSyncing = false
    /// Set when opening the engine refused because sealed records survive with no key to open
    /// them (AUDIT 5.34). It is the sole authorisation for `discardOrphanedLocalState`.
    private(set) var localStateIsOrphaned = false

    private var messagesByChat: [UUID: [Message]] = [:]

    var currentUserID: UUID { localAci ?? Self.unregisteredPlaceholder }

    /// Stands in for "this device has no address yet", so `Chat.participantIDs` is never empty
    /// and the views have something to compare against. Never sent anywhere.
    private static let unregisteredPlaceholder = UUID(
        uuidString: "00000000-0000-0000-0000-000000000000")!

    // MARK: - Dependencies

    /// Memoised as a `Task` rather than a stored value: opening the engine is async and
    /// throwing, and two screens asking at once must get the same engine. Two `CryptoEngine`
    /// instances over one container would each hold their own record store — same key, same
    /// files, no coordination — which is the shape of a lost write.
    private var engineTask: Task<CryptoEngine, Error>?
    private var repositoryTask: Task<MessageRepository, Error>?
    private let openEngine: @Sendable () async throws -> CryptoEngine
    private let destroyPersistedState: @Sendable () async throws -> Void

    /// DEBUG previews build a store with fixtures and no engine at all. In a Release build this
    /// is always false, and there is no code path that populates state without the archive.
    private let isPreviewOnly: Bool

    init(
        openEngine: @escaping @Sendable () async throws -> CryptoEngine = {
            try CryptoEngine.open()
        },
        destroyPersistedState: @escaping @Sendable () async throws -> Void = {
            try CryptoEngine.destroyPersistedState()
        }
    ) {
        isPreviewOnly = false
        self.openEngine = openEngine
        self.destroyPersistedState = destroyPersistedState
    }

    #if DEBUG
    /// Preview / test construction: state is set directly and nothing touches the Keychain, the
    /// container, or the network.
    init(previewChats: [Chat], previewMessages: [UUID: [Message]], previewContacts: [Contact]) {
        isPreviewOnly = true
        openEngine = { throw MessageRepository.Failure.storageUnavailable }
        destroyPersistedState = {}
        chats = previewChats
        messagesByChat = previewMessages
        contacts = previewContacts
        localAci = UUID(uuidString: "00000000-0000-0000-0000-0000000000aa")!
    }
    #endif

    /// Opens the engine, once, and hands the same one to every caller.
    ///
    /// A **failed** open is not memoised. Caching the failure would poison the store for the
    /// lifetime of the process: opening touches the Keychain and the container, so a first attempt
    /// before the device has been unlocked can fail transiently, and the app would then be
    /// permanently unable to message with nothing but a stale error to show for it.
    func engine() async throws -> CryptoEngine {
        if let engineTask { return try await engineTask.value }
        let task = Task { try await openEngine() }
        engineTask = task
        do {
            let opened = try await task.value
            localStateIsOrphaned = false
            return opened
        } catch {
            engineTask = nil
            // Latched from an *observed* refusal rather than probed for. The erase below is
            // irreversible, and the only evidence that it is the right thing to do is that
            // opening actually refused for this reason.
            localStateIsOrphaned = (error as? CryptoEngineError) == .orphanedLocalState
            throw error
        }
    }

    /// Erases sealed local state that no key can open, once the user has asked for it.
    ///
    /// AUDIT 5.34. Before this the condition was a dead end: every retry re-threw, and the only
    /// repair was deleting the app container from outside the app, which no user can do.
    ///
    /// **Why this is guarded rather than always available.** It reaches
    /// `CryptoEngine.destroyPersistedState`, which removes every Keychain secret and unlinks the
    /// container without opening anything. Against a *live* account that is a silent, total,
    /// irreversible loss. `destroyAccountState` may call the same primitive because a persisted
    /// `.destroying` gate has already authorised it; onboarding has no such gate, so the
    /// authorisation here is the latched refusal itself. A caller that has not seen
    /// `orphanedLocalState` is refused — which is the property the negative test pins.
    ///
    /// Consent is the caller's to obtain. This performs the erase; it does not ask.
    func discardOrphanedLocalState() async throws {
        guard !isPreviewOnly else { return }
        guard localStateIsOrphaned else {
            // Never widen this into "try it and see". A store that has not refused to open may
            // hold a working account, and this would take it without asking.
            AppLog.store.error("refused to discard local state that was never observed orphaned")
            throw MessageRepository.Failure.storageUnavailable
        }

        do {
            try await destroyPersistedState()
        } catch {
            AppLog.store.error("discarding orphaned local state failed")
            record(.storageUnavailable)
            throw MessageRepository.Failure.storageUnavailable
        }

        AppLog.store.info("orphaned local state discarded at the user's request")
        dropAccountModels()
        // Both handles were built over state that no longer exists. Clearing them is what lets
        // the next attempt open a genuinely fresh installation instead of re-throwing.
        engineTask = nil
        repositoryTask = nil
        localStateIsOrphaned = false
        failure = nil
    }

    private func repository() async throws -> MessageRepository {
        if let repositoryTask { return try await repositoryTask.value }
        let task = Task { [self] in MessageRepository(engine: try await engine()) }
        repositoryTask = task
        do {
            return try await task.value
        } catch {
            repositoryTask = nil
            throw error
        }
    }

    // MARK: - Lifecycle

    /// Called when the app reaches the main UI, and on every return to the foreground.
    ///
    /// Registration has its own root gate. Once main is reachable, load what is
    /// on disk before collecting what is waiting on the relay.
    func start() async {
        guard !isPreviewOnly else { return }

        // Before anything is loaded or drawn. A message whose timer ran out while the app was
        // not running must not be on screen for the instant it takes the sweep to reach it, and
        // this is the only ordering that guarantees that (P6.S03).
        await sweepExpiredMessages()
        // Once per launch, and this is the run that matters most: it finishes an unlink a
        // previous process was killed during, and it catches blobs orphaned by paths that
        // remove message rows in bulk without being able to name them — retention trimming and
        // quota eviction (P6.S04).
        await wipeOrphanedAttachments()
        await refresh()
        await maintainKeys()
        await receive()
    }

    /// Deletes messages whose timers have run out, then reloads if anything went.
    ///
    /// Failures are logged rather than surfaced: the sweep runs on every foreground, so a
    /// transient storage error corrects itself, and a banner over the conversation list would
    /// report a background task the user cannot influence. A *persistent* failure is visible in
    /// the only way that matters — the messages are still there.
    private func sweepExpiredMessages() async {
        guard !isPreviewOnly else { return }
        do {
            let deleted = try await repository().sweepExpiredMessages()
            if deleted > 0 { await refresh() }
        } catch {
            AppLog.store.error("expired-message sweep did not complete; it will be retried")
        }
    }

    /// Unlinks cached attachment ciphertext no message points at any more (P6.S04).
    ///
    /// Logged rather than surfaced, for the same reason the expiry sweep is: the keys are
    /// already gone with the rows that held them, so what remains is unopenable ciphertext and
    /// a retry on the next launch costs nothing. A banner would report a background task the
    /// user cannot influence.
    private func wipeOrphanedAttachments() async {
        guard !isPreviewOnly else { return }
        do {
            _ = try await repository().wipeOrphanedAttachments()
        } catch {
            AppLog.store.error("orphaned attachments were not unlinked; they will be retried")
        }
    }

    /// Retries an unfinished publication and rotates this installation's prekeys when either is
    /// due (P6.S01, AUDIT 2.4 and 5.36).
    ///
    /// **Before `receive`, and deliberately.** A device returning after a long absence has both
    /// a rotation outstanding and a queue waiting; draining the queue first can take twenty
    /// pages, and the operation gate holds the rotation behind all of it. Publishing first costs
    /// one request and is what lets peers start a session at all.
    ///
    /// **Failures are logged, not surfaced.** Nothing here is a user action: a rotation that
    /// could not reach the relay is retried on the next foreground, and the initial publication
    /// already reports its own failure at onboarding, where there is someone to tell. Recording
    /// it as `failure` would put a banner over the conversation list for a background task the
    /// user cannot influence.
    private func maintainKeys() async {
        do {
            try await repository().maintainKeys()
        } catch MessageRepository.Failure.notAuthenticated,
                MessageRepository.Failure.notRegistered {
            // Signed out, or onboarding has not finished. Neither is a fault.
        } catch {
            AppLog.keys.error("prekey maintenance did not complete; it will be retried")
        }
    }

    /// Reloads conversations and messages from the sealed archive. No network.
    func refresh() async {
        guard !isPreviewOnly else { return }

        do {
            let repository = try await repository()
            let aci = await repository.localAci()
            let stored = try await repository.conversations()

            var loaded: [UUID: [Message]] = [:]
            var ordinalsByMessage: [UUID: Int] = [:]
            for conversation in stored {
                let archived = try await repository.messages(with: conversation.peer)
                for message in archived { ordinalsByMessage[message.id] = message.ordinal }
                loaded[conversation.peer] = archived.map {
                    Self.viewMessage($0, peer: conversation.peer, localAci: aci)
                }
            }

            // Verification is read here rather than inside `apply`, which is synchronous.
            // One local read per conversation, no network: the state lives in the sealed
            // record store beside the identity key it describes.
            var verified: Set<UUID> = []
            for conversation in stored
            where await repository.peerIdentity(with: conversation.peer)?.isVerified == true {
                verified.insert(conversation.peer)
            }

            localAci = aci
            messagesByChat = loaded
            ordinals = ordinalsByMessage
            verifiedPeers = verified
            apply(stored)
            failure = nil
        } catch {
            record(error)
        }
    }

    /// Collects and stores everything waiting on the relay, then reloads.
    func receive() async {
        guard !isPreviewOnly else { return }
        isSyncing = true
        defer { isSyncing = false }

        do {
            let stored = try await repository().receive()
            failure = nil
            // Swept here as well as at launch. Not because an inbound message can arrive
            // overdue — it cannot, since its timer starts when this device files it — but
            // because a fetch can take a long time on a device that has been away, and other
            // conversations' messages fall due while it runs. One refresh covers both, so a
            // sweep that deletes nothing costs a query and no redraw.
            let deleted = (try? await repository().sweepExpiredMessages()) ?? 0
            if stored > 0 || deleted > 0 { await refresh() }
        } catch {
            record(error)
        }
    }

    /// Adopts the address the relay assigned at redemption and publishes this device's keys.
    func register() async throws {
        guard !isPreviewOnly else { return }
        do {
            let repository = try await repository()
            try await repository.register()
            localAci = await repository.localAci()
            failure = nil
        } catch {
            record(error)
            throw error
        }
    }

    /// Cryptographically erases every account-bound value, then discards every
    /// in-memory handle and view model that could still expose the old account.
    /// The session gate is cleared separately and only after this succeeds.
    func destroyAccountState() async throws {
        guard !isPreviewOnly else { return }

        // The persisted session gate already hides the old account. Drop plaintext view models
        // before touching storage as well, so a Keychain or filesystem failure cannot leave the
        // previous account resident in UI-owned memory while cleanup waits for a retry.
        dropAccountModels()
        repositoryTask = nil

        let engine: CryptoEngine
        do {
            engine = try await self.engine()
        } catch {
            // The expected crash-recovery case is ciphertext beside an already deleted record
            // key. Opening must refuse that state and, critically, must not mint a replacement
            // key. The persisted `.destroying` gate authorises direct key-first cleanup here.
            do {
                try await destroyPersistedState()
                engineTask = nil
                // The authorisation is spent with the state it authorised removing. Leaving it
                // latched would carry a stale "yes" past the erase it belonged to.
                localStateIsOrphaned = false
                failure = nil
                return
            } catch {
                record(.storageUnavailable)
                throw MessageRepository.Failure.storageUnavailable
            }
        }

        do {
            try await engine.destroyAllState()
        } catch {
            // Keep the erasing engine task so the next tap retries physical cleanup without
            // reopening or regaining access to its in-memory keys.
            record(.storageUnavailable)
            throw MessageRepository.Failure.storageUnavailable
        }

        engineTask = nil
        failure = nil
    }

    private func dropAccountModels() {
        chats = []
        contacts = []
        blockedContactIDs = []
        localAci = nil
        isSyncing = false
        messagesByChat = [:]
        ordinals = [:]
    }

    // MARK: - Reading

    func chat(id: UUID) -> Chat? {
        chats.first { $0.id == id }
    }

    func messages(for chatID: UUID) -> [Message] {
        messagesByChat[chatID] ?? []
    }

    func contact(id: UUID) -> Contact? {
        contacts.first { $0.id == id }
    }

    func otherParticipant(in chat: Chat) -> Contact? {
        contact(id: chat.id)
    }

    func searchMessages(query: String) -> [SearchHit] {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !needle.isEmpty else { return [] }

        var hits: [SearchHit] = []
        for chat in chats {
            for message in messages(for: chat.id) {
                // Only kinds this build can actually produce are searchable. The others exist
                // in `MessageKind` for the attachment work whose client half is not written yet;
                // nothing in the production path creates one, so there is nothing to index.
                let text: String
                switch message.kind {
                case .text(let value), .emoji(let value), .system(let value): text = value
                default: continue
                }
                guard text.lowercased().contains(needle) else { continue }
                hits.append(
                    SearchHit(
                        id: message.id, chatID: chat.id, chatTitle: chat.title,
                        snippet: text, date: message.date))
            }
        }
        return hits.sorted { $0.date > $1.date }
    }

    // MARK: - Writing

    /// Starts (or reveals) a conversation with a peer named by their Cipher ID.
    ///
    /// The ID is typed in or shared out of band. There is deliberately no lookup: server-side
    /// contact discovery is a standing prohibition (`THREAT_MODEL.md` §4.3), and it is the single
    /// largest metadata leak in messengers that have it.
    @discardableResult
    func startConversation(with aci: UUID, nickname: String?) async -> Chat? {
        guard !isPreviewOnly else { return chat(id: aci) }
        guard aci != localAci else {
            // A conversation with yourself would establish a session with your own address,
            // which libsignal has no meaning for.
            record(.relayRefused)
            return nil
        }

        do {
            _ = try await repository().startConversation(with: aci, nickname: nickname)
            failure = nil
            await refresh()
            return chat(id: aci)
        } catch {
            record(error)
            return nil
        }
    }

    func send(_ text: String, to chatID: UUID) async {
        guard !isPreviewOnly else { return }
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }

        isSyncing = true
        defer { isSyncing = false }

        do {
            let repository = try await repository()
            _ = try await repository.send(text: trimmed, to: chatID)
            failure = nil
        } catch {
            record(error)
        }
        // Reload either way: a failed send is stored as failed, and the user must see that.
        await refresh()
    }

    /// Re-encodes a picked image, encrypts it, uploads the ciphertext and sends the pointer
    /// (P6.S04).
    ///
    /// The re-encode happens before anything else and is not optional: it is what keeps the
    /// photo's EXIF — including where it was taken — out of the message (`PhotoAttachment`).
    func sendPhoto(_ data: Data, to chatID: UUID) async {
        guard !isPreviewOnly else { return }

        isSyncing = true
        defer { isSyncing = false }

        guard let prepared = PhotoAttachment.prepare(data) else {
            record(.attachmentUnavailable)
            return
        }

        do {
            _ = try await repository().sendAttachment(bytes: prepared, to: chatID)
            failure = nil
        } catch {
            record(error)
        }
        await refresh()
    }

    /// The decrypted bytes behind one attachment message, downloading the blob if this device
    /// does not hold it yet.
    ///
    /// Returns them rather than caching them here. Plaintext image bytes live only in the view
    /// that is showing them, so closing the conversation is what releases them — a store-level
    /// cache would keep every photo the user scrolled past resident for the life of the
    /// process, which is the opposite of what a disappearing-message feature is for.
    func attachmentBytes(for messageID: UUID, in chatID: UUID) async -> Data? {
        guard !isPreviewOnly else { return nil }
        guard let ordinal = ordinal(of: messageID) else { return nil }
        do {
            let bytes = try await repository().attachmentBytes(ordinal: ordinal, in: chatID)
            failure = nil
            return bytes
        } catch {
            record(error)
            return nil
        }
    }

    func togglePin(chatID: UUID) async {
        guard let chat = chat(id: chatID) else { return }
        await mutate { try await $0.setPinned(!chat.isPinned, for: chatID) }
    }

    func toggleMute(chatID: UUID) async {
        guard let chat = chat(id: chatID) else { return }
        await mutate { try await $0.setMuted(!chat.isMuted, for: chatID) }
    }

    func rename(chatID: UUID, to nickname: String?) async {
        let cleaned = nickname?.trimmingCharacters(in: .whitespacesAndNewlines)
        await mutate { try await $0.setNickname(cleaned?.isEmpty == true ? nil : cleaned, for: chatID) }
    }

    func markRead(chatID: UUID) async {
        await mutate { try await $0.markRead(chatID) }
    }

    func markUnread(chatID: UUID) async {
        await mutate { try await $0.markUnread(chatID) }
    }

    func deleteChat(chatID: UUID) async {
        await mutate(wipingAttachments: true) { try await $0.deleteConversation(chatID) }
    }

    func clearMessages(chatID: UUID) async {
        await mutate(wipingAttachments: true) { try await $0.clearMessages(in: chatID) }
    }

    func deleteMessage(_ messageID: UUID, in chatID: UUID) async {
        guard let ordinal = ordinal(of: messageID) else { return }
        await mutate(wipingAttachments: true) {
            try await $0.deleteMessage(ordinal: ordinal, in: chatID)
        }
    }

    /// Sets the timer for messages this device sends in `chatID` (P6.S03).
    ///
    /// The options a screen may offer, and the reason they are a list rather than a free field:
    /// a timer is carried on the wire, so an arbitrary value would be a fingerprint of the
    /// sender. A short shared set is one fewer thing that distinguishes one member of a small
    /// circle from another.
    static let disappearingOptions: [Int] = [
        30, 5 * 60, 60 * 60, 8 * 60 * 60, 24 * 60 * 60, 7 * 24 * 60 * 60,
    ]

    func setDisappearing(seconds: Int?, chatID: UUID) async {
        await mutate { try await $0.setDisappearing(seconds: seconds, for: chatID) }
    }

    func toggleBlock(_ peer: UUID) async {
        let blocked = blockedContactIDs.contains(peer)
        await mutate { try await $0.setBlocked(!blocked, for: peer) }
    }

    /// Runs a repository mutation and reloads. Every writing path goes through here so none of
    /// them can forget to reload and leave the UI showing state the archive no longer holds.
    ///
    /// - Parameter wipingAttachments: whether this mutation can have removed message rows, and
    ///   with them the only reference to a cached blob. Set on the three deletion paths rather
    ///   than on all of them, because deriving what is still referenced means decoding every
    ///   message row and a pin or a mute cannot have orphaned anything (P6.S04).
    private func mutate(
        wipingAttachments: Bool = false,
        _ body: (MessageRepository) async throws -> Void
    ) async {
        guard !isPreviewOnly else { return }
        do {
            try await body(try await repository())
            failure = nil
        } catch {
            record(error)
        }
        if wipingAttachments { await wipeOrphanedAttachments() }
        await refresh()
    }

    // MARK: - Failure reporting

    private func record(_ error: Error) {
        failure = (error as? MessageRepository.Failure) ?? .relayRefused
    }

    private func record(_ specific: MessageRepository.Failure) {
        failure = specific
    }

    func clearFailure() {
        failure = nil
    }

    // MARK: - Safety numbers (P5.S12)

    /// Everything the safety-number screen renders, or `nil` when there is no key yet.
    ///
    /// Assembled in one call so the digits and the key they were computed from cannot come
    /// from two different reads: the screen hands that exact key back when the user confirms,
    /// and the engine refuses it if the stored key has moved on since.
    func safetyNumberDetails(for peer: UUID) async -> SafetyNumberDetails? {
        guard !isPreviewOnly else { return nil }
        guard let repository = try? await repository() else { return nil }
        guard let identity = await repository.peerIdentity(with: peer) else { return nil }
        guard let digits = await repository.safetyNumber(with: peer) else { return nil }
        return SafetyNumberDetails(
            peer: peer,
            digits: digits,
            identityKey: identity.identityKey,
            isVerified: identity.isVerified,
            needsAcknowledgement: identity.needsAcknowledgement,
            changedAtMs: identity.changedAtMs)
    }

    /// Records or withdraws the user's comparison. Returns false if the key moved underneath.
    @discardableResult
    func setVerified(_ verified: Bool, peer: UUID, identityKey: Data) async -> Bool {
        guard !isPreviewOnly else { return false }
        guard let repository = try? await repository() else { return false }
        let ok = await repository.setVerified(verified, peer: peer, identityKey: identityKey)
        if ok { await refresh() }
        return ok
    }

    /// Accepts a changed key so sending is unblocked (locked decision §0.2.1).
    @discardableResult
    func acceptIdentity(peer: UUID, identityKey: Data) async -> Bool {
        guard !isPreviewOnly else { return false }
        guard let repository = try? await repository() else { return false }
        let ok = await repository.acceptIdentity(peer: peer, identityKey: identityKey)
        if ok { await refresh() }
        return ok
    }

    // MARK: - Mapping the archive onto the view models

    /// The view model's message ordinal, which the archive needs to address a deletion. Kept out
    /// of `Message` itself: the ordinal is a storage detail, and P5.S11 replaces it.
    private var ordinals: [UUID: Int] = [:]

    /// Peers whose safety number the user has compared out of band and confirmed.
    ///
    /// Derived on every refresh rather than stored here as truth. The record store owns it,
    /// bound to the exact identity key, so this is a render cache that a key change empties
    /// on the next reload rather than a second place the answer could be wrong.
    private var verifiedPeers: Set<UUID> = []

    private func ordinal(of messageID: UUID) -> Int? { ordinals[messageID] }

    private func apply(_ stored: [ConversationArchive.StoredConversation]) {
        blockedContactIDs = Set(stored.filter(\.isBlocked).map(\.peer))

        contacts = stored.map { conversation in
            Contact(
                id: conversation.peer,
                name: Self.title(for: conversation),
                username: Self.shortId(conversation.peer),
                initials: Self.initials(for: conversation),
                accentHue: Self.hue(for: conversation.peer),
                // Verified is now real (P5.S12): true only when the user has compared this
                // peer's safety number and the key has not changed since. Presence still does
                // not exist on the wire and stays false rather than decorative.
                isVerified: verifiedPeers.contains(conversation.peer),
                isOnline: false,
                about: "")
        }

        chats = stored.map { conversation in
            let messages = messagesByChat[conversation.peer] ?? []
            return Chat(
                id: conversation.peer,
                title: Self.title(for: conversation),
                isGroup: false,
                participantIDs: [currentUserID, conversation.peer],
                lastMessagePreview: Self.preview(of: messages.last),
                lastMessageDate: Date(
                    timeIntervalSince1970: Double(conversation.lastActivityMs) / 1000),
                unreadCount: max(0, conversation.nextOrdinal - conversation.lastReadOrdinal),
                isPinned: conversation.isPinned,
                isMuted: conversation.isMuted,
                isVerified: verifiedPeers.contains(conversation.peer),
                avatarInitials: Self.initials(for: conversation),
                accentHue: Self.hue(for: conversation.peer),
                disappearingSeconds: conversation.disappearingSeconds)
        }
        .sorted {
            if $0.isPinned != $1.isPinned { return $0.isPinned && !$1.isPinned }
            return $0.lastMessageDate > $1.lastMessageDate
        }
    }

    private static func viewMessage(
        _ stored: ConversationArchive.StoredMessage, peer: UUID, localAci: UUID?
    ) -> Message {
        let isMine = stored.direction == .outgoing
        let kind: MessageKind
        if let attachment = stored.attachment {
            // The size, and nothing else. The key and the blob id stay in the sealed row: a
            // view model is held in memory for as long as the conversation is on screen, and
            // neither belongs there (P6.S04).
            kind = .photo(byteCount: attachment.byteCount)
        } else {
            kind = isEmojiOnly(stored.text) ? .emoji(stored.text) : .text(stored.text)
        }
        return Message(
            id: stored.id,
            chatID: peer,
            senderID: isMine ? (localAci ?? unregisteredPlaceholder) : peer,
            kind: kind,
            date: Date(timeIntervalSince1970: Double(stored.timestampMs) / 1000),
            status: Self.status(of: stored),
            isFromCurrentUser: isMine,
            reactions: [:])
    }

    /// Status is only ever rendered for the user's own messages, and only these three exist:
    /// there are no delivery or read receipts on the wire, so there is nothing that could
    /// truthfully report what happened on the other device.
    private static func status(of stored: ConversationArchive.StoredMessage) -> MessageStatus {
        switch stored.state {
        case .sending: return .sending
        case .sent, .received: return .sent
        case .failed: return .failed
        }
    }

    private static func isEmojiOnly(_ text: String) -> Bool {
        !text.isEmpty && text.unicodeScalars.count <= 3
            && text.unicodeScalars.allSatisfy { $0.properties.isEmoji }
    }

    private static func preview(of message: Message?) -> String {
        guard let message else { return String(localized: "No messages yet") }
        switch message.kind {
        case .text(let value), .emoji(let value), .system(let value): return value
        case .photo: return String(localized: "Photo")
        default: return String(localized: "No messages yet")
        }
    }

    private static func title(for conversation: ConversationArchive.StoredConversation) -> String {
        if let nickname = conversation.nickname, !nickname.isEmpty { return nickname }
        return shortId(conversation.peer)
    }

    /// The first block of the ACI. Not a name and not pretending to be one — a peer has no name
    /// until the user gives them one, because there is no directory to ask.
    private static func shortId(_ peer: UUID) -> String {
        String(peer.uuidString.prefix(8)).uppercased()
    }

    private static func initials(
        for conversation: ConversationArchive.StoredConversation
    ) -> String {
        if let nickname = conversation.nickname, !nickname.isEmpty {
            let parts = nickname.split(separator: " ")
            if parts.count >= 2 {
                return String(parts[0].prefix(1) + parts[1].prefix(1)).uppercased()
            }
            return String(nickname.prefix(2)).uppercased()
        }
        return String(conversation.peer.uuidString.prefix(2)).uppercased()
    }

    /// A stable colour per peer, derived from the identifier rather than stored.
    ///
    /// Deterministic on purpose: an avatar colour that changed between launches would be a
    /// second, unreliable signal of "who am I talking to" sitting next to the name.
    private static func hue(for peer: UUID) -> Double {
        var accumulator: UInt64 = 0xcbf2_9ce4_8422_2325
        withUnsafeBytes(of: peer.uuid) { bytes in
            for byte in bytes {
                accumulator = (accumulator ^ UInt64(byte)) &* 0x1000_0000_01b3
            }
        }
        return Double(accumulator % 1000) / 1000.0
    }
}
