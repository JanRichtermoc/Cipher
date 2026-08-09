//
//  CipherProtocolStore.swift
//  CipherCrypto
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import CryptoKit
import Foundation
import LibSignalClient

/// libsignal's protocol stores, persisted.
///
/// ## Isolation
///
/// This type is **not** `Sendable` and is **not** an actor, and both are deliberate.
/// libsignal calls these methods synchronously through C function pointers from inside an
/// FFI call; an `actor` cannot satisfy them and `@unchecked Sendable` plus a lock would put
/// the safety argument in a comment. Instead the object is held in `@CryptoActor`-isolated
/// storage and every entry point opens with `CryptoActor.assertIsolated()`, which turns
/// "we believe libsignal serializes its callbacks" into something that traps the moment it
/// is not true. `IsolationContract` is the compile-time half of the same argument.
///
/// ## No caching, on purpose
///
/// Every method reads through to the record store. A future notification-service extension
/// is a **separate process** over the same container: it decrypts a message, steps the
/// ratchet, and writes a new session record while the app is suspended. Any in-memory cache
/// here would be stale on resume and would overwrite the extension's work with an older
/// ratchet state, silently breaking the session. The cost is a small database read per
/// callback, which is not the bottleneck in an operation that also runs PQXDH.
///
/// ## `SenderKeyStore` is deliberately not implemented
///
/// Group messaging is out of scope for this phase and `Envelope.payloadType(for:)` already
/// refuses `.senderKey` at the wire boundary. Implementing an untested sender-key store
/// would add reachable state that nothing validates. When groups arrive, the store and the
/// wire type land together.
internal final class CipherProtocolStore {

    /// Upper bound on remembered base keys per (kyber prekey, signed prekey) pair.
    ///
    /// See `markKyberPreKeyUsed` for why this is a bounded FIFO rather than an unbounded
    /// set or a hard failure.
    internal static let baseKeyWitnessCapacity = 512

    /// Named `deviceIdentity`, not `identity`: `IdentityKeyStore` already contributes an
    /// `identity(for:context:)` requirement, and one base name meaning two things in one
    /// type is how a reviewer misreads which one a line touches.
    private let deviceIdentity: DeviceIdentity
    private let records: RecordStore
    /// The app's queryable sealed store (P5.S11). `records` uses this same connection through a
    /// narrow key-value adapter, so a receive can commit protocol and archive state together.
    private let database: SealedRecordDatabase
    private let secrets: SecretStorage
    private let now: () -> UInt64

    /// - Parameter now: milliseconds since the Unix epoch, injectable so tests can assert on
    ///   the recorded timestamps rather than around them.
    internal init(
        deviceIdentity: DeviceIdentity,
        records: RecordStore,
        database: SealedRecordDatabase,
        secrets: SecretStorage,
        now: @escaping () -> UInt64 = { UInt64(Date().timeIntervalSince1970 * 1000) }
    ) {
        CryptoActor.assertIsolated()
        self.deviceIdentity = deviceIdentity
        self.records = records
        self.database = database
        self.secrets = secrets
        self.now = now
    }

    // MARK: - Record keys

    /// A peer's slot. It is blinded into a database tag and authenticated inside the sealed
    /// value; legacy builds hashed it into a filename. It never becomes a path component.
    private func addressKey(_ address: ProtocolAddress) -> String {
        "\(address.name).\(address.deviceId)"
    }

    private func idKey(_ id: UInt32) -> String { String(id) }

    // MARK: - Destructive reset

    /// Destroys every session, prekey, trust decision and the identity itself.
    ///
    /// The Keychain service is removed first, in one platform operation. That is the
    /// cryptographic erase: after it succeeds, every surviving database page, WAL frame and
    /// legacy record is ciphertext under a key that no longer exists. File cleanup follows and
    /// is retryable. Reversing those two steps leaves a crash window in which the files that
    /// survived are still fully recoverable with the untouched Keychain key.
    internal func destroyAllState() throws {
        CryptoActor.assertIsolated()
        try secrets.removeAll()
        // The database owns the exact private crypto root. Removing the root also removes every
        // legacy kind directory, including a copy whose post-migration unlink was interrupted.
        try database.destroy()
        CipherLog.store.warning("all local protocol state destroyed")
    }

    // MARK: - Prekey id allocation

    private static let nextPreKeyIdKey = "next-prekey-id"
    /// Signal keeps prekey ids inside 24 bits. Staying in that range means no id this
    /// module mints can ever be rejected by a peer that enforces it.
    private static let maxPreKeyId: UInt32 = 0xFF_FFFF

    /// Reserves `count` fresh prekey ids and advances the counter.
    ///
    /// Ids come from a monotonic counter rather than from "which ids are currently stored",
    /// which is the reason the record store deliberately offers no key enumeration. The
    /// difference matters: libsignal deletes a one-time prekey the moment it is used, so an
    /// allocator that looked at what exists would happily hand back the id of a prekey that
    /// was consumed seconds ago, and a replayed message could then be matched against a
    /// brand-new private key.
    internal func reservePreKeyIds(count: Int) throws -> ClosedRange<UInt32> {
        CryptoActor.assertIsolated()
        precondition(count > 0, "cannot reserve zero prekey ids")

        let next = try loadNextPreKeyId()
        guard UInt64(next) + UInt64(count) - 1 <= UInt64(Self.maxPreKeyId) else {
            throw ProtocolStoreError.preKeyIdSpaceExhausted
        }

        let last = next + UInt32(count) - 1
        var advanced = Data(capacity: 4)
        withUnsafeBytes(of: (last + 1).bigEndian) { advanced.append(contentsOf: $0) }
        try records.store(.metadata, Self.nextPreKeyIdKey, advanced)

        return next...last
    }

    /// The counter's value, or 1 when nothing has been allocated yet.
    ///
    /// A stored 0 is treated as corruption rather than as "start again": restarting the
    /// counter would reissue ids whose prekeys libsignal has already consumed and deleted.
    private func loadNextPreKeyId() throws -> UInt32 {
        guard let stored = try records.load(.metadata, Self.nextPreKeyIdKey) else { return 1 }
        guard stored.count == 4 else { throw ProtocolStoreError.malformedMetadata }

        let base = stored.startIndex
        var value: UInt32 = 0
        for offset in 0..<4 { value = (value << 8) | UInt32(stored[base + offset]) }

        guard value >= 1 else { throw ProtocolStoreError.malformedMetadata }
        return value
    }

    // MARK: - Prekey rotation (P6.S01, AUDIT 2.4)

    private static let preKeyRotationKey = "prekey-rotation"

    /// Upper bound on retired pairs the record will carry.
    ///
    /// Retention alone bounds this in every schedule the app actually runs — thirty days of
    /// two-day rotations is fifteen pairs — so this is the valve for a schedule that is wrong,
    /// not the mechanism. It matters because the record is one sealed value with a size ceiling:
    /// an unbounded list would eventually fail to *write*, which would make rotation itself
    /// start failing. Overflow retires the oldest entries early, which is the safe direction —
    /// it deletes key material sooner rather than keeping it longer.
    internal static let retiredPreKeyCapacity = 64

    /// Which store a retired record belongs to. Persisted as a byte, so it is a format
    /// decision: a rotation record written by one build must resolve to the same store in the
    /// next, or a prune would delete the wrong key.
    internal enum RetiredPreKeyKind: UInt8 {
        case signedPreKey = 1
        case kyberLastResort = 2

        fileprivate var recordKind: RecordKind {
            switch self {
            case .signedPreKey: return .signedPreKey
            case .kyberLastResort: return .kyberPreKey
            }
        }
    }

    internal struct RetiredPreKey: Equatable {
        internal let kind: RetiredPreKeyKind
        internal let keyId: UInt32
        internal let retiredAtMs: UInt64
    }

    /// The live signed prekey and last-resort Kyber key, when they were minted, and the
    /// superseded pairs still inside their retention window.
    internal struct PreKeyRotationRecord: Equatable {
        internal let signedPreKeyId: UInt32
        internal let kyberLastResortId: UInt32
        internal let rotatedAtMs: UInt64
        internal let retired: [RetiredPreKey]
    }

    internal func preKeyRotation() throws -> PreKeyRotationRecord? {
        CryptoActor.assertIsolated()
        guard let bytes = try records.load(.metadata, Self.preKeyRotationKey) else { return nil }
        return try Self.decodeRotation(bytes)
    }

    /// Promotes the newly minted pair to live, retires the pair it replaces, and deletes
    /// retired records whose retention has elapsed.
    ///
    /// # Why the old pair is not deleted here
    ///
    /// A peer that fetched this account's bundle just before the rotation holds the *old*
    /// signed prekey id and names it in their first message. Deleting the private half on the
    /// spot turns that message into a permanent `invalidKeyIdentifier` — the peer cannot retry
    /// into success, because the key is gone. Retention is what makes rotation safe to do
    /// often; the prune is what stops it from being a slow leak.
    ///
    /// # Order, and what a crash in the middle costs
    ///
    /// Expired records are removed **before** the new record is written. A crash between the
    /// two leaves the previous pair still marked live, so the next rotation retires it again —
    /// nothing is orphaned. The reverse order would drop the only reference to a record that
    /// still exists on disk, and nothing would ever prune it.
    ///
    /// # The one thing this cannot clean up
    ///
    /// An installation that published before this record existed has a signed prekey and a
    /// last-resort Kyber key whose ids nothing recorded, and the record store deliberately
    /// offers no enumeration to find them. Those two records survive until the account is
    /// erased. Two records, known and bounded, and stated rather than discovered later.
    internal func recordPreKeyRotation(
        signedPreKeyId: UInt32, kyberLastResortId: UInt32, at now: UInt64, retention: UInt64
    ) throws {
        CryptoActor.assertIsolated()

        let previous = try preKeyRotation()
        var retired = previous?.retired ?? []
        if let previous {
            retired.append(
                RetiredPreKey(
                    kind: .signedPreKey, keyId: previous.signedPreKeyId, retiredAtMs: now))
            retired.append(
                RetiredPreKey(
                    kind: .kyberLastResort, keyId: previous.kyberLastResortId, retiredAtMs: now))
        }

        // A clock that moved backwards keeps a record rather than dropping it: the test is
        // "demonstrably older than the window", not "not newer than". Erring toward keeping
        // costs one stored keypair; erring the other way costs a peer their first message.
        //
        // One predicate, applied once, rather than a filter and its negation written out twice:
        // two expressions that must stay exact complements are two expressions that can drift,
        // and a drift here either deletes a live key or never deletes a dead one.
        func hasExpired(_ entry: RetiredPreKey) -> Bool {
            now >= entry.retiredAtMs && now - entry.retiredAtMs >= retention
        }
        var expired = retired.filter(hasExpired)
        var kept = retired.filter { !hasExpired($0) }

        if kept.count > Self.retiredPreKeyCapacity {
            let overflow = kept.count - Self.retiredPreKeyCapacity
            expired.append(contentsOf: kept.prefix(overflow))
            kept.removeFirst(overflow)
            CipherLog.keys.warning(
                "retired prekey list at capacity; retiring the oldest entries early")
        }

        for entry in expired {
            try records.remove(entry.kind.recordKind, idKey(entry.keyId))
        }

        try records.store(
            .metadata, Self.preKeyRotationKey,
            Self.encodeRotation(
                PreKeyRotationRecord(
                    signedPreKeyId: signedPreKeyId, kyberLastResortId: kyberLastResortId,
                    rotatedAtMs: now, retired: kept)))

        if !expired.isEmpty {
            CipherLog.keys.info("pruned superseded prekey records past their retention")
        }
    }

    // MARK: Rotation record coding

    /// ```text
    ///  offset  size  field
    ///       0     1  version             always 0x01
    ///       1     4  signedPreKeyId      big-endian
    ///       5     4  kyberLastResortId   big-endian
    ///       9     8  rotatedAtMs         big-endian
    ///      17     1  retiredCount
    ///      18  13*n  retired entries     kind(1) | keyId(4) | retiredAtMs(8)
    /// ```
    ///
    /// Fixed-width and versioned for the same reason `PeerIdentityRecord` is: a record this
    /// build cannot parse must fail loudly rather than be read as a different record. An
    /// unreadable rotation record surfaces as a refusal to rotate, which is visible, rather
    /// than as a silent "never rotated" that would republish over live keys.
    private static let rotationVersion: UInt8 = 1
    private static let retiredEntrySize = 13
    private static let rotationHeaderSize = 18

    private static func encodeRotation(_ record: PreKeyRotationRecord) -> Data {
        precondition(record.retired.count <= retiredPreKeyCapacity)

        var out = Data(capacity: rotationHeaderSize + record.retired.count * retiredEntrySize)
        out.append(rotationVersion)
        appendBigEndian(&out, record.signedPreKeyId)
        appendBigEndian(&out, record.kyberLastResortId)
        appendBigEndian(&out, record.rotatedAtMs)
        out.append(UInt8(record.retired.count))
        for entry in record.retired {
            out.append(entry.kind.rawValue)
            appendBigEndian(&out, entry.keyId)
            appendBigEndian(&out, entry.retiredAtMs)
        }
        return out
    }

    private static func decodeRotation(_ bytes: Data) throws -> PreKeyRotationRecord {
        let base = bytes.startIndex
        guard bytes.count >= rotationHeaderSize, bytes[base] == rotationVersion else {
            throw ProtocolStoreError.malformedMetadata
        }

        let count = Int(bytes[base + 17])
        guard bytes.count == rotationHeaderSize + count * retiredEntrySize,
              count <= retiredPreKeyCapacity
        else {
            throw ProtocolStoreError.malformedMetadata
        }

        var retired: [RetiredPreKey] = []
        retired.reserveCapacity(count)
        for index in 0..<count {
            let start = base + rotationHeaderSize + index * retiredEntrySize
            guard let kind = RetiredPreKeyKind(rawValue: bytes[start]) else {
                throw ProtocolStoreError.malformedMetadata
            }
            retired.append(
                RetiredPreKey(
                    kind: kind,
                    keyId: readBigEndian(bytes, start + 1),
                    retiredAtMs: readBigEndian(bytes, start + 5)))
        }

        return PreKeyRotationRecord(
            signedPreKeyId: readBigEndian(bytes, base + 1),
            kyberLastResortId: readBigEndian(bytes, base + 5),
            rotatedAtMs: readBigEndian(bytes, base + 9),
            retired: retired)
    }

    private static func appendBigEndian(_ out: inout Data, _ value: UInt32) {
        withUnsafeBytes(of: value.bigEndian) { out.append(contentsOf: $0) }
    }

    private static func appendBigEndian(_ out: inout Data, _ value: UInt64) {
        withUnsafeBytes(of: value.bigEndian) { out.append(contentsOf: $0) }
    }

    private static func readBigEndian(_ bytes: Data, _ offset: Int) -> UInt32 {
        var value: UInt32 = 0
        for index in 0..<4 { value = (value << 8) | UInt32(bytes[offset + index]) }
        return value
    }

    private static func readBigEndian(_ bytes: Data, _ offset: Int) -> UInt64 {
        var value: UInt64 = 0
        for index in 0..<8 { value = (value << 8) | UInt64(bytes[offset + index]) }
        return value
    }

    // MARK: - Installation metadata

    /// Small, non-secret installation facts — currently only this device's own address.
    ///
    /// Deliberately a narrow pair rather than a general key-value surface: metadata records
    /// share the record store's encryption and its AAD binding, so anything written here is
    /// destroyed by `destroyAllState` along with the sessions, which is the property that
    /// makes "delete everything" mean it. A wider API would invite storing something that
    /// ought to be a typed record with its own validation.
    internal func metadata(_ key: String) throws -> Data? {
        CryptoActor.assertIsolated()
        return try records.load(.metadata, key)
    }

    internal func setMetadata(_ key: String, _ value: Data) throws {
        CryptoActor.assertIsolated()
        try records.store(.metadata, key, value)
    }

    // MARK: - Application records

    /// The app's own sealed records — conversations and message bodies (P5.S10).
    ///
    /// Deliberately a separate `RecordKind` from `.metadata` rather than a shared namespace:
    /// the kind is part of the AEAD's authenticated data, so app records and this module's own
    /// counters cannot be swapped for one another by anything with container write access, and
    /// the `metadata` comment above stays true — that surface remains narrow. The validation
    /// of the composed key lives at the public boundary in `SealedAppStore.swift`.
    internal func storeAppData(_ key: String, _ value: Data) throws {
        CryptoActor.assertIsolated()
        try records.store(.appData, key, value)
    }

    internal func loadAppData(_ key: String) throws -> Data? {
        CryptoActor.assertIsolated()
        return try records.load(.appData, key)
    }

    internal func removeAppData(_ key: String) throws {
        CryptoActor.assertIsolated()
        try records.remove(.appData, key)
    }

    /// The app's queryable sealed store (P5.S11).
    ///
    /// `internal` for exactly the reason `CryptoEngine.store` is: the validated public boundary
    /// is in `SealedRowStore.swift`, and handing the connection out beyond this module would
    /// hand out the ability to write a row that nothing sealed.
    internal var appDatabase: SealedRecordDatabase { database }

    // MARK: - Peer identity state, for the UI

    /// The trust state to render a safety-number screen from, or `nil` if this peer has
    /// never been seen.
    internal func peerIdentity(for address: ProtocolAddress) throws -> PeerIdentityRecord? {
        CryptoActor.assertIsolated()
        return try loadPeerIdentity(address)
    }

    /// Records that the user has looked at and accepted `identity` for `address`.
    ///
    /// The key is a parameter rather than implied, so an approval always names exactly what
    /// was shown. If another change arrives between the screen being drawn and the user
    /// tapping accept, the approval no longer matches what is stored and is refused —
    /// otherwise a well-timed attacker could have a user approve a key they never saw.
    ///
    /// - Returns: `false` if the stored key is not the one being accepted, in which case
    ///   nothing changed and the caller must re-present the current key.
    @discardableResult
    internal func acceptIdentity(_ identity: IdentityKey, for address: ProtocolAddress) throws
        -> Bool {
        CryptoActor.assertIsolated()

        guard let existing = try loadPeerIdentity(address) else { return false }
        guard existing.identityKey == identity else {
            CipherLog.session.warning("identity acceptance refused: stale key presented")
            return false
        }
        guard existing.needsAcknowledgement else { return true }

        try storePeerIdentity(
            PeerIdentityRecord(
                identityKey: existing.identityKey,
                firstSeenMs: existing.firstSeenMs,
                changedAtMs: existing.changedAtMs,
                needsAcknowledgement: false,
                // Accepting is not verifying, and collapsing the two would be the whole point
                // of AUDIT 5.4 undone. Accepting says "I have seen that this key changed and
                // I want to keep talking"; verifying says "I compared the digits with this
                // person out of band and they matched". A user who accepts a substituted key
                // to unblock a conversation must not thereby acquire a verified badge, so
                // this deliberately carries the existing bit forward rather than setting it —
                // and after a change that bit is already false, because saveIdentity cleared
                // it when it wrote the new key.
                isVerified: existing.isVerified),
            for: address)
        CipherLog.session.info("identity change accepted for a peer")
        return true
    }

    /// Records the user's out-of-band comparison of this peer's safety number.
    ///
    /// Takes the key for the same reason `acceptIdentity` does, and it matters more here:
    /// the digits the user compared are a function of that exact key, so a verification that
    /// did not name it could be applied to a key the user never saw. If the stored key has
    /// moved on since the screen was drawn, this refuses and the caller must re-present.
    ///
    /// Clearing is the same operation with `verified: false` — a user who decides the numbers
    /// did not match needs a way to say so, and it must not require the key to have changed.
    ///
    /// - Returns: `false` if the stored key is not the one being verified, in which case
    ///   nothing changed.
    @discardableResult
    internal func setIdentityVerified(
        _ verified: Bool, _ identity: IdentityKey, for address: ProtocolAddress
    ) throws -> Bool {
        CryptoActor.assertIsolated()

        guard let existing = try loadPeerIdentity(address) else { return false }
        guard existing.identityKey == identity else {
            CipherLog.session.warning("identity verification refused: stale key presented")
            return false
        }
        guard existing.isVerified != verified else { return true }

        try storePeerIdentity(
            PeerIdentityRecord(
                identityKey: existing.identityKey,
                firstSeenMs: existing.firstSeenMs,
                changedAtMs: existing.changedAtMs,
                needsAcknowledgement: existing.needsAcknowledgement,
                isVerified: verified),
            for: address)
        // No address, no key, no digits. Whether a peer is verified is a fact about a
        // conversation, and the log is not where it belongs.
        CipherLog.session.info("peer safety-number verification state changed")
        return true
    }

    // MARK: - Peer identity storage

    private func loadPeerIdentity(_ address: ProtocolAddress) throws -> PeerIdentityRecord? {
        guard let bytes = try records.load(.peerIdentity, addressKey(address)) else { return nil }
        return try PeerIdentityRecord.decode(bytes)
    }

    private func storePeerIdentity(
        _ record: PeerIdentityRecord, for address: ProtocolAddress
    ) throws {
        try records.store(.peerIdentity, addressKey(address), record.encode())
    }
}

// MARK: - IdentityKeyStore

extension CipherProtocolStore: IdentityKeyStore {

    internal func identityKeyPair(context: StoreContext) throws -> IdentityKeyPair {
        CryptoActor.assertIsolated()
        return deviceIdentity.identityKeyPair
    }

    internal func localRegistrationId(context: StoreContext) throws -> UInt32 {
        CryptoActor.assertIsolated()
        return deviceIdentity.registrationId
    }

    /// Records `identity` as this peer's key.
    ///
    /// libsignal calls this on the receive path, after `isTrustedIdentity` has already
    /// allowed the message through. A change therefore lands here rather than being
    /// refused, and the flag it sets is what later blocks *sending* until the user has
    /// looked at the new safety number.
    internal func saveIdentity(
        _ identity: IdentityKey,
        for address: ProtocolAddress,
        context: StoreContext
    ) throws -> IdentityChange {
        CryptoActor.assertIsolated()

        let timestamp = now()

        guard let existing = try loadPeerIdentity(address) else {
            try storePeerIdentity(
                PeerIdentityRecord(
                    identityKey: identity,
                    firstSeenMs: timestamp,
                    changedAtMs: nil,
                    needsAcknowledgement: false),
                for: address)
            return .newOrUnchanged
        }

        guard existing.identityKey != identity else {
            // Idempotent. Rewriting the record here would reset nothing but would churn the
            // file on every inbound message.
            return .newOrUnchanged
        }

        try storePeerIdentity(
            PeerIdentityRecord(
                identityKey: identity,
                firstSeenMs: existing.firstSeenMs,
                changedAtMs: timestamp,
                needsAcknowledgement: true,
                // The new key has never been compared with anyone, so it is not verified —
                // stated explicitly rather than relying on the default, because this is the
                // line that makes "invalidate on identity change" true. A verified badge that
                // survived a key change would be the most dangerous possible lie in this app:
                // it would assert the substitution had been checked.
                isVerified: false),
            for: address)
        CipherLog.session.error("peer identity key changed; sending is blocked until accepted")
        return .replacedExisting
    }

    /// The trust decision, and the one place where the two directions deliberately differ.
    ///
    /// - **First sight** is trusted (TOFU). There is nothing to compare against, and the
    ///   safety number is what lets two users detect a substitution out of band.
    ///
    /// - **A changed key, receiving.** Trusted. Refusing would not protect the user: the
    ///   attacker already holds the ciphertext, and all a refusal achieves locally is that
    ///   messages vanish with no explanation — which trains users to ignore the warning
    ///   that follows. The protection is the loud, user-visible safety-number change that
    ///   `saveIdentity` arms, not a silent drop.
    ///
    /// - **A changed or unacknowledged key, sending.** Refused. This is the direction where
    ///   refusing genuinely protects, because it is the only one that would hand *new
    ///   plaintext* to a key the user has never seen. libsignal surfaces this as
    ///   `SignalError.untrustedIdentity`, and it stays refused until `acceptIdentity`
    ///   records that the user looked at the new key.
    internal func isTrustedIdentity(
        _ identity: IdentityKey,
        for address: ProtocolAddress,
        direction: Direction,
        context: StoreContext
    ) throws -> Bool {
        CryptoActor.assertIsolated()

        guard let existing = try loadPeerIdentity(address) else { return true }

        guard existing.identityKey == identity else {
            // A change that has not been recorded yet.
            switch direction {
            case .receiving: return true
            case .sending: return false
            }
        }

        switch direction {
        case .receiving:
            return true
        case .sending:
            return !existing.needsAcknowledgement
        }
    }

    internal func identity(for address: ProtocolAddress, context: StoreContext) throws
        -> IdentityKey? {
        CryptoActor.assertIsolated()
        return try loadPeerIdentity(address)?.identityKey
    }
}

// MARK: - PreKeyStore

extension CipherProtocolStore: PreKeyStore {

    internal func loadPreKey(id: UInt32, context: StoreContext) throws -> PreKeyRecord {
        CryptoActor.assertIsolated()

        guard let bytes = try records.load(.preKey, idKey(id)) else {
            // libsignal expects this exact error shape for a missing prekey; a different
            // one would be reported to the peer as a generic failure rather than as the
            // recoverable "that prekey is gone, fetch a new bundle".
            throw SignalError.invalidKeyIdentifier("no prekey with this identifier")
        }
        return try PreKeyRecord(bytes: bytes)
    }

    internal func storePreKey(_ record: PreKeyRecord, id: UInt32, context: StoreContext) throws {
        CryptoActor.assertIsolated()
        var serialized = record.serialize()
        defer { serialized.resetBytes(in: serialized.startIndex..<serialized.endIndex) }
        try records.store(.preKey, idKey(id), serialized)
    }

    /// libsignal removes a consumed one-time prekey itself, from inside the prekey-decrypt
    /// path. `LibsignalContractTests.testLibraryConsumesOneTimePreKeyItself` pins that, and
    /// this module must never do it as well: removing a prekey the library still intends to
    /// use would break session establishment in a way that only shows up under retries.
    internal func removePreKey(id: UInt32, context: StoreContext) throws {
        CryptoActor.assertIsolated()
        try records.remove(.preKey, idKey(id))
    }

    /// How many unused one-time prekeys remain, for replenishment thresholds.
    internal func remainingPreKeyCount() throws -> Int {
        CryptoActor.assertIsolated()
        return try records.count(.preKey)
    }
}

// MARK: - SignedPreKeyStore

extension CipherProtocolStore: SignedPreKeyStore {

    internal func loadSignedPreKey(id: UInt32, context: StoreContext) throws -> SignedPreKeyRecord {
        CryptoActor.assertIsolated()

        guard let bytes = try records.load(.signedPreKey, idKey(id)) else {
            throw SignalError.invalidKeyIdentifier("no signed prekey with this identifier")
        }
        return try SignedPreKeyRecord(bytes: bytes)
    }

    internal func storeSignedPreKey(
        _ record: SignedPreKeyRecord, id: UInt32, context: StoreContext
    ) throws {
        CryptoActor.assertIsolated()
        var serialized = record.serialize()
        defer { serialized.resetBytes(in: serialized.startIndex..<serialized.endIndex) }
        try records.store(.signedPreKey, idKey(id), serialized)
    }
}

// MARK: - KyberPreKeyStore

extension CipherProtocolStore: KyberPreKeyStore {

    internal func loadKyberPreKey(id: UInt32, context: StoreContext) throws -> KyberPreKeyRecord {
        CryptoActor.assertIsolated()

        guard let bytes = try records.load(.kyberPreKey, idKey(id)) else {
            throw SignalError.invalidKeyIdentifier("no kyber prekey with this identifier")
        }
        return try KyberPreKeyRecord(bytes: bytes)
    }

    internal func storeKyberPreKey(
        _ record: KyberPreKeyRecord, id: UInt32, context: StoreContext
    ) throws {
        CryptoActor.assertIsolated()
        var serialized = record.serialize()
        defer { serialized.resetBytes(in: serialized.startIndex..<serialized.endIndex) }
        try records.store(.kyberPreKey, idKey(id), serialized)
    }

    /// Replay protection for session establishment, and the point at which a **used one-time
    /// Kyber prekey stops existing**.
    ///
    /// ## The deletion, and why it is here
    ///
    /// libsignal's `KyberPreKeyStore` has no `removeKyberPreKey`: this callback is the only
    /// notification a store gets that a Kyber prekey was consumed, so deleting is the store's
    /// job. It was not being done. A one-time Kyber prekey whose private half survives its use
    /// offers no more forward secrecy than the last-resort key the pool exists to avoid falling
    /// back to (`BACKEND.md` §2.6): against an adversary who records a session-establishing
    /// message and later reads this device (`THREAT_MODEL.md` §1.1/§1.3 with §1.4), every
    /// X25519 contribution in PQXDH is recoverable from public values by a quantum-capable
    /// attacker, leaving the KEM secret as the only barrier — and a retained private key is not
    /// a barrier. The curve half was already correct: libsignal calls `removePreKey` itself.
    /// AUDIT 2.6.
    ///
    /// **The last-resort key is never deleted**, live or retired. It is reusable by design, and
    /// a retired one is still inside the retention window that keeps a peer's in-flight first
    /// message decryptable (`recordPreKeyRotation` above). Every uncertainty — no rotation
    /// record, an unreadable one — resolves to *keep*, because deleting a key that is still
    /// being handed out costs a peer their first message permanently, while keeping one costs
    /// the forward secrecy this deletion buys and nothing else.
    ///
    /// A legitimate retransmission is unaffected: libsignal returns early from `process_prekey`
    /// when a session state for the same base key already exists, so the store is not consulted
    /// a second time. That is the same property the witness below already depends on — without
    /// it, a resent first message would fail here as a "reused base key" long before this
    /// deletion existed.
    ///
    /// ## Replay protection
    ///
    /// Anyone holding this device's published prekey bundle can start a session with it —
    /// that is what makes asynchronous messaging work — and the initiator chooses the base
    /// key. libsignal delegates the duplicate check to the store, so without this method a
    /// captured `PreKeySignalMessage` could be replayed against a **last-resort** kyber
    /// prekey (which is not consumed on use) and re-establish the same session, delivering
    /// the same message again.
    ///
    /// Base keys are remembered as SHA-256 digests, so the record carries no key material,
    /// and the witness is bounded at `baseKeyWitnessCapacity` entries with **oldest-first
    /// eviction**. The alternatives were both worse:
    ///
    /// - *Unbounded* is a disk-exhaustion DoS any unauthenticated party can drive, because
    ///   starting a session needs nothing but the public bundle.
    /// - *Fail closed at the cap* lets that same unauthenticated party permanently disable
    ///   session establishment against a published prekey.
    ///
    /// Eviction degrades instead: an attacker must first capture a specific old prekey
    /// message and then flush the witness before it can be replayed. The real fixes are
    /// server-side bundle-fetch rate limiting (P4.S06) and prekey rotation (P6.S01,
    /// `recordPreKeyRotation` above), and **both are now live**. AUDIT 3.1 stays open
    /// regardless until P6.S02 records what residual remains with both in place — an
    /// implemented mitigation is not the same as a reviewed one.
    ///
    /// Witness records are not pruned when a retired prekey is: they carry SHA-256 digests
    /// and no key material, they are bounded per pair, and the pairing needed to find them
    /// is not what the rotation record tracks. Stated on AUDIT 2.4 as a residual.
    internal func markKyberPreKeyUsed(
        id: UInt32, signedPreKeyId: UInt32, baseKey: PublicKey, context: StoreContext
    ) throws {
        CryptoActor.assertIsolated()

        let witnessKey = "\(id).\(signedPreKeyId)"
        let digest = Data(SHA256.hash(data: baseKey.serialize()))

        var seen = try loadBaseKeyWitness(witnessKey)
        guard !seen.contains(digest) else {
            // The same error the library's own store raises, so callers pattern-match one
            // case rather than two.
            throw SignalError.invalidMessage("reused base key")
        }

        seen.append(digest)
        if seen.count > Self.baseKeyWitnessCapacity {
            seen.removeFirst(seen.count - Self.baseKeyWitnessCapacity)
            CipherLog.keys.warning(
                "base-key witness at capacity; evicting oldest entries for one prekey pair")
        }
        try storeBaseKeyWitness(seen, witnessKey)

        // After the witness, not before: a replayed base key throws above and must leave the
        // key exactly as it was. In production this whole callback runs inside the receive
        // transaction (`CryptoEngine.withDecryptedMessageTransaction`), so a later failure
        // rolls the deletion back together with the ratchet it belongs to.
        if isOneTimeKyberPreKey(id) {
            try records.remove(.kyberPreKey, idKey(id))
        }
    }

    /// Whether `id` names a one-time Kyber prekey, which is consumed, rather than a last-resort
    /// one, which is not.
    ///
    /// Deliberately non-throwing, and deliberately answers "no" to every question it cannot
    /// settle. The two error directions are not symmetric. Refusing the message would turn an
    /// unreadable *local* record into a permanently undeliverable inbound message — the receive
    /// path treats an unmapped failure as permanent and acknowledges the envelope away — while
    /// keeping the key merely forgoes this deletion. AUDIT 4.9's "a corrupt record is fatal"
    /// applies where the record is load-bearing for the operation; here it is load-bearing only
    /// for hygiene, so it is logged and stepped over rather than raised.
    private func isOneTimeKyberPreKey(_ id: UInt32) -> Bool {
        let rotation: PreKeyRotationRecord?
        do {
            rotation = try preKeyRotation()
        } catch {
            CipherLog.keys.warning(
                "prekey rotation record unreadable; keeping a used Kyber prekey (AUDIT 2.6)")
            return false
        }

        // No record at all is the installation that published before rotation existed
        // (`recordPreKeyRotation`, "The one thing this cannot clean up"). Its last-resort id is
        // unknown, so nothing here may be deleted.
        guard let rotation else { return false }

        guard id != rotation.kyberLastResortId else { return false }
        return !rotation.retired.contains {
            $0.kind == .kyberLastResort && $0.keyId == id
        }
    }

    // MARK: Base-key witness coding

    /// ```text
    ///  offset  size  field
    ///       0     1  version   always 0x01
    ///       1     2  count     UInt16, number of digests
    ///       3  32*n  digests   SHA-256 of each base key, oldest first
    /// ```
    private static let witnessVersion: UInt8 = 1
    private static let digestSize = 32

    private func loadBaseKeyWitness(_ key: String) throws -> [Data] {
        guard let bytes = try records.load(.baseKeyWitness, key) else { return [] }

        let base = bytes.startIndex
        guard bytes.count >= 3, bytes[base] == Self.witnessVersion else {
            throw ProtocolStoreError.malformedBaseKeyWitness
        }

        let count = Int(bytes[base + 1]) << 8 | Int(bytes[base + 2])
        guard bytes.count == 3 + count * Self.digestSize else {
            throw ProtocolStoreError.malformedBaseKeyWitness
        }

        return (0..<count).map { index in
            let start = base + 3 + index * Self.digestSize
            return Data(bytes[start..<(start + Self.digestSize)])
        }
    }

    private func storeBaseKeyWitness(_ digests: [Data], _ key: String) throws {
        precondition(digests.count <= Self.baseKeyWitnessCapacity)

        var out = Data(capacity: 3 + digests.count * Self.digestSize)
        out.append(Self.witnessVersion)
        out.append(UInt8(truncatingIfNeeded: digests.count >> 8))
        out.append(UInt8(truncatingIfNeeded: digests.count))
        for digest in digests { out.append(digest) }
        try records.store(.baseKeyWitness, key, out)
    }
}

// MARK: - SessionStore

extension CipherProtocolStore: SessionStore {

    internal func loadSession(for address: ProtocolAddress, context: StoreContext) throws
        -> SessionRecord? {
        CryptoActor.assertIsolated()

        guard let bytes = try records.load(.session, addressKey(address)) else { return nil }
        return try SessionRecord(bytes: bytes)
    }

    internal func loadExistingSessions(for addresses: [ProtocolAddress], context: StoreContext)
        throws -> [SessionRecord] {
        CryptoActor.assertIsolated()

        return try addresses.map { address in
            guard let session = try loadSession(for: address, context: context) else {
                // The address is deliberately not interpolated: it is a service id, and
                // this string can reach a log.
                throw SignalError.sessionNotFound("no session for the requested address")
            }
            return session
        }
    }

    internal func storeSession(
        _ record: SessionRecord, for address: ProtocolAddress, context: StoreContext
    ) throws {
        CryptoActor.assertIsolated()
        var serialized = record.serialize()
        defer { serialized.resetBytes(in: serialized.startIndex..<serialized.endIndex) }
        try records.store(.session, addressKey(address), serialized)
    }
}

// MARK: - Errors

internal enum ProtocolStoreError: Error, Equatable {
    case malformedPeerIdentity
    case malformedBaseKeyWitness
    case malformedMetadata
    case preKeyIdSpaceExhausted
}
