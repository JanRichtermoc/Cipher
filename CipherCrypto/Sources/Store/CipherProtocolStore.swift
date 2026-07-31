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
                needsAcknowledgement: false),
            for: address)
        CipherLog.session.info("identity change accepted for a peer")
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
                needsAcknowledgement: true),
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

    /// Replay protection for session establishment.
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
    /// server-side bundle-fetch rate limiting and prekey rotation, neither of which exists
    /// yet; this is recorded in `docs/AUDIT.md` as an open residual, not as solved.
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
