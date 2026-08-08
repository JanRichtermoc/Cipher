//
//  Messaging.swift
//  CipherCrypto
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import LibSignalClient

// MARK: - Decrypted message

/// A message that decrypted, and what is actually known about where it came from.
///
/// ## Two senders, and only one of them is a fact
///
/// `sender` is the address whose **session keys authenticated the ciphertext**. Nothing in
/// the envelope produced it; it is the session the message decrypted under, which is the
/// only thing a hostile relay cannot forge. `senderIdentityKey` is the public identity key
/// bound into that session — the same value a safety number is computed from.
///
/// `claimedSender` is the envelope's routing field, kept only so a caller can log or
/// display the discrepancy. It is attacker-controlled. It has no bearing on attribution and
/// must never gate a security decision. It exists in this type precisely so that a reader
/// of calling code can see which of the two a line is using. It is `nil` for a sealed
/// message, because such a frame makes no claim: there is nothing in it for a relay to
/// rewrite, so there is no discrepancy to report.
///
/// ## What "authenticated" is worth without verification
///
/// For a message on an **established session**, the guarantee is strong: the Double Ratchet
/// MAC only verifies under keys derived from that session, so a relay that rewrites the
/// envelope's sender cannot make A's message decrypt as B — it makes it fail to decrypt.
/// `testRewrittenEnvelopeSenderCannotMisattribute` demonstrates that rather than asserting it.
///
/// For a **session-establishing** message the bound is weaker, and honestly so: the address
/// is chosen by whoever relayed it, and the identity key comes from inside the message. A
/// relay can therefore take a genuine first message from A and present it as arriving from
/// an address the user knows as B — the *content* is A's and unforgeable, but the *label* is
/// not. Nothing local detects this. It is closed by comparing safety numbers out of band
/// (P5.S12), and is recorded as AUDIT 3.8 until then. Callers must treat
/// `senderIdentityKey`, not `sender`, as the thing a user verified.
///
/// **Sealed sender narrows that, and it is worth being exact about how much.** On a sealed
/// frame the address lives inside the ciphertext, so a *relay* cannot relabel a first message
/// at all: it can neither read the certificate nor replace it, and re-wrapping the payload
/// under a name of its own is refused because the certificate's key would not be the key the
/// session authenticated (`EnvelopeError.sealedSenderKeyMismatch`). What stays open is the
/// *sender's* own claim — the certificate is self-issued
/// (`CryptoEngine.selfIssuedSenderCertificate`), so an account can still name itself anything,
/// which is what comparing safety numbers is for — and the addressed receive path, which is
/// still accepted for compatibility and carries the old weakness unchanged. AUDIT 3.8
/// therefore stays open, with a smaller surface than before.
public struct DecryptedMessage: Sendable, Equatable {

    /// The address whose session authenticated this ciphertext.
    public let sender: PeerAddress

    /// The peer identity key bound into that session. The value a safety number is built
    /// from, and the one to compare against a previously verified contact.
    public let senderIdentityKey: Data

    public let plaintext: Data

    /// The envelope's sender field: a routing hint, attacker-controlled, never attribution.
    /// Differs from `sender` only if something rewrote it in flight, and is `nil` when the
    /// frame was sealed and therefore named nobody.
    public let claimedSender: ServiceIdentifier?

    /// The envelope's timestamp: untrusted, milliseconds since the Unix epoch. Retained for
    /// gross-skew detection and display ordering. Must never gate a cryptographic decision.
    public let envelopeTimestampMs: UInt64

    /// True when the ciphertext established the session rather than continuing one, which is
    /// exactly the case where the address is unauthenticated. Surfaced so a caller can hold
    /// a first message to a lower standard rather than having to infer it.
    public let establishedSession: Bool
}

// MARK: - Errors

public enum MessagingError: Error, Equatable, Sendable {
    /// A bundle failed to parse. Distinct from a bundle whose signatures do not verify,
    /// which surfaces as `sessionSetupFailed`.
    case malformedKeyBundle
    /// `processPreKeyBundle` refused it: a bad signature, or an identity change while
    /// sending is blocked.
    case sessionSetupFailed
    /// No session with this peer, and the message was not one that establishes one.
    case noSession
    /// This installation has no address yet. Nothing can be sent or attributed until one is
    /// adopted; see `adoptLocalAddress`.
    case localAddressNotSet
    /// A local address is already recorded and differs from the one offered. Changing it
    /// would orphan every existing session, so it is refused rather than applied.
    case localAddressAlreadySet
    /// Plaintext exceeded what one envelope can carry.
    case messageTooLarge(Int)
    /// The message decrypted, but the session that decrypted it has no identity key stored —
    /// so nothing can be attributed. Should be unreachable; treated as a failure, never as
    /// an unattributed message.
    case unattributableMessage
    /// This peer's identity key has changed and the user has not accepted the new one, so
    /// **sending** is refused (locked decision §0.2.1). Receiving is unaffected.
    ///
    /// libsignal raises this as `SignalError.untrustedIdentity`, and it used to be rethrown
    /// verbatim. That was a hole in the module boundary that `verify-api-boundary.sh` cannot
    /// see: a thrown type does not appear in any signature, so the digester finds nothing —
    /// yet a caller that wanted to tell "verify the new key" from "the network is down" had to
    /// `import LibSignalClient` to name the case, which is exactly what AUDIT 5.12 closed.
    /// Mapping it keeps the original intent, which was that a caller must not be able to
    /// mistake it for a transport failure and retry.
    case identityNotAccepted
    /// The record container could not be read or written. **Distinct from every other failure
    /// because it is the only transient one**: the receive path must acknowledge a message it
    /// cannot decrypt (retrying will never succeed, and the relay would retain the ciphertext
    /// forever), but must *not* acknowledge one it failed to store — that message is still on
    /// the relay and can be collected again.
    case storeUnavailable
}

// MARK: - The messaging API

/// Sessions and messages.
///
/// The whole surface is plain values: `PeerAddress`, `PeerKeyBundle`, `Data`,
/// `DecryptedMessage`. No LibSignalClient type appears in any signature, which
/// `Scripts/verify-api-boundary.sh` checks against the built module rather than trusting
/// review. See `ServiceIdentifier` for why that matters more than tidiness.
extension CryptoEngine {

    // MARK: Local address

    private static let localAddressKey = "local-service-id"

    /// This installation's own address, once it has one.
    public var localAddress: PeerAddress? {
        get throws {
            try requireLive()
            guard let bytes = try store.metadata(Self.localAddressKey) else { return nil }
            return PeerAddress(serviceId: try ServiceIdentifier.decode(fixedWidth: bytes))
        }
    }

    /// Records the address the relay assigned to this installation.
    ///
    /// Write-once. A changed local address would leave every existing session keyed to an
    /// identity this device no longer answers to — messages would arrive addressed to the
    /// old one and be dropped, and the failure would look like a network problem rather than
    /// a state problem. Re-adopting the *same* address is a no-op so a retried registration
    /// is safe.
    public func adoptLocalAddress(_ address: PeerAddress) throws {
        try requireLive()

        if let existing = try localAddress {
            guard existing == address else { throw MessagingError.localAddressAlreadySet }
            return
        }
        try store.setMetadata(Self.localAddressKey, address.serviceId.fixedWidthBinary)
        CipherLog.session.info("local address adopted")
    }

    private func requireLocalAddress() throws -> PeerAddress {
        guard let address = try localAddress else { throw MessagingError.localAddressNotSet }
        return address
    }

    // MARK: Sessions

    /// Establishes a session from a peer's published bundle.
    ///
    /// libsignal verifies the bundle's signatures against the identity key it carries, and
    /// applies the trust policy: if this peer's key has changed and the user has not accepted
    /// the new one, this fails rather than silently re-keying. That is the same send-side
    /// block `isTrustedIdentity` enforces, arriving one step earlier.
    public func startSession(with peer: PeerAddress, bundle: PeerKeyBundle) throws {
        try requireLive()
        let localAddress = try requireLocalAddress()

        do {
            try processPreKeyBundle(
                try bundle.makePreKeyBundle(),
                for: try peer.makeProtocolAddress(),
                ourAddress: try localAddress.makeProtocolAddress(),
                sessionStore: store, identityStore: store,
                context: NullContext())
        } catch let error as MessagingError {
            throw error
        } catch {
            // An identity refusal here is the *same* decision as the send-side block, arriving
            // one step earlier, so it must not be flattened into "the bundle was bad": the
            // caller has to tell "compare a safety number" from "this bundle does not parse".
            if let mapped = Self.boundaryError(error) { throw mapped }
            CipherLog.session.error("prekey bundle refused")
            throw MessagingError.sessionSetupFailed
        }
    }

    /// Maps the two failure classes the app has to be able to name, and only those.
    ///
    /// Returns `nil` for anything else, which the caller then handles as it sees fit. Every
    /// remaining libsignal error still escapes as an opaque `Error` — that is deliberate and
    /// bounded: no caller pattern-matches one, the receive path treats any unmapped failure as
    /// permanent for that envelope, and adding a case here means adding a *behaviour* that
    /// depends on it. Every record-store error is different: corrupt, oversized or newer state
    /// is a local storage failure, not evidence that the relay envelope is bad. The receive path
    /// must roll back and retain the relay copy rather than acknowledging it away.
    private static func boundaryError(_ error: Error) -> MessagingError? {
        if case SignalError.untrustedIdentity = error { return .identityNotAccepted }
        if error is RecordStoreError { return .storeUnavailable }
        return nil
    }

    /// Whether a session exists with this peer.
    public func hasSession(with peer: PeerAddress) throws -> Bool {
        try requireLive()
        return try store.loadSession(for: try peer.makeProtocolAddress(), context: NullContext())
            != nil
    }

    // MARK: Sending

    /// Encrypts `plaintext` for `peer` and returns an encoded `Envelope` ready to relay.
    ///
    /// Refuses when the peer's identity key has changed and the user has not accepted it, as
    /// `MessagingError.identityNotAccepted` — a distinct case precisely so a caller cannot
    /// mistake it for a transport failure and retry. See that case for why it is no longer
    /// libsignal's own error type.
    ///
    /// ## Every message is sealed (P7.S01, AUDIT 3.4)
    ///
    /// There is no unsealed send path and no negotiation. A per-peer choice would be worse
    /// than useless: the choice itself would be visible to the relay as the difference
    /// between a `.sealed` frame and an addressed one, so the accounts still sending in the
    /// open would be exactly the ones the metadata is about. **Receiving** still accepts
    /// addressed frames, so a message already in flight across the upgrade is not lost; a
    /// peer that cannot yet read a `.sealed` frame refuses it, which is the cost of a new
    /// payload type rather than a `wireVersion` bump and is why this is a private-circle
    /// build decision rather than a compatibility scheme.
    public func encrypt(_ plaintext: Data, to peer: PeerAddress) throws -> Data {
        try requireLive()
        let localAddress = try requireLocalAddress()
        let context = NullContext()

        let message: CiphertextMessage
        let sealed: Data
        do {
            message = try signalEncrypt(
                message: plaintext,
                for: try peer.makeProtocolAddress(),
                localAddress: try localAddress.makeProtocolAddress(),
                sessionStore: store, identityStore: store, context: context)

            // The wire-boundary refusals apply to what is being sealed, not to the wrapper,
            // so they run here — before the payload becomes opaque to every later check.
            // `signalEncrypt` cannot currently produce either refused type, which is exactly
            // why the check belongs here: it is the assertion that keeps that true.
            _ = try Envelope.payloadType(for: message.messageType)

            let content = try UnidentifiedSenderMessageContent(
                message,
                from: try selfIssuedSenderCertificate(for: localAddress),
                contentHint: .default,
                // Empty: groups are unreachable (§0.2.2), and this field is where a group id
                // would travel. Sent empty and refused non-empty on the way back in.
                groupId: Data())

            sealed = try sealedSenderEncrypt(
                content, for: try peer.makeProtocolAddress(),
                identityStore: store, context: context)
        } catch {
            throw Self.boundaryError(error) ?? error
        }

        guard sealed.count <= Envelope.maxCiphertextBytes else {
            // Reported against the plaintext, which is the number a caller can act on. The
            // sealed container's overhead comes out of the same 64 KiB budget; a payload is
            // capped at 32 KiB (`MessagePayload.maxEncodedBytes`), so there is room for it.
            throw MessagingError.messageTooLarge(plaintext.count)
        }

        return try Envelope(
            type: .sealed, sender: nil, timestamp: now(), ciphertext: sealed
        ).encode()
    }

    // MARK: Sealed sender

    private static let senderCertificateKey = "sealed-sender-certificate"

    /// A sender certificate this account issues to itself, because the relay cannot issue one.
    ///
    /// ## Why it is self-issued
    ///
    /// libsignal's sealed-sender container requires a `SenderCertificate`; there is no way to
    /// build an `UnidentifiedSenderMessageContent` without one. Signal's server mints it, and
    /// P7.S01 was written expecting Cipher's to do the same. It cannot: those certificates are
    /// signed with **XEd25519 over Curve25519 keys**, the relay is Go, and neither its
    /// dependency set nor the standard library can produce that signature. The two ways to
    /// change that — writing the scheme in Go, or linking libsignal into the relay — are a
    /// standing prohibition (plan §0.6, "do not invent cryptography") and a supply-chain
    /// change that needs its own approval. So the certificate is minted here.
    ///
    /// ## What it therefore is, and is not
    ///
    /// **The identifier it carries authenticates nothing.** Anyone can mint one naming any
    /// ACI, exactly as anyone can write any value into the cleartext `sender` field it
    /// replaces (§0.2.3). It is not a credential, nothing validates it against a trust root on
    /// the way in — there is no trust root to validate against — and no code path treats the
    /// name in it as evidence. Attribution is still the session that decrypted the inner
    /// message.
    ///
    /// The **key** it carries is a different matter, and not because of the signature: sealing
    /// binds it. libsignal refuses a container whose certificate names a key its sealer does
    /// not hold, and the receive path then refuses one whose key is not the key that peer's
    /// session authenticated. Between them, the account that sealed a message is the account
    /// whose session opens it.
    ///
    /// What sealing buys is who can *read* the address. Today it is seventeen cleartext bytes
    /// in every stored envelope; sealed, it is inside a ciphertext only the recipient's
    /// identity key opens. That is the property `THREAT_MODEL.md` §3.2 asks for — a seized
    /// database holds no record of who sent what — and it is the whole of what this delivers.
    /// The live relay still learns the sender from the bearer token on `POST /v1/messages`;
    /// that residual is AUDIT 3.9, not something this pretends to cover.
    ///
    /// ## The issuing keys are generated and dropped
    ///
    /// The trust root and server key exist only inside this function. Nothing persists them,
    /// so no key survives that anyone could later present as an authority — which is the
    /// honest shape for a signature that is structural rather than meaningful.
    private func selfIssuedSenderCertificate(for localAddress: PeerAddress) throws
        -> SenderCertificate {
        let identity = try store.identityKeyPair(context: NullContext())
        let identityKey = identity.identityKey.publicKey

        // Re-minted rather than repaired if any of the three facts it binds has moved. The
        // local address is write-once and the identity key lives as long as the installation,
        // so this is a restored-container guard, not an expected path.
        if let stored = try store.metadata(Self.senderCertificateKey),
           let certificate = try? SenderCertificate(stored),
           certificate.senderUuid == localAddress.serviceId.canonicalString,
           certificate.senderE164 == nil,
           certificate.deviceId == localAddress.deviceId,
           certificate.publicKey.serialize() == identityKey.serialize() {
            return certificate
        }

        let trustRoot = PrivateKey.generate()
        let serverKey = PrivateKey.generate()
        let serverCertificate = try ServerCertificate(
            keyId: 1, publicKey: serverKey.publicKey, trustRoot: trustRoot)

        let certificate = try SenderCertificate(
            sender: try SealedSenderAddress(
                // Explicitly no phone number (§0.2.7). libsignal's certificate has a field for
                // one; Cipher has never had a value to put in it, and the receive path refuses
                // a certificate that carries one so the field cannot become a channel.
                e164: nil,
                uuidString: localAddress.serviceId.canonicalString,
                deviceId: localAddress.deviceId),
            publicKey: identityKey,
            // No expiry. An expiry is a control only when something trustworthy signs the
            // certificate; nothing signs this one, so a finite value would be a date the
            // holder can reissue past at will — a control in appearance only.
            expiration: UInt64.max,
            signerCertificate: serverCertificate,
            signerKey: serverKey)

        try store.setMetadata(Self.senderCertificateKey, certificate.serialize())
        CipherLog.session.info("sealed-sender certificate minted")
        return certificate
    }

    // MARK: Receiving

    /// Decrypts a relayed envelope.
    ///
    /// The envelope's `sender` is used for exactly one thing: choosing which session to try.
    /// It is a lookup hint, not evidence. If it is wrong, the session it names cannot
    /// authenticate the ciphertext and this throws — a rewritten field costs the attacker a
    /// dropped message, never a misattributed one. Attribution in the returned value is the
    /// session that actually decrypted.
    ///
    /// ### Replays and duplicates
    ///
    /// Handled by libsignal, not here, and the two cases differ:
    ///
    /// - A **duplicate on an established session** is rejected by the ratchet's own message-
    ///   key bookkeeping: a key already used is gone, so the second copy fails to decrypt.
    /// - A **replayed session-establishing message** is rejected by the base-key witness in
    ///   `markKyberPreKeyUsed`. That check exists because a last-resort kyber prekey is not
    ///   consumed on use, so without it a captured first message could re-establish the same
    ///   session and deliver its plaintext again. The witness is a bounded FIFO and its
    ///   eviction trade-off is argued there and open as AUDIT 3.1.
    ///
    /// Neither is reported as a distinct error. A caller that could tell "replayed" from
    /// "corrupt" could be used to probe which messages a device has already seen.
    public func decrypt(_ envelopeBytes: Data) throws -> DecryptedMessage {
        try decryptMessage(envelopeBytes)
    }

    /// Decrypts and lets the caller persist the result in the same database transaction as
    /// every ratchet, prekey and trust-record mutation made by libsignal.
    ///
    /// The closure is synchronous and crypto-actor isolated so neither this connection nor the
    /// protocol store can be suspended half way through the transaction. Throwing from the
    /// closure rolls the ratchet back together with the archive write; returning commits both.
    public func withDecryptedMessageTransaction<T: Sendable>(
        _ envelopeBytes: Data,
        _ body: @CryptoActor (DecryptedMessage, SealedRowTransaction) throws -> T
    ) throws -> T {
        try requireLive()
        let database = store.appDatabase
        do {
            return try database.withTransaction {
                let decrypted = try decryptMessage(envelopeBytes)
                return try body(decrypted, SealedRowTransaction(database: database))
            }
        } catch is SealedDatabaseError {
            throw MessagingError.storeUnavailable
        }
    }

    /// A frame reduced to the Signal ciphertext a session can open, once any sealing has been
    /// removed. Modelled with a `Bool` rather than an `Envelope.PayloadType` because that enum
    /// now carries `.sealed`, which is a wrapper and not something a ratchet can decrypt —
    /// keeping it here would add a branch that cannot be reached and cannot be tested.
    private struct InboundPayload {
        /// Where to look for a session. Read out of the sealed certificate when there was
        /// one, and out of the envelope's routing field when there was not. Neither is
        /// evidence; both are hints that the ciphertext then has to justify.
        let sender: PeerAddress
        let establishesSession: Bool
        let ciphertext: Data
        /// The identity key the sealed certificate claimed, if the frame was sealed. Checked
        /// against the session's own key after decryption, never trusted in its place.
        let certificateKey: Data?
    }

    /// Removes the sealed-sender wrapper and applies every boundary refusal to what was inside.
    ///
    /// The refusals are the point. Sealing makes the payload opaque to every other layer, so a
    /// container that was opened and then handed straight to a session would be a way to reach
    /// the two payload types the wire refuses (§0.2.2 sender-key, §0.2.4 `PlaintextContent`)
    /// and the multi-device addressing wire v1 does not have (§0.2.5). Each is refused here,
    /// before any session, prekey or ratchet state is touched.
    private func openSealedContainer(_ ciphertext: Data, context: NullContext) throws
        -> InboundPayload {
        let content = try UnidentifiedSenderMessageContent(
            message: ciphertext, identityStore: store, context: context)

        guard content.groupId == nil else { throw EnvelopeError.groupMessagingNotSupported }

        let inner = try Envelope.payloadType(for: content.messageType)

        let certificate = content.senderCertificate
        guard certificate.senderE164 == nil else {
            throw EnvelopeError.sealedSenderIdentifierRefused
        }
        guard certificate.deviceId == PeerAddress.primaryDevice else {
            throw EnvelopeError.sealedSenderDeviceRefused(certificate.deviceId)
        }
        guard let aci = certificate.senderAci else {
            throw EnvelopeError.sealedSenderIdentifierRefused
        }

        return InboundPayload(
            sender: PeerAddress(serviceId: ServiceIdentifier(aci)),
            establishesSession: inner == .preKey,
            ciphertext: content.contents,
            certificateKey: certificate.publicKey.serialize())
    }

    private func decryptMessage(_ envelopeBytes: Data) throws -> DecryptedMessage {
        try requireLive()
        let localAddress = try requireLocalAddress()

        let envelope = try Envelope.decode(envelopeBytes)
        let context = NullContext()

        let payload: InboundPayload
        let plaintext: Data
        do {
            switch envelope.type {
            case .preKey, .whisper:
                // Addressed frames are still accepted so nothing in flight across the sealed
                // sender upgrade is lost. `Envelope.decode` has already refused a frame of
                // this type with no sender, so the unwrap below cannot be the thing that
                // fails; it is written as a refusal rather than a `!` because the invariant
                // lives in another file.
                guard let claimed = envelope.sender else { throw EnvelopeError.senderMissing }
                payload = InboundPayload(
                    sender: PeerAddress(serviceId: claimed),
                    establishesSession: envelope.type == .preKey,
                    ciphertext: envelope.ciphertext,
                    certificateKey: nil)
            case .sealed:
                payload = try openSealedContainer(envelope.ciphertext, context: context)
            }

            let address = try payload.sender.makeProtocolAddress()
            if payload.establishesSession {
                plaintext = try signalDecryptPreKey(
                    message: try PreKeySignalMessage(bytes: payload.ciphertext),
                    from: address, localAddress: try localAddress.makeProtocolAddress(),
                    sessionStore: store, identityStore: store,
                    preKeyStore: store, signedPreKeyStore: store,
                    kyberPreKeyStore: store, context: context)
            } else {
                guard try store.loadSession(for: address, context: context) != nil else {
                    throw MessagingError.noSession
                }
                plaintext = try signalDecrypt(
                    message: try SignalMessage(bytes: payload.ciphertext),
                    from: address, to: try localAddress.makeProtocolAddress(),
                    sessionStore: store, identityStore: store, context: context)
            }
        } catch {
            // Every local-store failure is remapped, because it is the class the caller must
            // treat differently: an envelope that failed cryptographic verification can never
            // decrypt, while one blocked by unreadable local state must stay on the relay.
            throw Self.boundaryError(error) ?? error
        }

        // The identity key the session is bound to. Read *after* decryption, so it is the key
        // that authenticated this message rather than whatever was on file beforehand.
        guard let identityKey = try store.identity(
            for: try payload.sender.makeProtocolAddress(), context: context) else {
            throw MessagingError.unattributableMessage
        }

        // A sealed container states the sender twice: once in the certificate and once in the
        // session its ciphertext decrypts under. libsignal has already tied the certificate's
        // key to whoever sealed the container, so requiring the two to agree is what makes
        // the sealer and the session owner the same account — and what stops anyone holding a
        // plaintext Signal ciphertext from re-sealing it under a name of their choosing.
        if let claimedKey = payload.certificateKey, claimedKey != identityKey.serialize() {
            throw EnvelopeError.sealedSenderKeyMismatch
        }

        return DecryptedMessage(
            sender: payload.sender,
            senderIdentityKey: identityKey.serialize(),
            plaintext: plaintext,
            claimedSender: envelope.sender,
            envelopeTimestampMs: envelope.timestamp,
            establishedSession: payload.establishesSession)
    }
}
