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
/// of calling code can see which of the two a line is using.
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
/// (P5.S12) or by sealed-sender certificates (P7), and is recorded as AUDIT 3.8 until then.
/// Callers must treat `senderIdentityKey`, not `sender`, as the thing a user verified.
public struct DecryptedMessage: Sendable, Equatable {

    /// The address whose session authenticated this ciphertext.
    public let sender: PeerAddress

    /// The peer identity key bound into that session. The value a safety number is built
    /// from, and the one to compare against a previously verified contact.
    public let senderIdentityKey: Data

    public let plaintext: Data

    /// The envelope's sender field: a routing hint, attacker-controlled, never attribution.
    /// Differs from `sender` only if something rewrote it in flight.
    public let claimedSender: ServiceIdentifier

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

    /// Maps the two library-level failures the app has to be able to name, and only those.
    ///
    /// Returns `nil` for anything else, which the caller then handles as it sees fit. Every
    /// remaining libsignal error still escapes as an opaque `Error` — that is deliberate and
    /// bounded: no caller pattern-matches one, the receive path treats any unmapped failure as
    /// permanent for that envelope, and adding a case here means adding a *behaviour* that
    /// depends on it.
    private static func boundaryError(_ error: Error) -> MessagingError? {
        if case SignalError.untrustedIdentity = error { return .identityNotAccepted }
        if let store = error as? RecordStoreError, case .ioFailure = store {
            return .storeUnavailable
        }
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
    public func encrypt(_ plaintext: Data, to peer: PeerAddress) throws -> Data {
        try requireLive()
        let localAddress = try requireLocalAddress()

        let message: CiphertextMessage
        do {
            message = try signalEncrypt(
                message: plaintext,
                for: try peer.makeProtocolAddress(),
                localAddress: try localAddress.makeProtocolAddress(),
                sessionStore: store, identityStore: store, context: NullContext())
        } catch {
            throw Self.boundaryError(error) ?? error
        }

        let ciphertext = message.serialize()
        guard ciphertext.count <= Envelope.maxCiphertextBytes else {
            // Reported against the plaintext, which is the number a caller can act on.
            throw MessagingError.messageTooLarge(plaintext.count)
        }

        return try Envelope(
            type: try Envelope.payloadType(for: message.messageType),
            sender: localAddress.serviceId,
            timestamp: now(),
            ciphertext: ciphertext
        ).encode()
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
        try requireLive()
        let localAddress = try requireLocalAddress()

        let envelope = try Envelope.decode(envelopeBytes)
        let candidate = PeerAddress(serviceId: envelope.sender)
        let address = try candidate.makeProtocolAddress()
        let context = NullContext()

        let plaintext: Data
        do {
            switch envelope.type {
            case .preKey:
                plaintext = try signalDecryptPreKey(
                    message: try PreKeySignalMessage(bytes: envelope.ciphertext),
                    from: address, localAddress: try localAddress.makeProtocolAddress(),
                    sessionStore: store, identityStore: store,
                    preKeyStore: store, signedPreKeyStore: store,
                    kyberPreKeyStore: store, context: context)
            case .whisper:
                guard try store.loadSession(for: address, context: context) != nil else {
                    throw MessagingError.noSession
                }
                plaintext = try signalDecrypt(
                    message: try SignalMessage(bytes: envelope.ciphertext),
                    from: address, to: try localAddress.makeProtocolAddress(),
                    sessionStore: store, identityStore: store, context: context)
            }
        } catch {
            // Only the container failure is remapped, because it is the only one the caller
            // must treat differently — a message that failed to decrypt can never decrypt, and
            // a message that failed to *store* is still waiting on the relay.
            throw Self.boundaryError(error) ?? error
        }

        // The identity key the session is bound to. Read *after* decryption, so it is the key
        // that authenticated this message rather than whatever was on file beforehand.
        guard let identityKey = try store.identity(for: address, context: context) else {
            throw MessagingError.unattributableMessage
        }

        return DecryptedMessage(
            sender: candidate,
            senderIdentityKey: identityKey.serialize(),
            plaintext: plaintext,
            claimedSender: envelope.sender,
            envelopeTimestampMs: envelope.timestamp,
            establishedSession: envelope.type == .preKey)
    }
}
