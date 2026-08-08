//
//  AttachmentCipher.swift
//  CipherCrypto
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import CryptoKit
import Foundation

/// Encrypts an attachment before it is uploaded, and refuses to open one that is not exactly
/// the blob the sender described (P6.S04).
///
/// ## Why an attachment is not carried in the envelope
///
/// `Envelope.maxCiphertextBytes` is 64 KiB, which no photo fits in, and the Double Ratchet is
/// the wrong tool for megabytes anyway — every message key it derives is bound to one message.
/// So an attachment travels **out of band**: the bytes go to the relay's blob store as an
/// opaque object, and the ordinary encrypted message carries the pointer and the key.
///
/// ## The relay holds only opaque blobs, and that ordering is the whole control
///
/// Encryption happens **here, before the upload**, under a key minted for this attachment and
/// nothing else. The key is never sent to the relay: it exists only inside the end-to-end
/// ciphertext of the message that points at the blob (`MessagePayload.Attachment`). A relay
/// that is seized therefore holds a directory of AES-GCM ciphertexts with no key material
/// anywhere on it, and no record of who uploaded which (`BACKEND.md` §2.8 — there is no owner
/// column, by design).
///
/// The anti-goal named in the roadmap row is "upload then encrypt", and it is not a strawman:
/// uploading first and encrypting on the way out is the shape that reads as an optimisation
/// and hands the plaintext to the host for the duration.
///
/// ## Two integrity checks, and neither is redundant
///
/// - **AES-256-GCM** is the guarantee. A single flipped bit anywhere in the blob makes `open`
///   fail; there is no path that returns partially authenticated bytes.
/// - **A SHA-256 digest of the ciphertext**, carried in the same end-to-end message, is
///   checked *before* the AEAD. It buys two things the tag alone does not. It binds the blob
///   to the message: the relay chooses what to answer a download with, and substituting a
///   different blob is caught by a comparison this device makes against a value the sender
///   authenticated, rather than by a decryption failure that could equally be corruption. And
///   it is checkable without the key, so a mismatch is settled before any key is used.
///
/// The declared plaintext length is checked twice for the same reason: it bounds the buffer
/// before decryption, and it is compared against what actually came out afterwards.
///
/// ## Not `@CryptoActor`
///
/// Deliberately, and it is the one place in this module that is not. Nothing here touches
/// libsignal, the protocol store, or any long-lived key — every value is passed in and the key
/// is generated per call — so the isolation that exists to keep the FFI on one queue would buy
/// nothing and would put multi-megabyte AES work behind the queue that the ratchet and the
/// message archive share.
public enum AttachmentCipher {

    /// The largest attachment this build will send or accept.
    ///
    /// Far below the relay's own 100 MiB ceiling (`api.MaxBlobBytes`), and that gap is
    /// deliberate rather than timid: a blob is sealed, uploaded, downloaded and opened as one
    /// buffer, so this number is also the peak memory a single attachment costs on a phone.
    /// It is enforced on the *hostile* side too — a peer naming a larger size is refused at
    /// the payload boundary before anything is fetched.
    public static let maxPlaintextBytes = 8 * 1024 * 1024

    /// AES-256.
    public static let keyBytes = 32

    /// SHA-256.
    public static let digestBytes = 32

    /// What `AES.GCM.SealedBox.combined` adds: a 12-byte nonce in front and a 16-byte tag
    /// behind. Named so the exact expected ciphertext length can be derived rather than
    /// guessed, which is what lets a download be bounded to the byte.
    public static let overheadBytes = 12 + 16

    /// The exact number of bytes a sealed attachment of `plaintextBytes` occupies.
    public static func ciphertextSize(forPlaintext plaintextBytes: Int) -> Int {
        plaintextBytes + overheadBytes
    }

    /// A sealed attachment: the bytes to upload, and everything the recipient needs to open
    /// them — which travels inside the end-to-end message, never beside the blob.
    public struct Sealed: Sendable {
        /// `nonce ‖ ciphertext ‖ tag`. This is what the relay stores, and all it stores.
        public let ciphertext: Data
        /// The one-attachment AES-256 key. Never uploaded, never logged, never reused.
        public let key: Data
        /// SHA-256 over ``ciphertext``.
        public let digest: Data
        /// Length of the original plaintext.
        public let plaintextByteCount: Int
    }

    /// Encrypts `plaintext` under a fresh random key.
    ///
    /// A new key per attachment rather than one derived from the session: the pointer already
    /// travels inside the session's ciphertext, so deriving would add a dependency on ratchet
    /// state without narrowing what an attacker holding the blob can do. It would also make
    /// the blob undecryptable after the session is reset, which is a way to lose a photo the
    /// user can still see the message for.
    public static func seal(_ plaintext: Data) throws -> Sealed {
        guard !plaintext.isEmpty else { throw AttachmentCipherError.empty }
        guard plaintext.count <= maxPlaintextBytes else {
            throw AttachmentCipherError.tooLarge(plaintext.count)
        }

        let key = SymmetricKey(size: .bits256)
        let box: AES.GCM.SealedBox
        do {
            box = try AES.GCM.seal(plaintext, using: key)
        } catch {
            throw AttachmentCipherError.notAuthentic
        }
        // `combined` is nil only for a nonce that is not 12 bytes, which the default
        // randomly-generated nonce always is. Treated as a failure rather than force-unwrapped
        // so a CryptoKit change cannot turn this into a crash on a user's device.
        guard let ciphertext = box.combined else { throw AttachmentCipherError.notAuthentic }

        return Sealed(
            ciphertext: ciphertext,
            key: key.withUnsafeBytes { Data($0) },
            digest: Data(SHA256.hash(data: ciphertext)),
            plaintextByteCount: plaintext.count)
    }

    /// Verifies `ciphertext` against `digest`, opens it under `key`, and confirms the result is
    /// exactly `plaintextByteCount` bytes.
    ///
    /// Every argument except the ciphertext comes from a message the Double Ratchet
    /// authenticated, so they are the sender's; the ciphertext comes from the relay, which is
    /// assumed hostile. The checks are ordered accordingly — the cheap comparison against the
    /// sender's digest runs first, then the AEAD, then the length.
    public static func open(
        ciphertext: Data, key: Data, digest: Data, plaintextByteCount: Int
    ) throws -> Data {
        guard key.count == keyBytes else { throw AttachmentCipherError.malformedKey }
        guard digest.count == digestBytes else { throw AttachmentCipherError.malformedDigest }
        guard plaintextByteCount > 0, plaintextByteCount <= maxPlaintextBytes else {
            throw AttachmentCipherError.tooLarge(plaintextByteCount)
        }
        // Length before hashing: a blob that cannot be the one described is refused without
        // spending SHA-256 over whatever the relay chose to send.
        guard ciphertext.count == ciphertextSize(forPlaintext: plaintextByteCount) else {
            throw AttachmentCipherError.sizeMismatch
        }

        guard constantTimeEquals(Data(SHA256.hash(data: ciphertext)), digest) else {
            throw AttachmentCipherError.digestMismatch
        }

        let plaintext: Data
        do {
            plaintext = try AES.GCM.open(
                try AES.GCM.SealedBox(combined: ciphertext), using: SymmetricKey(data: key))
        } catch {
            // Undifferentiated on purpose, exactly as the message path is: a caller that could
            // tell "wrong key" from "tampered bytes" could use this device as an oracle about
            // material it supplied.
            throw AttachmentCipherError.notAuthentic
        }

        guard plaintext.count == plaintextByteCount else {
            throw AttachmentCipherError.sizeMismatch
        }
        return plaintext
    }

    /// Compares two equal-length digests without an early exit.
    ///
    /// The digest is not a secret — both parties hold it — so this is defence in depth rather
    /// than a known vector: the attacker supplies the blob, and a comparison that returned
    /// after the first differing byte would leak how much of a forged prefix matched. GCM
    /// would still refuse the result, which is why this is cheap insurance and not the
    /// control. `count` is compared first because a length difference is not secret either.
    private static func constantTimeEquals(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for (left, right) in zip(lhs, rhs) { difference |= left ^ right }
        return difference == 0
    }
}

public enum AttachmentCipherError: Error, Equatable, Sendable {
    /// A zero-byte attachment. Refused rather than sealed: it carries nothing, and it would
    /// still cost a blob slot, a key and a message.
    case empty
    /// Larger than ``AttachmentCipher/maxPlaintextBytes``, in either direction — a local file
    /// too big to send, or a peer naming a size this build will not allocate for.
    case tooLarge(Int)
    case malformedKey
    case malformedDigest
    /// The blob is not the one the message described. The relay answered with something else,
    /// or the bytes were changed in storage.
    case digestMismatch
    /// The blob did not authenticate, or its length is not the one the sender stated.
    case sizeMismatch
    /// AES-GCM refused. Wrong key, tampered ciphertext, or truncation the length check missed
    /// — deliberately not distinguished.
    case notAuthentic
}
