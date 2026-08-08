//
//  AttachmentCipherTests.swift
//  CipherCryptoTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//
//  P6.S04. An attachment travels out of band, so the bytes on the relay are the only thing an
//  adversary who seizes it holds — and the ciphertext this file produces is what has to be
//  worthless to them. Every refusal below is a hostile input: the blob comes from the relay,
//  and only the key, digest and length come from the authenticated message.
//

import CryptoKit
import Foundation
import XCTest

@testable import CipherCrypto

final class AttachmentCipherTests: XCTestCase {

    private let plaintext = Data("the whole point is that this never reaches the relay".utf8)

    // MARK: - Round trip

    func testSealedBytesOpenBackToExactlyWhatWentIn() throws {
        let sealed = try AttachmentCipher.seal(plaintext)
        let opened = try AttachmentCipher.open(
            ciphertext: sealed.ciphertext, key: sealed.key, digest: sealed.digest,
            plaintextByteCount: sealed.plaintextByteCount)
        XCTAssertEqual(opened, plaintext)
    }

    func testTheCiphertextIsNotThePlaintextAndDoesNotContainIt() throws {
        // The step's anti-goal is "upload then encrypt". This is the property that ordering
        // would break, asserted against the bytes rather than against the call order.
        let sealed = try AttachmentCipher.seal(plaintext)
        XCTAssertNotEqual(sealed.ciphertext, plaintext)
        XCTAssertNil(sealed.ciphertext.range(of: plaintext))
        XCTAssertEqual(
            sealed.ciphertext.count,
            AttachmentCipher.ciphertextSize(forPlaintext: plaintext.count))
        XCTAssertEqual(sealed.plaintextByteCount, plaintext.count)
    }

    func testEveryAttachmentGetsItsOwnKeyAndItsOwnCiphertext() throws {
        let first = try AttachmentCipher.seal(plaintext)
        let second = try AttachmentCipher.seal(plaintext)

        // A key per attachment is what keeps one recovered key from opening the rest, and a
        // fresh nonce is what keeps two sends of the same photo from being visibly the same
        // object on the relay.
        XCTAssertNotEqual(first.key, second.key)
        XCTAssertNotEqual(first.ciphertext, second.ciphertext)
        XCTAssertNotEqual(first.digest, second.digest)
    }

    func testTheDigestIsOverTheCiphertextTheRelayWouldStore() throws {
        // Not over the plaintext, which would hand anyone holding the blob a way to confirm a
        // guess about its contents without the key.
        let sealed = try AttachmentCipher.seal(plaintext)
        XCTAssertEqual(sealed.digest, Data(SHA256.hash(data: sealed.ciphertext)))
        XCTAssertNotEqual(sealed.digest, Data(SHA256.hash(data: plaintext)))
    }

    // MARK: - Refusals

    func testAnotherAttachmentsKeyDoesNotOpenThisOne() throws {
        let sealed = try AttachmentCipher.seal(plaintext)
        let other = try AttachmentCipher.seal(plaintext)

        XCTAssertThrowsError(
            try AttachmentCipher.open(
                ciphertext: sealed.ciphertext, key: other.key, digest: sealed.digest,
                plaintextByteCount: sealed.plaintextByteCount)
        ) { error in
            XCTAssertEqual(error as? AttachmentCipherError, .notAuthentic)
        }
    }

    func testASubstitutedBlobIsCaughtByTheDigestBeforeTheKeyIsUsed() throws {
        // The relay chooses what to answer a download with. Substituting a *different, valid*
        // blob of the same length is the case AES-GCM alone would report as "wrong key" and
        // the digest reports as what it is: not the object the message named.
        let sealed = try AttachmentCipher.seal(plaintext)
        let substitute = try AttachmentCipher.seal(plaintext)

        XCTAssertThrowsError(
            try AttachmentCipher.open(
                ciphertext: substitute.ciphertext, key: sealed.key, digest: sealed.digest,
                plaintextByteCount: sealed.plaintextByteCount)
        ) { error in
            XCTAssertEqual(error as? AttachmentCipherError, .digestMismatch)
        }
    }

    func testOneFlippedBitAnywhereIsRefused() throws {
        let sealed = try AttachmentCipher.seal(plaintext)

        // Every region of the combined box: the nonce, the body, and the tag.
        for offset in [0, sealed.ciphertext.count / 2, sealed.ciphertext.count - 1] {
            var tampered = sealed.ciphertext
            tampered[tampered.startIndex + offset] ^= 0x01

            XCTAssertThrowsError(
                try AttachmentCipher.open(
                    ciphertext: tampered, key: sealed.key, digest: sealed.digest,
                    plaintextByteCount: sealed.plaintextByteCount)
            ) { error in
                XCTAssertEqual(
                    error as? AttachmentCipherError, .digestMismatch,
                    "a changed byte at \(offset) was not refused")
            }

            // And with the digest recomputed over the tampered bytes — the case a relay that
            // could also rewrite the message would need, which the AEAD is what refuses.
            XCTAssertThrowsError(
                try AttachmentCipher.open(
                    ciphertext: tampered, key: sealed.key,
                    digest: Data(SHA256.hash(data: tampered)),
                    plaintextByteCount: sealed.plaintextByteCount)
            ) { error in
                XCTAssertEqual(error as? AttachmentCipherError, .notAuthentic)
            }
        }
    }

    func testALengthThatIsNotTheOneTheSenderStatedIsRefused() throws {
        let sealed = try AttachmentCipher.seal(plaintext)

        XCTAssertThrowsError(
            try AttachmentCipher.open(
                ciphertext: sealed.ciphertext, key: sealed.key, digest: sealed.digest,
                plaintextByteCount: sealed.plaintextByteCount - 1)
        ) { error in
            XCTAssertEqual(error as? AttachmentCipherError, .sizeMismatch)
        }

        XCTAssertThrowsError(
            try AttachmentCipher.open(
                ciphertext: sealed.ciphertext.dropLast(), key: sealed.key,
                digest: sealed.digest, plaintextByteCount: sealed.plaintextByteCount)
        ) { error in
            XCTAssertEqual(error as? AttachmentCipherError, .sizeMismatch)
        }
    }

    func testAMalformedKeyOrDigestIsRefusedBeforeAnythingIsRead() throws {
        let sealed = try AttachmentCipher.seal(plaintext)

        XCTAssertThrowsError(
            try AttachmentCipher.open(
                ciphertext: sealed.ciphertext, key: Data(repeating: 7, count: 16),
                digest: sealed.digest, plaintextByteCount: sealed.plaintextByteCount)
        ) { error in
            XCTAssertEqual(error as? AttachmentCipherError, .malformedKey)
        }

        XCTAssertThrowsError(
            try AttachmentCipher.open(
                ciphertext: sealed.ciphertext, key: sealed.key,
                digest: Data(repeating: 7, count: 8),
                plaintextByteCount: sealed.plaintextByteCount)
        ) { error in
            XCTAssertEqual(error as? AttachmentCipherError, .malformedDigest)
        }
    }

    func testTheSizeBoundIsEnforcedInBothDirections() throws {
        XCTAssertThrowsError(try AttachmentCipher.seal(Data())) { error in
            XCTAssertEqual(error as? AttachmentCipherError, .empty)
        }

        // Sealing something larger than the ceiling, and — the half that matters — a peer
        // naming a length this device would otherwise allocate for.
        let oversize = AttachmentCipher.maxPlaintextBytes + 1
        XCTAssertThrowsError(
            try AttachmentCipher.seal(Data(repeating: 0, count: oversize))
        ) { error in
            XCTAssertEqual(error as? AttachmentCipherError, .tooLarge(oversize))
        }
        XCTAssertThrowsError(
            try AttachmentCipher.open(
                ciphertext: Data(repeating: 0, count: 64),
                key: Data(repeating: 1, count: AttachmentCipher.keyBytes),
                digest: Data(repeating: 2, count: AttachmentCipher.digestBytes),
                plaintextByteCount: oversize)
        ) { error in
            XCTAssertEqual(error as? AttachmentCipherError, .tooLarge(oversize))
        }
    }
}
