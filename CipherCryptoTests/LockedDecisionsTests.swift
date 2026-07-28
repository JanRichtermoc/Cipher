//
//  LockedDecisionsTests.swift
//  CipherCryptoTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//
//  The six decisions in docs/CLAUDE_IMPLEMENTATION_PLAN.md §0.2, made enforceable.
//
//  Each of those decisions looks like a bug to someone reading the code cold: refusing to
//  send while still accepting receipts, a store that implements five of libsignal's six
//  protocols, a sender field nothing validates. They are requirements, and a requirement
//  that lives only in a doc comment gets "fixed" by the next person who has not read it.
//
//  This file exists so that helpfully repairing one of them fails a test whose message says
//  why it was that way. It is a registry, not a duplicate suite: where a decision is already
//  covered behaviourally elsewhere, the entry names that test rather than re-asserting it.
//
//  | §0.2 | Decision                                    | Pinned by                                            |
//  |------|---------------------------------------------|------------------------------------------------------|
//  | 1    | Identity change: receive OK, send refused   | ProtocolStoreTests.testChangedIdentityBlocksSending…  |
//  |      | until acceptIdentity names the exact key    | …ButNotReceiving / …testAcceptingAStaleKeyIsRefused   |
//  | 2    | Groups unreachable, no SenderKeyStore       | testGroupMessagingHasNoReachableState (here)          |
//  |      |                                             | + EnvelopeTests.testRejectsSenderKeyMessages          |
//  | 3    | Envelope.sender is untrusted routing data   | testEnvelopeSenderIsNotATrustInput (here)             |
//  | 4    | PlaintextContent refused, value 3 reserved  | testPlaintextContentStaysReservedAndNotLive (here)    |
//  |      |                                             | + EnvelopeTests.testRefusesUnauthenticatedPlaintext…  |
//  | 5    | Wire v1 is single-device, no deviceId       | testWireVersionOneCarriesNoDeviceId (here)            |
//  | 6    | Keychain AfterFirstUnlockThisDeviceOnly     | KeychainTests.testStoredItemsAreDeviceOnlyAnd…        |
//

import Foundation
import LibSignalClient
import XCTest

@testable import CipherCrypto

final class LockedDecisionsTests: XCTestCase {

    // MARK: - §0.2.2 — groups have no reachable state

    /// The decision is not "groups are unimplemented" — it is that there is **no sender-key
    /// state to reach at all**. Rejecting `.senderKey` at the wire boundary is only half of
    /// that; the other half is that the protocol store must not quietly grow the
    /// conformance, because a `SenderKeyStore` that exists is a `SenderKeyStore` libsignal
    /// can call, and nothing in this project tests what it would do.
    ///
    /// Adding `SenderKeyStore` to `CipherProtocolStore` fails here, which is the intent:
    /// groups arrive in a dedicated phase, store and wire type together, with tests.
    func testGroupMessagingHasNoReachableState() {
        // Erased through `Any.Type` so the compiler cannot fold this to a constant and
        // warn — which, with warnings-as-errors on, would break the build instead of
        // running the check.
        let storeType: Any.Type = CipherProtocolStore.self

        // Positive control. A negative conformance check proves nothing unless the check
        // can still detect a conformance that *is* present: if erasure or a future runtime
        // change made `is` always false here, the assertion below would pass forever while
        // testing nothing.
        XCTAssertTrue(storeType is SessionStore.Type,
                      "the conformance check itself is broken; the assertion below is void")

        XCTAssertFalse(
            storeType is SenderKeyStore.Type,
            """
            CipherProtocolStore now conforms to SenderKeyStore. That is a locked decision \
            (plan §0.2.2, AUDIT 3.7): group messaging must not be half-enabled. Implement \
            groups as a whole phase — store, wire type, and tests — or not at all.
            """)

        // No storage slot exists for sender keys either, so there is nowhere for the state
        // to live even if a conformance were added by hand. The `session` check is the
        // positive control for the predicate.
        XCTAssertTrue(
            RecordKind.allCases.contains { $0.rawValue.localizedCaseInsensitiveContains("session") },
            "the record-kind predicate matches nothing; the assertion below is void")
        XCTAssertFalse(
            RecordKind.allCases.contains { $0.rawValue.localizedCaseInsensitiveContains("sender") },
            "a sender-key record kind appeared; see plan §0.2.2")

        // And the wire enum has no group payload type to carry one.
        XCTAssertEqual(Set(Envelope.PayloadType.allCases.map(\.rawValue)), [1, 2],
                       "wire v1 carries exactly preKey and whisper")
    }

    // MARK: - §0.2.3 — the sender field is data, not a credential

    /// `Envelope.sender` is attacker-controlled routing metadata. Authenticity comes from
    /// the ciphertext, and a decrypted message must be attributed to the session that
    /// decrypted it.
    ///
    /// The hazard this pins down is a plausible-looking "improvement": adding a check at the
    /// wire layer that the sender matches something we know. It would read as hardening and
    /// would be actively harmful — it would move an authenticity decision to the one layer
    /// that has no key with which to make it, and would make the field look trustworthy to
    /// every later caller.
    ///
    /// So: decoding must succeed for a sender this device has never heard of, must not
    /// consult any stored state, and must preserve the field verbatim. Session-bound
    /// attribution is a separate control and lands with the messaging façade (plan step 12).
    func testEnvelopeSenderIsNotATrustInput() throws {
        let ciphertext = Data([0xDE, 0xAD, 0xBE, 0xEF])
        let claimed = Aci(fromUUID: UUID(uuidString: "de305d54-75b4-431b-adb2-eb6b9e546014")!)
        let unrelated = Aci(fromUUID: UUID(uuidString: "ffffffff-ffff-4fff-bfff-ffffffffffff")!)

        // A sender with no session, no stored identity, and no relationship to this device
        // decodes exactly as readily as any other. `decode` is a static function over bytes:
        // it takes no store and no key, so there is nothing it could have checked.
        for sender in [claimed, unrelated].map(ServiceIdentifier.init) {
            let frame = try Envelope(
                type: .whisper, sender: sender, timestamp: 1, ciphertext: ciphertext).encode()
            let decoded = try Envelope.decode(frame)
            XCTAssertEqual(decoded.sender, sender,
                           "the field is carried verbatim, not validated")
            XCTAssertEqual(decoded.ciphertext, ciphertext)
        }

        // Rewriting only the sender — what a hostile relay does — leaves a well-formed frame
        // carrying the same ciphertext. That is expected: the forgery is caught when the
        // ciphertext fails to decrypt under the session, never here.
        var rewritten = try Envelope(
            type: .whisper, sender: ServiceIdentifier(claimed), timestamp: 1,
            ciphertext: ciphertext).encode()
        rewritten.replaceSubrange(2..<19, with: unrelated.serviceIdFixedWidthBinary)

        let forged = try Envelope.decode(rewritten)
        XCTAssertEqual(forged.sender, ServiceIdentifier(unrelated))
        XCTAssertEqual(forged.ciphertext, ciphertext,
                       "a relay can rewrite the sender; only the ciphertext authenticates")
    }

    // MARK: - §0.2.4 — payload type 3 stays reserved

    /// `PlaintextContent` carries `DecryptionErrorMessage`, and it is unauthenticated: it
    /// does not travel through `signalEncrypt`, so its only sender binding would be the
    /// field the previous test just showed a relay can rewrite. Accepting it would hand a
    /// malicious relay a repeatable session-reset primitive.
    ///
    /// `EnvelopeTests` covers the two live rejections. What is pinned here is the shape that
    /// makes them impossible to undo by accident: value 3 is reserved, and there is no enum
    /// case for it, so a payload type cannot be added without deliberately editing this.
    func testPlaintextContentStaysReservedAndNotLive() {
        XCTAssertEqual(Envelope.reservedPlaintextType, 3)
        XCTAssertNil(
            Envelope.PayloadType(rawValue: Envelope.reservedPlaintextType),
            """
            payload type 3 became live. It is reserved (plan §0.2.4, AUDIT 3.5): \
            DecryptionErrorMessage must travel as the plaintext of an ordinary encrypted \
            message, so the ratchet authenticates it.
            """)
        XCTAssertFalse(
            Envelope.PayloadType.allCases.contains { $0.rawValue == Envelope.reservedPlaintextType })
    }

    // MARK: - §0.2.5 — wire v1 is single-device

    /// `deviceId` is deliberately absent from the wire format. Adding it is a breaking
    /// change that requires `wireVersion` 2, and the point of this test is that it cannot be
    /// slipped in as a compatible-looking extra field.
    ///
    /// The header budget is fully consumed by the five documented fields, so there is no
    /// spare or reserved space to hide one in — any addition changes `headerSize` and fails
    /// both this and `EnvelopeTests.testEncodingMatchesTheDocumentedLayout`.
    func testWireVersionOneCarriesNoDeviceId() throws {
        XCTAssertEqual(Envelope.wireVersion, 1)

        let version = 1, type = 1, sender = 17, timestamp = 8, length = 4
        XCTAssertEqual(
            version + type + sender + timestamp + length, Envelope.headerSize,
            """
            the v1 header is exactly the five documented fields with no slack. A new field \
            — deviceId or otherwise — is a wire break and needs wireVersion 2 \
            (plan §0.2.5, AUDIT 3.6).
            """)

        // And the encoded frame is header + ciphertext with nothing between them.
        let ciphertext = Data(repeating: 0xAB, count: 9)
        let encoded = try Envelope(
            type: .preKey,
            sender: ServiceIdentifier(
                kind: .aci, uuid: UUID(uuidString: "de305d54-75b4-431b-adb2-eb6b9e546014")!),
            timestamp: 0, ciphertext: ciphertext).encode()
        XCTAssertEqual(encoded.count, Envelope.headerSize + ciphertext.count)
    }
}
