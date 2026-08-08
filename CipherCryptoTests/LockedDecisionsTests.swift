//
//  LockedDecisionsTests.swift
//  CipherCryptoTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//
//  The seven decisions in docs/CLAUDE_IMPLEMENTATION_PLAN.md §0.2, made enforceable.
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
//  |      |                                             | + SealedSenderTests.testASealedGroupPayloadIsRefused  |
//  | 3    | Envelope.sender is untrusted routing data   | testEnvelopeSenderIsNotATrustInput (here)             |
//  | 4    | PlaintextContent refused, value 3 reserved  | testPlaintextContentStaysReservedAndNotLive (here)    |
//  |      |                                             | + EnvelopeTests.testRefusesUnauthenticatedPlaintext…  |
//  |      |                                             | + SealedSenderTests.testASealedPlaintextContent…      |
//  | 5    | Wire v1 is single-device, no deviceId       | testWireVersionOneCarriesNoDeviceId (here)            |
//  |      |                                             | + SealedSenderTests.testASealedCertificateNamingA…    |
//  | 6    | Keychain AfterFirstUnlockThisDeviceOnly     | KeychainTests.testStoredItemsAreDeviceOnlyAnd…        |
//  | 7    | Invite codes only: no phone number, email,  | testIdentityCarriesNoHumanIdentifier (here) — the     |
//  |      | server-side username or verification code   | wire half only, plus SealedSenderTests.testASealed…   |
//  |      |                                             | CertificateCarryingAPhoneNumberIsRefused for the      |
//  |      |                                             | e164 field libsignal's certificate has and Cipher     |
//  |      |                                             | never fills. The account model, the auth API and      |
//  |      |                                             | the relay schema are Go and SQL and no Swift test can |
//  |      |                                             | reach them: Scripts/verify-identity-fields.py is that |
//  |      |                                             | half, and verify-all.sh runs both.                    |
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

        // And the wire enum has no group payload type to carry one. `.sealed` (4) joined the
        // set in P7.S01 and is not a third payload: it wraps one of the other two, and what
        // it wraps goes through the same `Envelope.payloadType(for:)` refusal after the
        // container is opened — `SealedSenderTests.testASealedGroupPayloadIsRefused` is that
        // half, because sealing would otherwise hide the inner type from this check.
        XCTAssertEqual(Set(Envelope.PayloadType.allCases.map(\.rawValue)), [1, 2, 4],
                       "wire v1 carries preKey, whisper, and the sealed wrapper around them")
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

    // MARK: - §0.2.7 — identity is an invite code and an opaque ACI, nothing else

    /// Cipher collects no phone number, no email address, no server-side username and no
    /// verification code. This test pins the half of that decision which lives in this
    /// module: **the types that say who someone is carry no human-facing identifier, and
    /// the wire has no field one could travel in.**
    ///
    /// The other half — the `accounts` row, the redemption request, the relay schema — is
    /// Go and SQL and is out of reach here. `Scripts/verify-identity-fields.py` covers it,
    /// and `verify-all.sh` runs both. Neither is sufficient alone, which is why the plan
    /// names both.
    ///
    /// Reflection rather than a compile-time assertion because the failure being guarded
    /// against is *additive*: someone adds `phoneNumber` beside `uuid` and everything still
    /// compiles. `Mirror` sees stored properties, so the new field shows up here.
    func testIdentityCarriesNoHumanIdentifier() throws {
        // Every type in this module that answers "who is this". If identity ever grows a
        // new carrier, it belongs in this list — that is the maintenance cost of the
        // decision, and it is deliberate.
        let uuid = UUID(uuidString: "de305d54-75b4-431b-adb2-eb6b9e546014")!
        let identifier = ServiceIdentifier(kind: .aci, uuid: uuid)
        let carriers: [(String, Any)] = [
            ("ServiceIdentifier", identifier),
            ("PeerAddress", PeerAddress(serviceId: identifier)),
            ("Envelope", try Envelope(type: .whisper, sender: identifier, timestamp: 0,
                                      ciphertext: Data([0x01]))),
            ("PeerKeyBundle", PeerKeyBundle(
                registrationId: 1, identityKey: Data(), preKeyId: 1, preKey: Data(),
                signedPreKeyId: 2, signedPreKey: Data(), signedPreKeySignature: Data(),
                kyberPreKeyId: 3, kyberPreKey: Data(), kyberPreKeySignature: Data())),
            ("PublishedKeys.SignedKey", PublishedKeys.SignedKey(
                keyId: 1, publicKey: Data(), signature: Data())),
            ("PublishedKeys.OneTimeKey", PublishedKeys.OneTimeKey(
                keyId: 1, publicKey: Data())),
            ("PublishedKeys", PublishedKeys(
                signedPreKey: PublishedKeys.SignedKey(
                    keyId: 1, publicKey: Data(), signature: Data()),
                kyberLastResort: PublishedKeys.SignedKey(
                    keyId: 2, publicKey: Data(), signature: Data()),
                kyberPreKeys: [], oneTimePreKeys: [])),
            ("DecryptedMessage", DecryptedMessage(
                sender: PeerAddress(serviceId: identifier), senderIdentityKey: Data(),
                plaintext: Data(), claimedSender: identifier, envelopeTimestampMs: 0,
                establishedSession: true)),
        ]

        // Positive control. Every assertion below is "the name was not found", and an
        // empty Mirror produces exactly that answer while checking nothing. So first
        // prove reflection still sees properties that are definitely there. See AUDIT R2.
        //
        // A *superset* check, deliberately: asserting the set is exactly `kind` and
        // `uuid` would mean a newly added `phoneNumber` failed here first, reporting
        // "reflection is broken" for a tree in which reflection worked perfectly and
        // found a phone number. The control must not be able to pre-empt the finding it
        // exists to make believable.
        let identifierFields = Set(Mirror(reflecting: identifier).children.compactMap(\.label))
        XCTAssertTrue(
            identifierFields.isSuperset(of: ["kind", "uuid"]),
            "reflection no longer sees ServiceIdentifier's stored properties (saw "
                + "\(identifierFields.sorted())); every assertion below is void")

        // Matched on whole words so `mailbox` is not `mail` and `preKeyId` is not `key`,
        // the same rule Scripts/verify-identity-fields.py applies to the Go and SQL
        // surfaces. This list is that gate's FORBIDDEN_TOKENS plus `handle` and
        // `nickname`, which it cannot use: over there they would fire on `mux.Handle`
        // and on every SQLite handle in the tree, whereas here the entire search space
        // is the stored properties of the eight types above.
        let forbidden: Set<String> = [
            "phone", "telephone", "msisdn", "e164", "email", "mailto",
            "sms", "smtp", "otp", "username", "handle", "nickname",
        ]

        for (name, value) in carriers {
            let labels = Mirror(reflecting: value).children.compactMap(\.label)
            XCTAssertFalse(labels.isEmpty, "\(name) reflected to no stored properties")

            for label in labels {
                let words = Set(Self.identifierWords(label))
                let hit = forbidden.intersection(words)
                XCTAssertTrue(
                    hit.isEmpty,
                    """
                    \(name).\(label) is a human-facing identifier. That is a locked \
                    decision (plan §0.2.7, THREAT_MODEL.md §3.4): Cipher's only identifier \
                    is an invite code redeemed for an opaque ACI. An identifier that is \
                    never collected cannot be leaked, correlated, subpoenaed, or used to \
                    enumerate the user base, and a phone or mail flow would put an SMS or \
                    mail provider — a seizable third party — inside a design that has none.
                    """)
                XCTAssertFalse(
                    words.contains("verification") && words.contains("code"),
                    """
                    \(name).\(label) carries a verification code, which implies an \
                    out-of-band delivery channel Cipher does not have (plan §0.2.7).
                    """)
            }
        }

        // The wire identifier is a namespace byte and 16 UUID bytes, and that is all it
        // can ever be: there is no length in which a phone number or an address could
        // travel, and `decode` rejects any other size rather than reading a prefix.
        XCTAssertEqual(ServiceIdentifier.encodedSize, 1 + 16)
        XCTAssertEqual(identifier.fixedWidthBinary.count, ServiceIdentifier.encodedSize)
        XCTAssertThrowsError(
            try ServiceIdentifier.decode(
                fixedWidth: identifier.fixedWidthBinary + Data("+15551234567".utf8)),
            """
            a longer identifier now decodes. The 17-byte fixed width is what makes it \
            impossible to smuggle a human-facing identifier into an address (plan §0.2.7).
            """)
    }

    /// Splits `phoneNumber`, `phone_number` and `PHONE_NUMBER` into the same words, so a
    /// field is matched however it is spelled and `preKeyId` never reads as `key`.
    private static func identifierWords(_ name: String) -> [String] {
        var words: [String] = []
        var current = ""

        func flush() {
            if !current.isEmpty { words.append(current.lowercased()) }
            current = ""
        }

        for character in name {
            if character == "_" || character == "-" {
                flush()
            } else if character.isUppercase, !current.isEmpty,
                      current.last?.isUppercase == false {
                // camelCase boundary only: an acronym run (`ACIKind`) stays whole until a
                // lowercase letter starts the next word, which `flush` below handles.
                flush()
                current.append(character)
            } else {
                current.append(character)
            }
        }
        flush()
        return words
    }
}
