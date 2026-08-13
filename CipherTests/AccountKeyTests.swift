//
//  AccountKeyTests.swift
//  CipherTests
//
//  AUDIT 5.41 — the device's re-authentication key.
//

import CryptoKit
import XCTest

@testable import Cipher

final class AccountKeyTests: XCTestCase {

    /// A scratch service, so nothing here can touch a real installation's key. The same
    /// separation `SessionCredentialTests` keeps for the session item.
    private func makeStore() -> AccountKey {
        AccountKey(service: "cz.janrichtermoc.Cipher.accountkey.tests.\(UUID().uuidString)")
    }

    func testEnsureCreatesOnceAndIsIdempotent() throws {
        let store = makeStore()
        defer { try? store.clear() }

        let first = try store.ensure()
        let second = try store.ensure()
        XCTAssertEqual(
            first.publicKey.rawRepresentation, second.publicKey.rawRepresentation,
            "a second ensure() must return the same key: the relay refuses to replace a "
                + "published one, so minting a new key locks this device out of reconnecting")
    }

    func testTheKeySurvivesRestart() throws {
        let service = "cz.janrichtermoc.Cipher.accountkey.tests.\(UUID().uuidString)"
        let store = AccountKey(service: service)
        defer { try? store.clear() }
        let created = try store.ensure()

        let reopened = AccountKey(service: service)
        XCTAssertEqual(
            reopened.current()?.publicKey.rawRepresentation,
            created.publicKey.rawRepresentation)
    }

    func testClearRemovesTheKey() throws {
        let store = makeStore()
        _ = try store.ensure()
        try store.clear()
        XCTAssertNil(store.current(), "erasure must take the account key with the account")
        XCTAssertNoThrow(try store.clear(), "clearing twice is not an error")
    }

    /// The signature must verify against the published public half — the exact check the
    /// relay performs with `crypto/ed25519`.
    func testASignatureVerifiesAgainstThePublishedKey() throws {
        let store = makeStore()
        defer { try? store.clear() }
        let key = try store.ensure()
        let aci = UUID()
        let challenge = "Zm9vYmFyYmF6"

        let signature = try store.sign(aci: aci, challenge: challenge)
        let raw = try XCTUnwrap(Data(base64Encoded: signature))
        XCTAssertTrue(
            key.publicKey.isValidSignature(
                raw, for: AccountKey.signingPayload(aci: aci, challenge: challenge)))
    }

    /// **The trap this test exists for.** Swift's `UUID.uuidString` is UPPERCASE and Go's
    /// `uuid.UUID.String()` is lowercase, so a payload built from the raw Swift value would
    /// differ from the relay's by case alone — every signature would verify locally and be
    /// refused in production, which is the worst possible place to find it.
    func testTheSigningPayloadUsesTheRelaysLowercaseFormatting() throws {
        let aci = try XCTUnwrap(UUID(uuidString: "3F2B8C14-0000-4000-8000-ABCDEFABCDEF"))
        let payload = AccountKey.signingPayload(aci: aci, challenge: "abc")
        let text = try XCTUnwrap(String(data: payload, encoding: .utf8))

        XCTAssertEqual(text, "cipher-reauth-v1:3f2b8c14-0000-4000-8000-abcdefabcdef:abc")
        XCTAssertFalse(text.contains("3F2B8C14"), "the relay formats a UUID in lowercase")
    }

    /// Domain separation, and the reason the context string is not decoration: the same key
    /// signing a bare challenge elsewhere must not produce a valid re-authentication.
    func testTheContextIsPartOfWhatIsSigned() throws {
        let store = makeStore()
        defer { try? store.clear() }
        let key = try store.ensure()
        let aci = UUID()
        let challenge = "Zm9vYmFy"

        let bare = try key.signature(for: Data(challenge.utf8))
        XCTAssertFalse(
            key.publicKey.isValidSignature(
                bare, for: AccountKey.signingPayload(aci: aci, challenge: challenge)),
            "a signature over the challenge alone must not authenticate")
    }

    /// A signature is bound to the account it authenticates, so one minted for A cannot be
    /// presented as B even if a challenge ever escaped its namespace.
    func testASignatureIsBoundToItsAccount() throws {
        let store = makeStore()
        defer { try? store.clear() }
        let key = try store.ensure()
        let challenge = "Zm9vYmFy"
        let mine = UUID()
        let other = UUID()

        let signature = try store.sign(aci: mine, challenge: challenge)
        let raw = try XCTUnwrap(Data(base64Encoded: signature))
        XCTAssertFalse(
            key.publicKey.isValidSignature(
                raw, for: AccountKey.signingPayload(aci: other, challenge: challenge)),
            "a signature for one account must not verify for another")
    }

    func testThePublicHalfIsThirtyTwoBytes() throws {
        let store = makeStore()
        defer { try? store.clear() }
        let key = try store.ensure()
        let encoded = AccountKey.publicKeyBase64(key)
        let raw = try XCTUnwrap(Data(base64Encoded: encoded))
        XCTAssertEqual(raw.count, 32, "an Ed25519 public key is 32 bytes")
        XCTAssertEqual(raw, key.publicKey.rawRepresentation)
        XCTAssertNotEqual(
            raw, key.rawRepresentation,
            "the value published to the relay must never be the private half")
    }
}
