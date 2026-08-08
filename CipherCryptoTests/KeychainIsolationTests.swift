//
//  KeychainIsolationTests.swift
//  CipherCryptoTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//
//  AUDIT 6.18 — a test run must not be able to destroy a real installation.
//
//  The crypto tests are app-hosted (AUDIT 6.6), so they run inside the real app process and
//  reach the real Keychain through `Keychain.shared`. `MessagingFixture.tearDown` calls
//  `destroyAllState()`, which issues `SecItemDelete` across a whole service — and before this,
//  that service was the one holding the account. 6.17's guard lives in `verify-all.sh`, so a
//  direct `xcodebuild test` bypassed it. It is not hypothetical: it took the simulator
//  installation the P5.S13 field test was using.
//
//  # What can and cannot be asserted here, and why the obvious test is not written
//
//  The tempting test is a canary: write an item under the production service, run a test
//  engine's `destroyAllState`, and assert the canary survived. It is not here, and the reason
//  is the point of the finding. To *prove* it fires, the negative control has to break the
//  redirect — and a negative control for that test destroys whatever real account is on the
//  machine. A gate whose own verification is the disaster it prevents is worse than no gate
//  (AUDIT R5 is a list of self-tests that were wrong in the same way as the check).
//
//  So the guarantee is decomposed into two properties that are each safe to prove, and which
//  together give it: tests do not use the production service, and a deletion under one service
//  cannot reach another. Neither writes to the production service at any point.
//

import Foundation
import XCTest

@testable import CipherCrypto

final class KeychainIsolationTests: XCTestCase {

    /// The first half: this test run is not pointed at the account's service.
    func testTheSharedKeychainIsNotTheProductionServiceUnderTests() {
        // Pinned as a literal rather than read from the type, so a rename that pointed the
        // production service at the test one would fail here instead of quietly agreeing with
        // itself. This value is what a real installation's items are stored under; changing it
        // orphans every existing account.
        XCTAssertEqual(Keychain.productionService, "cz.janrichtermoc.Cipher.crypto")

        XCTAssertEqual(
            Keychain.shared.service, Keychain.testService,
            """
            The shared Keychain is not pointed at the test service while tests are running. \
            Every app-hosted test that opens an engine writes to whatever this names, and \
            `destroyAllState` deletes across all of it — which is how AUDIT 6.18 destroyed a \
            registered account. See Keychain.shared.
            """)

        XCTAssertNotEqual(
            Keychain.shared.service, Keychain.productionService,
            "a test run is writing to, and can delete, the production Keychain service")
    }

    /// The second half: `removeAll` is scoped to one service, so the redirect above is
    /// sufficient rather than merely different.
    ///
    /// Both services here are test-only. The property — `kSecAttrService` matches exactly, so a
    /// delete under A leaves B alone — is what makes the isolation real, and it can be proved
    /// without going anywhere near the production service.
    func testRemovingEverythingUnderOneServiceLeavesAnotherAlone() throws {
        let doomed = Keychain(service: "cz.janrichtermoc.Cipher.crypto.xctest.doomed")
        let bystander = Keychain(service: "cz.janrichtermoc.Cipher.crypto.xctest.bystander")
        addTeardownBlock {
            try? doomed.removeAll()
            try? bystander.removeAll()
        }

        _ = try doomed.addOrLoad(Data("doomed".utf8), forKey: "identity")
        _ = try bystander.addOrLoad(Data("bystander".utf8), forKey: "identity")

        // Positive control: both are really there, so the survival check below cannot pass
        // because nothing was ever stored (AUDIT R2).
        XCTAssertEqual(try doomed.load("identity"), Data("doomed".utf8))
        XCTAssertEqual(try bystander.load("identity"), Data("bystander".utf8))

        try doomed.removeAll()

        XCTAssertNil(try doomed.load("identity"), "removeAll did not clear its own service")
        XCTAssertEqual(
            try bystander.load("identity"), Data("bystander".utf8),
            """
            A removeAll under one service deleted an item stored under another. The whole \
            isolation in AUDIT 6.18 rests on kSecAttrService matching exactly; if this fails, \
            pointing tests at a different service protects nothing.
            """)
    }

    /// The public entry point an app-side test reaches for is the one that has to be covered,
    /// because that is what `MessagingFixture` calls. It takes its secrets from
    /// `Keychain.shared` and has no parameter for anything else, so the redirect is the only
    /// thing standing between it and the account — which is exactly why the redirect lives
    /// there rather than in a fixture.
    func testTheEngineOpensThroughTheSharedKeychain() async throws {
        let root = TestContainer.make()
        defer { TestContainer.remove(root) }

        let engine = try await CryptoEngine.open(container: root)
        addTeardownBlock { try? await engine.destroyAllState() }

        // It opened, and it opened against the test service: an engine holds an identity, and
        // an identity comes from `Keychain.shared`.
        _ = try await engine.localIdentityKey
        XCTAssertEqual(Keychain.shared.service, Keychain.testService)
    }
}
