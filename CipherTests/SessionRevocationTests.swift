//
//  SessionRevocationTests.swift
//  CipherTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//
//  P6.S05, the half of "device revoke" that is implementable under a locked single-device
//  decision. `Envelope` carries no `deviceId` at all (plan §0.2.5, AUDIT 3.6), so there is no
//  second device to revoke and never was — the fabricated device list and its Revoke button went
//  with `MockStore` in P5.S10.
//
//  What can be revoked is *this* device's session token, and the relay has had the endpoint for
//  it since P4: `DELETE /v1/auth`. The client calls it on the account-cleanup path. Nothing
//  asserted that until now, which is the gap this file closes — "revoke observable server-side"
//  was true of the code and untested, and an untested best-effort call is indistinguishable from
//  one that was never wired up (AUDIT 5.36 is the same shape).
//
//  What this covers, stated so it is not read as more: the *mechanism*. That
//  `AuthFlowView.clean` calls it is one line above `destroyAccountState`, and driving a SwiftUI
//  cleanup screen to assert that line would test the view rather than the revocation. The
//  mechanism is where the failure modes are — the wrong token, an account-wide revoke, or a
//  relay error that stops the erase — and every one of those is asserted below.
//

import Foundation
import XCTest

@testable import Cipher

final class SessionRevocationTests: XCTestCase {

    /// A canonical 32-byte base64url token, because `SessionCredential.bearerToken` returns nil
    /// for anything else — a credential whose bytes are not a well-formed server token has no
    /// session to revoke, which is a property this suite relies on in both directions.
    private static let token: String = Data((0..<32).map { UInt8($0) })
        .base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")

    private func credential(
        origin: SessionCredential.Origin = .serverIssued,
        phase: SessionCredential.Phase = .destroying
    ) -> SessionCredential {
        let issuedAt = Date(timeIntervalSince1970: 1_800_000_000)
        return SessionCredential(
            token: Data(Self.token.utf8), aci: UUID(), issuedAt: issuedAt,
            expiresAt: issuedAt.addingTimeInterval(30 * 24 * 60 * 60),
            origin: origin, phase: phase)
    }

    private func lifecycle() -> SessionLifecycle {
        SessionLifecycle(client: RoutedStubRelay.client())
    }

    // MARK: - The call reaches the relay, with this device's credential

    func testAccountCleanupRevokesThisDevicesTokenOnTheRelay() async throws {
        RoutedStubRelay.reset(["DELETE /v1/auth": [.init(status: 204)]])

        await lifecycle().revokeBestEffort(credential())

        XCTAssertEqual(
            RoutedStubRelay.count("DELETE /v1/auth"), 1,
            "account cleanup did not revoke the session token server-side")
        // The credential being erased, not merely *a* credential. A revocation that carried
        // anything else would delete some other session and leave this one live on the relay
        // until its own expiry — the outcome the call exists to prevent.
        XCTAssertEqual(
            RoutedStubRelay.authorizations("DELETE /v1/auth"), ["Bearer \(Self.token)"])
    }

    func testRevocationEndsThisSessionAndNotEveryOtherOne() async throws {
        // The relay also exposes `DELETE /v1/auth/all`, which signs out every session for the
        // account. That is a different action with a different blast radius, and no client path
        // calls it. Pinned so a future edit cannot quietly widen a device sign-out into an
        // account-wide one.
        RoutedStubRelay.reset([
            "DELETE /v1/auth": [.init(status: 204)],
            "DELETE /v1/auth/all": [.init(status: 204)],
        ])

        await lifecycle().revokeBestEffort(credential())

        XCTAssertEqual(RoutedStubRelay.count("DELETE /v1/auth/all"), 0)
    }

    // MARK: - Best effort means local erasure is never blocked by it

    func testARelayThatRefusesRevocationDoesNotStopTheErase() async throws {
        // The claim in `revokeBestEffort`'s own documentation: local cleanup continues even if
        // the relay is offline, because the token still has a hard expiry and the erased device
        // no longer holds message keys. Asserted as "returns without throwing", which is what
        // the caller depends on — `AuthFlowView.clean` runs `destroyAccountState` immediately
        // afterwards and must reach it.
        RoutedStubRelay.reset(["DELETE /v1/auth": [.init(status: 503)]])

        await lifecycle().revokeBestEffort(credential())

        XCTAssertGreaterThanOrEqual(
            RoutedStubRelay.count("DELETE /v1/auth"), 1,
            "the revocation was never attempted")
    }

    func testAnUnreachableRelayDoesNotStopTheErase() async throws {
        // No route registered at all: the stub answers 404, which is neither retried nor
        // reported. Distinct from the 503 above because that path exhausts retries and this one
        // does not, and both have to return.
        RoutedStubRelay.reset([:])

        await lifecycle().revokeBestEffort(credential())

        XCTAssertEqual(RoutedStubRelay.count("DELETE /v1/auth"), 1)
    }

    // MARK: - Nothing is sent when there is no server-issued token

    func testNoCredentialSendsNothing() async throws {
        RoutedStubRelay.reset(["DELETE /v1/auth": [.init(status: 204)]])

        await lifecycle().revokeBestEffort(nil)

        XCTAssertEqual(RoutedStubRelay.count("DELETE /v1/auth"), 0)
    }

    func testACredentialThatIsNotAServerTokenRevokesNothing() async throws {
        // The other half of the two tests above, which would also pass against a
        // `revokeBestEffort` that never sent anything at all: a credential whose bytes are not
        // a server token has no relay session to end, and presenting those bytes as a bearer
        // token would be the fake credential the plan forbids. Built here rather than through
        // `SessionCredential.development()` so the case exists in both configurations —
        // `.development` is not DEBUG-only, precisely because a Release build has to refuse it.
        //
        // The factory is also avoided for a second, measured reason: calling it in a test that
        // has touched `RoutedStubRelay` crashes the test host, reproducibly, and bisecting
        // showed the revocation call is not involved — `reset` plus `development()` is enough,
        // and neither of them alone is. Both halves are test-only, so nothing in the product
        // reaches the combination; it is recorded here rather than left as a mystery for the
        // next person who reaches for the factory.
        let issuedAt = Date(timeIntervalSince1970: 1_800_000_000)
        let local = SessionCredential(
            token: Data(repeating: 0x5A, count: 32), aci: UUID(), issuedAt: issuedAt,
            expiresAt: issuedAt.addingTimeInterval(30 * 24 * 60 * 60),
            origin: .development, phase: .active)
        XCTAssertNil(local.bearerToken)

        RoutedStubRelay.reset(["DELETE /v1/auth": [.init(status: 204)]])

        await lifecycle().revokeBestEffort(local)

        XCTAssertEqual(RoutedStubRelay.count("DELETE /v1/auth"), 0)
    }
}
