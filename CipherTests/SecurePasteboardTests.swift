//
//  SecurePasteboardTests.swift
//  CipherTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//
//  AUDIT 4.6 has been CLOSED since P3.S03, and in this ledger CLOSED means a tested control
//  exists. Nothing referenced `SecurePasteboard` from either test target, so the difference
//  between it and the `UIPasteboard.general.string = text` it replaces — the difference
//  between a decrypted message staying on this phone and being forwarded to every Mac and
//  iPad on the Apple Account — was asserted nowhere. AUDIT 6.21.
//

import UIKit
import UniformTypeIdentifiers
import XCTest

@testable import Cipher

/// `@MainActor` because `SecurePasteboard` is: the app target compiles with
/// `SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor` and this test target does not, so a type that
/// needs no annotation in `Cipher/` needs one here.
@MainActor
final class SecurePasteboardTests: XCTestCase {

    /// The option that stops Universal Clipboard. This is the whole finding: without it a
    /// message decrypted on a phone lands, over the air and within seconds, on a laptop that
    /// may be in another room or another person's house.
    func testACopiedMessageIsMarkedLocalToThisDevice() {
        let options = SecurePasteboard.options()

        XCTAssertEqual(
            options[.localOnly] as? Bool, true,
            "without .localOnly the item is forwarded by Universal Clipboard (AUDIT 4.6)")
    }

    /// And it expires. The window is bounded rather than closed — any app the user pastes into
    /// receives the text, which is what copying is — so the assertion is about the bound.
    func testACopiedMessageExpiresAfterTheStatedLifetime() {
        let now = Date(timeIntervalSince1970: 1_000_000)

        let expiry = SecurePasteboard.options(now: now)[.expirationDate] as? Date

        XCTAssertEqual(expiry, now.addingTimeInterval(SecurePasteboard.lifetime))
        XCTAssertEqual(
            SecurePasteboard.lifetime, 90,
            "the lifetime is the control; changing it is a decision, not a refactor")
    }

    /// The seam is only worth anything if the live call uses it, so this drives the real
    /// `copy` and reads the item back. It controls for one failure only — if `copy` stopped
    /// writing anything at all, the two assertions above would still pass.
    ///
    /// **It does not control for the failure the seam exists to catch.** Replacing `copy`'s
    /// body with `UIPasteboard.general.string = text` passes all three tests, because
    /// `UIPasteboard` exposes no way to read back the options an item was written with. That
    /// `copy` passes these options is established by inspection, not by assertion, and it is
    /// two lines apart in one file for that reason.
    func testCopyPutsTheTextOnThePasteboardThroughThoseOptions() {
        let unique = "cipher-pasteboard-\(UUID().uuidString)"

        SecurePasteboard.copy(unique)

        XCTAssertEqual(UIPasteboard.general.string, unique)
        // Written as a plain-text item rather than through the `.string` convenience, which is
        // the API that carries no options at all.
        XCTAssertEqual(
            UIPasteboard.general.items.first?[UTType.utf8PlainText.identifier] as? String,
            unique)
    }

    override func tearDown() {
        // A test must not leave a decrypted-looking string on the simulator's pasteboard for
        // the next one, or for whatever the developer pastes next.
        UIPasteboard.general.items = []
        super.tearDown()
    }
}
