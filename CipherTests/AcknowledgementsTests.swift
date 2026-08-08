//
//  AcknowledgementsTests.swift
//  CipherTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//
//  P8.S07 — AUDIT 6.2, and `NOTICE.md` obligation 3.
//
//  libsignal is AGPL-3.0. Surfacing its acknowledgements is a licence term, so what is
//  asserted here is not that a screen exists but that the licence text is **in the app
//  bundle and reachable at runtime** — the two ways this obligation actually fails are a
//  resource that never shipped and a parser that quietly returns nothing.
//
//  `Scripts/verify-acknowledgements.sh` covers the other half, which no test in the app can
//  see: that the shipped copy still matches what CocoaPods generated, so a pod update cannot
//  leave the previous licence on the screen.
//

import XCTest

@testable import Cipher

final class AcknowledgementsTests: XCTestCase {

    /// The resource has to be in the bundle. It lives outside `Pods/` precisely because
    /// nothing under `Pods/` ships, and a file the app cannot read at runtime discharges
    /// nothing.
    func testTheAcknowledgementsResourceShipsInTheBundle() throws {
        let url = Bundle.main.url(forResource: "Acknowledgements", withExtension: "plist")
        XCTAssertNotNil(
            url,
            """
            Acknowledgements.plist is not in the app bundle. libsignal is AGPL-3.0 and \
            NOTICE.md obligation 3 requires its acknowledgements to be surfaced in the app; \
            a resource that did not ship cannot be rendered. See AUDIT 6.2.
            """)
    }

    /// The parser must return the library, and with its licence attached.
    func testLibsignalsLicenceIsReadableAtRuntime() throws {
        let libraries = Acknowledgement.load()
        XCTAssertFalse(
            libraries.isEmpty,
            "the acknowledgements parsed to nothing, which renders an empty screen")

        let libsignal = try XCTUnwrap(
            libraries.first { $0.name == "LibSignalClient" },
            "LibSignalClient is absent from the acknowledgements: \(libraries.map(\.name))")

        XCTAssertTrue(
            libsignal.licence.contains("GNU AFFERO GENERAL PUBLIC LICENSE"),
            "the entry exists but does not carry the AGPL text")

        // A title with a fragment under it is the failure that looks like success, so the
        // length is asserted rather than only the marker. The real licence is ~34 KB.
        XCTAssertGreaterThan(
            libsignal.licence.count, 10_000,
            "the licence body is truncated; obligation 3 is to surface the licence, not its title")
    }

    /// CocoaPods brackets the list with a header sentence and its own attribution. Neither is
    /// a library, and rendering them as sections would put "Acknowledgements" and an empty
    /// name in a list of licences.
    func testTheGeneratedHeaderAndFooterAreNotRenderedAsLibraries() {
        let names = Acknowledgement.load().map(\.name)

        XCTAssertFalse(names.contains("Acknowledgements"), "the header is being shown as a library")
        XCTAssertFalse(names.contains(""), "the footer is being shown as a library")

        // Positive control: something survived the filtering, so the two assertions above
        // are not passing because everything was dropped (AUDIT R2).
        XCTAssertFalse(names.isEmpty, "the filter removed every entry; the checks above are void")
    }
}
