//
//  ProfileStorageTests.swift
//  CipherTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//
//  AUDIT 4.7: the local user's display name, username and "about" used to live in
//  `UserDefaults` — a plist in the app container, unencrypted, readable by anything with
//  container access. They are not secrets, but they identify the person using the device, which
//  is what a seized or stolen phone should not volunteer. P5.S11 sealed them.
//
//  The property being pinned is not "the profile round-trips". It is that **nothing is left in
//  the plist**, including for a device upgrading from a build that put it there.
//

import CipherCrypto
import Foundation
import XCTest

@testable import Cipher

final class ProfileStorageTests: XCTestCase {

    private var container: URL!
    private var defaults: UserDefaults!
    private var suiteName: String!

    /// The three retired keys, named here rather than reached for through the type, so a rename
    /// in `AppSession` cannot silently make this test check nothing.
    private static let retiredKeys = ["cipher.displayName", "cipher.username", "cipher.about"]

    override func setUp() {
        super.setUp()
        container = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("profile-\(UUID().uuidString)", isDirectory: true)
        // A scratch suite: `UserDefaults.standard` is process-wide, so tests that shared it
        // leaked state into each other and passed or failed on run order.
        suiteName = "cipher.tests.\(UUID().uuidString)"
        defaults = UserDefaults(suiteName: suiteName)
    }

    override func tearDown() {
        defaults.removePersistentDomain(forName: suiteName)
        try? FileManager.default.removeItem(at: container)
        super.tearDown()
    }

    @MainActor
    private func makeSession() -> AppSession {
        AppSession(defaults: defaults)
    }

    // MARK: - Nothing reaches UserDefaults

    @MainActor
    func testEditingTheProfileWritesNothingToUserDefaults() async throws {
        let engine = try await CryptoEngine.open(container: container)
        let session = makeSession()
        await session.adoptProfileStorage(engine: engine)

        session.displayName = "Jan"
        session.username = "jan"
        session.about = "Reading"

        // The whole point of 4.7. A value here is the finding, whatever else works.
        for key in Self.retiredKeys {
            XCTAssertNil(
                defaults.object(forKey: key),
                "\(key) is still being written to UserDefaults")
        }
    }

    @MainActor
    func testTheProfileSurvivesARelaunch() async throws {
        let engine = try await CryptoEngine.open(container: container)

        let session = makeSession()
        await session.adoptProfileStorage(engine: engine)
        session.displayName = "Jan"
        session.username = "jan"
        session.about = "Reading"

        // The write is persisted from a detached task, so let it land before reopening. The
        // alternative — asserting immediately — is a test that passes on a fast machine.
        try await Task.sleep(for: .milliseconds(200))

        let reopened = makeSession()
        XCTAssertEqual(reopened.displayName, "You", "a fresh session starts with placeholders")
        await reopened.adoptProfileStorage(engine: engine)

        XCTAssertEqual(reopened.displayName, "Jan")
        XCTAssertEqual(reopened.username, "jan")
        XCTAssertEqual(reopened.about, "Reading")
    }

    // MARK: - Migrating a device that already has the plist values

    @MainActor
    func testValuesLeftByAnOlderBuildAreSealedAndThenRemoved() async throws {
        // Exactly what a pre-P5.S11 build left behind.
        defaults.set("Old Name", forKey: "cipher.displayName")
        defaults.set("oldname", forKey: "cipher.username")
        defaults.set("Old about", forKey: "cipher.about")

        let engine = try await CryptoEngine.open(container: container)
        let session = makeSession()
        await session.adoptProfileStorage(engine: engine)

        // Adopted, not discarded: an upgrade must not silently reset the user's own profile.
        XCTAssertEqual(session.displayName, "Old Name")
        XCTAssertEqual(session.username, "oldname")
        XCTAssertEqual(session.about, "Old about")

        // And the plist copy is gone. Leaving it would mean the unencrypted values were still
        // there for anyone reading the container — the finding would be documented as fixed and
        // still be true.
        for key in Self.retiredKeys {
            XCTAssertNil(
                defaults.object(forKey: key),
                "\(key) survived the migration, so 4.7 is not actually closed")
        }

        // The sealed copy is what a relaunch reads.
        let reopened = makeSession()
        await reopened.adoptProfileStorage(engine: engine)
        XCTAssertEqual(reopened.displayName, "Old Name")
    }

    @MainActor
    func testAPartiallyPopulatedLegacyProfileKeepsWhatWasThere() async throws {
        // A build where the user set only a display name. The other two must fall back to the
        // placeholders rather than becoming empty strings, which would render as blank rows.
        defaults.set("Only Name", forKey: "cipher.displayName")

        let engine = try await CryptoEngine.open(container: container)
        let session = makeSession()
        await session.adoptProfileStorage(engine: engine)

        XCTAssertEqual(session.displayName, "Only Name")
        XCTAssertEqual(session.username, "you")
        XCTAssertEqual(session.about, "Available")
    }

    // MARK: - Not at rest in plaintext

    @MainActor
    func testTheProfileIsNotInPlaintextInTheContainer() async throws {
        let engine = try await CryptoEngine.open(container: container)
        let session = makeSession()
        await session.adoptProfileStorage(engine: engine)

        let name = "Zdenek-Vzacny-QX7"
        session.displayName = name
        try await Task.sleep(for: .milliseconds(200))

        var bytes = Data()
        let files = FileManager.default.enumerator(at: container, includingPropertiesForKeys: nil)
        while let url = files?.nextObject() as? URL {
            var isDirectory: ObjCBool = false
            FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory)
            guard !isDirectory.boolValue else { continue }
            bytes.append(try Data(contentsOf: url))
        }

        // Positive control first: a scan that cannot find anything would pass this test against
        // an empty directory just as happily.
        let control = "control-\(UUID().uuidString)"
        try Data(control.utf8).write(to: container.appendingPathComponent("control.probe"))
        let withControl = try Data(contentsOf: container.appendingPathComponent("control.probe"))
        XCTAssertNotNil(withControl.range(of: Data(control.utf8)))

        XCTAssertNil(
            bytes.range(of: Data(name.utf8)),
            "the display name is in plaintext at rest")
    }

    // MARK: - Sign-out

    @MainActor
    func testSigningOutClearsTheStoredProfile() async throws {
        let engine = try await CryptoEngine.open(container: container)
        let session = makeSession()
        await session.adoptProfileStorage(engine: engine)
        session.displayName = "Jan"
        try await Task.sleep(for: .milliseconds(200))

        try session.signOut()
        XCTAssertEqual(session.displayName, "You")
        try await Task.sleep(for: .milliseconds(200))

        // A device that has been signed out must not still say who used it.
        let reopened = makeSession()
        await reopened.adoptProfileStorage(engine: engine)
        XCTAssertEqual(reopened.displayName, "You")
    }
}
