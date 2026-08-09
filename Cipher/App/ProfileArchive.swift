//
//  ProfileArchive.swift
//  Cipher
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import CipherCrypto
import Foundation

/// The local user's own profile fields, sealed in the crypto module's container.
///
/// ## Why these moved (AUDIT 4.7)
///
/// Display name, username and "about" lived in `UserDefaults` — a plist in the app container,
/// unencrypted, readable by anything with container access and by anyone holding an unlocked
/// device. They are not secrets, and they were never presented as protected, but they identify
/// the person using the device, which is exactly what a seized or stolen phone should not
/// volunteer. Account cleanup now removes the whole sealed store before a new account can enter,
/// so a signed-out device does not retain this row or the social graph beside it.
///
/// P5.S10 had already moved the *harder* half — the names the user gives peers, and the list of
/// who they talk to, which is the social graph — into sealed conversation records. This is the
/// remainder, and it closes 4.7.
///
/// ## Why it is one row and not three
///
/// The three fields are written together by one screen and are meaningless apart. One row means
/// one seal, one write, and no state in which the name has been updated and the username has
/// not.
actor ProfileArchive {

    private let engine: CryptoEngine

    init(engine: CryptoEngine) {
        self.engine = engine
    }

    private enum Namespace {
        static let profile = "profile"
    }

    /// There is exactly one local user, so there is exactly one group.
    private static let localGroup = "local"
    private static let singleton = 0

    nonisolated struct StoredProfile: Codable, Sendable, Equatable, SchemaVersioned {
        static let expectedSchema = 1

        var schema: Int = StoredProfile.expectedSchema
        var displayName: String
        var username: String
        var about: String
    }

    func load() async throws -> StoredProfile? {
        guard let bytes = try await engine.loadSealedRow(
            namespace: Namespace.profile, group: Self.localGroup, ordinal: Self.singleton)
        else { return nil }
        return try ArchiveCoding.decode(StoredProfile.self, from: bytes)
    }

    func save(_ profile: StoredProfile) async throws {
        try await engine.storeSealedRow(
            namespace: Namespace.profile, group: Self.localGroup, ordinal: Self.singleton,
            value: try ArchiveCoding.encode(profile))
    }

    // `clear()` was here, documented as the sign-out erase, and had no caller in the app or in
    // the tests — `ProfileStoring` does not even declare it. Sign-out erases this row by taking
    // the whole container: `AppSession.completeAccountCleanup` calls `detachProfileStorage`,
    // which only drops the handle, and `CryptoEngine.destroyAllState` is what removes the bytes
    // (proved by `ProfileStorageTests.testSigningOutClearsTheStoredProfile`). Removed 2026-08-09
    // rather than wired in: a second erase path that nothing exercises is the AUDIT 5.36 shape —
    // code that reads as live, is not, and is trusted by the next person to read it.
}

/// The narrow persistence dependency `AppSession` needs. Keeping the queue above this boundary
/// makes ordering a property of the session's mutations, not an accident of how concurrent tasks
/// happen to arrive at the archive actor or at `CryptoActor`.
protocol ProfileStoring: Sendable {
    func load() async throws -> ProfileArchive.StoredProfile?
    func save(_ profile: ProfileArchive.StoredProfile) async throws
}

extension ProfileArchive: ProfileStoring {}
