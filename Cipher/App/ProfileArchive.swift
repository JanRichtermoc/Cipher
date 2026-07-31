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

    /// Deletes the profile outright, for sign-out.
    ///
    /// A distinct operation rather than saving empty strings: an empty record still records that
    /// someone was here and chose nothing, and leaves a row for a future read to interpret.
    func clear() async throws {
        try await engine.removeSealedRow(
            namespace: Namespace.profile, group: Self.localGroup, ordinal: Self.singleton)
    }
}
