//
//  ServiceIdentifier.swift
//  CipherCrypto
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import LibSignalClient

/// Who a message is addressed to or claims to be from: a UUID in one of two namespaces.
///
/// ## Why this exists rather than using libsignal's `ServiceId`
///
/// Nothing outside this module may hold a LibSignalClient type. Two separate reasons, and
/// only the first is about taste:
///
/// - **Handles.** Most libsignal types — `ProtocolAddress`, `PreKeyBundle`, `PublicKey` —
///   own a Rust pointer and are freed by a `deinit` that calls back into the FFI. Every FFI
///   call in this module is required to run on the crypto queue, and a value the UI holds
///   can be released on any thread at all. `ServiceId` happens to be plain storage today,
///   but "happens to be" is not a boundary; a type that is safe to hand out must be one
///   that *cannot* become unsafe in an upstream release.
/// - **Substitutability.** libsignal is deliberately `0.x` and promises nothing between
///   releases (AUDIT 1.4). If its types appear in this module's public signatures, every
///   bump becomes an app-wide refactor and the contract tests stop being the only place a
///   breaking change shows up.
///
/// So this is a plain value: two stored fields, no allocation, no `deinit`, `Sendable`
/// because it genuinely is.
///
/// ## Wire encoding
///
/// The 17-byte form is **libsignal's**, not ours: `[kind][16 UUID bytes]`, matching
/// `ServiceId.serviceIdFixedWidthBinary`. Keeping their layout rather than inventing one
/// means `Envelope` stays byte-compatible with anything that speaks Signal's format, and it
/// leaves exactly one thing to verify — that the two encodings still agree, which
/// `testFixedWidthLayoutMatchesLibsignal` asserts against the real library rather than
/// against a comment.
public struct ServiceIdentifier: Sendable, Hashable {

    /// Namespace. Raw values are libsignal's `ServiceIdKind` and are wire-visible: changing
    /// one silently reinterprets every stored and in-flight identifier.
    public enum Kind: UInt8, Sendable, CaseIterable {
        /// Account identifier — the long-lived identity.
        case aci = 0
        /// Phone-number identifier. Cipher never issues one (identifiers are invite codes,
        /// never phone numbers — see THREAT_MODEL.md), but the wire format must be able to
        /// represent and reject one rather than misparse it.
        case pni = 1
    }

    public static let encodedSize = 17

    public let kind: Kind
    public let uuid: UUID

    public init(kind: Kind, uuid: UUID) {
        self.kind = kind
        self.uuid = uuid
    }

    // MARK: - Fixed-width coding

    /// `[kind][16 UUID bytes]`, always exactly 17 bytes.
    public var fixedWidthBinary: Data {
        var out = Data(capacity: Self.encodedSize)
        out.append(kind.rawValue)
        withUnsafeBytes(of: uuid.uuid) { out.append(contentsOf: $0) }
        return out
    }

    /// Parses the 17-byte form, rejecting an unknown namespace rather than defaulting.
    ///
    /// An unrecognised kind byte is refused because the alternative — treating it as an ACI
    /// — would let a relay turn one identifier into a different one that this device would
    /// then treat as a known peer.
    public static func decode(fixedWidth bytes: Data) throws -> ServiceIdentifier {
        guard bytes.count == encodedSize else {
            throw EnvelopeError.invalidSender
        }
        // Index from `startIndex`: a `Data` sliced out of a larger buffer does not start at
        // zero, and assuming it does is a silent parsing bug.
        let base = bytes.startIndex

        guard let kind = Kind(rawValue: bytes[base]) else {
            throw EnvelopeError.invalidSender
        }

        var raw = uuid_t(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        _ = withUnsafeMutableBytes(of: &raw) { destination in
            bytes[(base + 1)...].copyBytes(to: destination)
        }
        return ServiceIdentifier(kind: kind, uuid: UUID(uuid: raw))
    }
}

// MARK: - libsignal bridge

/// Conversions to and from the library's own type.
///
/// `internal` on purpose: this is the seam, and the whole point of the type above is that
/// the seam has exactly one side the rest of the app can see. Nothing here may become
/// `public`, and `Scripts/verify-api-boundary.sh` fails the build if it does.
extension ServiceIdentifier {

    internal init(_ serviceId: ServiceId) {
        self.init(kind: Kind(rawValue: serviceId.kind.rawValue) ?? .aci, uuid: serviceId.rawUUID)
    }

    internal func makeServiceId() -> ServiceId {
        switch kind {
        case .aci: return Aci(fromUUID: uuid)
        case .pni: return Pni(fromUUID: uuid)
        }
    }

    /// The canonical string libsignal uses to name this identifier.
    ///
    /// Delegated rather than reimplemented. The format differs per namespace — a bare UUID
    /// for an ACI, a prefixed form for a PNI — and it is produced inside the Rust core, so
    /// hand-rolling it here would be guessing at a value that has to match byte for byte to
    /// address the right store slot. `testCanonicalStringMatchesLibsignal` pins it.
    internal var canonicalString: String {
        makeServiceId().serviceIdString
    }
}
