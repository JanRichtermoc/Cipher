//
//  InviteCode.swift
//  Cipher
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

/// A typed invite code, normalised the way the relay normalises it.
///
/// ## Why the client parses a code it does not judge
///
/// The relay decides whether a code is *redeemable*; only it can, since that is one atomic
/// `DELETE … RETURNING` against a table this device cannot see. But `POST /v1/invite/redeem`
/// is the only per-IP rate limit the relay has (5/hour, `BACKEND.md` §5, and AUDIT 5.15 is
/// about how narrow that budget is), and redemption is the *only* flow an unauthenticated
/// install has. Spending an attempt on a string that cannot be a code — a transcription with
/// a missing symbol, a paste that picked up a stray character — costs the user one fifth of
/// their hourly budget for a request whose answer is already known. Four typos lock them out
/// of onboarding for an hour.
///
/// ## Mirrored exactly, on purpose
///
/// `server/internal/invite/code.go` is the authority for this format, and the danger of a
/// second implementation is that it drifts *stricter* and refuses a code the relay would have
/// taken — a rejection the user cannot distinguish from a bad invite. So this mirrors `Parse`
/// symbol for symbol, Crockford's transcription substitutions included, and
/// `RelayTransportTests` pins each one. Where the two could still disagree the direction is
/// safe: a code this accepts and the relay does not is an ordinary refusal.
///
/// The alphabet excludes `I`, `L`, `O` and `U`; the first three are *accepted on input* and
/// mapped to what the writer meant, which is why a mirror that merely checked "is it in the
/// alphabet" would be wrong.
nonisolated struct InviteCode: Sendable, Equatable {

    /// Crockford base32, as `code.go` defines it.
    static let alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

    /// Symbols carrying the relay's 128 bits of entropy: `(128 + 4) / 5`.
    static let length = 26

    /// The normalised form: uppercase, no separators, exactly ``length`` symbols. This is what
    /// is sent, because it is what the relay's own parser would have produced.
    let canonical: String

    /// Normalises `raw`, or returns `nil` if it cannot be a code.
    ///
    /// Deliberately not `throws`: there is one reason to refuse and no caller acts differently
    /// on a shape than on a spent code — see ``InviteRedemption/Failure/refused``.
    init?(_ raw: String) {
        var symbols = ""
        symbols.reserveCapacity(raw.count)

        for scalar in raw.trimmingCharacters(in: .whitespacesAndNewlines).unicodeScalars {
            // Separators are how the code is *shown* (groups of five) and how it gets read
            // aloud; neither carries information.
            if scalar == "-" || scalar == " " { continue }

            var symbol = Character(scalar)
            if symbol.isASCII, ("a"..."z").contains(symbol) {
                symbol = Character(String(symbol).uppercased())
            }

            // Crockford's transcription rules, applied on input only — the relay never emits
            // these, so accepting them widens what a human may type without widening the key
            // space.
            switch symbol {
            case "I", "L": symbol = "1"
            case "O": symbol = "0"
            default: break
            }

            guard Self.alphabet.contains(symbol) else { return nil }
            symbols.append(symbol)
        }

        guard symbols.count == Self.length else { return nil }
        canonical = symbols
    }
}
