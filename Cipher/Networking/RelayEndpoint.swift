//
//  RelayEndpoint.swift
//  Cipher
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

/// Where the relay is, and which public keys are allowed to answer for it.
///
/// ## The pins are the security boundary, not the URL
///
/// `docs/BACKEND.md` §9.1 is the authority for these values and explains the rotation
/// procedure. Two properties of that section matter to anyone editing this file:
///
/// 1. **Exactly the keys marked `**YES**` in §9.1 belong here.** The intermediate and root
///    SPKIs are recorded there deliberately *so that nobody re-adds them by reflex*. A pin set
///    is only as strong as its weakest accepted pin, and accepting Let's Encrypt's intermediate
///    accepts any certificate LE issues for this host — which anyone who can pass ACME
///    validation can obtain, meaning anyone who controls DNS or the host. That is precisely
///    `THREAT_MODEL.md` §1.1 and §1.3, so pinning the intermediate would stop none of the
///    adversaries pinning exists for while reducing the control to "must be a Let's Encrypt
///    certificate", which ordinary chain validation already provides.
///
/// 2. **Two pins, one of them a key not currently in use.** One pin plus one lost key is a
///    permanently bricked client — every installed app fails closed against a host that cannot
///    present the pinned key, and there is no server-side remedy because the clients are
///    already shipped. `backupKey` is that spare.
///
/// `Scripts/verify-pins.sh` checks these constants against §9.1 *and* against the key the live
/// host actually serves, because the failure mode is silent until the certificate renews.
nonisolated enum RelayEndpoint {

    /// The API host. Also the name the pinner requires the challenge to be for.
    static let host = "relay.mgchatman.app"

    /// Base URL. `https` is not a preference — see ``baseURL`` and ``AllowedScheme``.
    static let baseURL = URL(string: "https://\(host)")!

    /// SHA-256 of the DER `SubjectPublicKeyInfo`, base64 — the same value
    /// `openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256`
    /// produces, which is how §9.1's table was generated.
    ///
    /// Recorded 2026-07-29. Both are ECDSA P-256 and both are **public values**: an SPKI hash
    /// is derived from a public key that appears in the certificate, so shipping them in the
    /// binary discloses nothing an observer of the TLS handshake does not already have.
    enum PinnedKey {
        /// The key the staging leaf currently uses. Stable across renewals because certbot is
        /// configured with `reuse_key` — without that it would rotate roughly every 60 days
        /// and break every installed client.
        static let currentLeaf = "MRFmm9ckpODEhUXZfYHbhMzIsxiCDsBJD/HwOy/rQBM="

        /// Generated 2026-07-29 and deliberately **not yet in use**. This is the key an
        /// emergency reissue switches to, and because it is already pinned that switch needs
        /// no client release. See §9.1, "Emergency: the leaf key is compromised".
        static let backupKey = "+qAajv1/B4owz+yao2g3R3lSNjD7qPN3eR3JXwA5FCY="
    }

    /// The pin set, decoded once.
    ///
    /// A malformed constant is a programmer error that must not degrade into "no pinning":
    /// silently dropping an undecodable pin would shrink the set, and shrinking it to empty
    /// would disable the control entirely while every request still succeeded. So decoding
    /// failure traps in debug and yields an empty set in release — and an empty set makes
    /// ``CertificatePinner`` refuse every connection rather than accept any.
    static let pinnedSPKIHashes: Set<Data> = {
        let encoded = [PinnedKey.currentLeaf, PinnedKey.backupKey]
        var decoded = Set<Data>()
        for value in encoded {
            guard let data = Data(base64Encoded: value), data.count == 32 else {
                assertionFailure("RelayEndpoint pin \(value) is not a base64 SHA-256")
                continue
            }
            decoded.insert(data)
        }
        assert(decoded.count == encoded.count, "a pin was dropped while decoding")
        return decoded
    }()
}
