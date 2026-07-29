//
//  CertificatePinner.swift
//  Cipher
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import CryptoKit
import Foundation

/// Public-key pinning for the relay connection. **Fails closed.**
///
/// ## Pinning is *in addition to* chain validation, never instead of it
///
/// The common mistake is to treat a pin match as the whole check and hand back a credential
/// without evaluating the trust object. That accepts a certificate that is expired, revoked,
/// issued for a different hostname, or self-signed — as long as it carries the pinned key. Here
/// `SecTrustEvaluateWithError` runs **first** and a failure ends the connection; the pin is an
/// extra hurdle after the platform is already satisfied.
///
/// ## What is hashed, and the mistake that silently breaks it
///
/// The pin is SHA-256 of the DER **`SubjectPublicKeyInfo`** — the structure OpenSSL emits for
/// `openssl pkey -pubin -outform der`, which is how `docs/BACKEND.md` §9.1's table was made.
///
/// `SecKeyCopyExternalRepresentation` does **not** return that. For an elliptic-curve key it
/// returns the bare `04 ‖ X ‖ Y` point — 65 bytes for P-256 — with no algorithm identifier and
/// no ASN.1 wrapper. Hashing it directly produces a digest that will never equal the recorded
/// pin, and because the client fails closed the symptom is "nothing connects, ever", with the
/// cause invisible at the call site. The 26-byte header below is the missing `SubjectPublicKeyInfo`
/// prefix for P-256, and `CertificatePinnerTests` proves the reconstruction against the real
/// certificate rather than trusting this comment.
///
/// ## Only P-256 is supported, on purpose
///
/// Both pinned keys are P-256 and the runbook issues P-256. An unsupported key type returns
/// `nil` from ``spkiSHA256(of:)``, which fails the pin and refuses the connection — the safe
/// direction. Adding RSA headers "for completeness" would ship a code path no test exercises
/// and no deployment uses.
nonisolated struct CertificatePinner: Sendable {

    /// DER `SubjectPublicKeyInfo` prefix for `id-ecPublicKey` over `prime256v1`, up to and
    /// including the BIT STRING header:
    ///
    /// ```text
    /// SEQUENCE (0x30 0x59)
    ///   SEQUENCE (0x30 0x13)
    ///     OID 1.2.840.10045.2.1   id-ecPublicKey
    ///     OID 1.2.840.10045.3.1.7 prime256v1
    ///   BIT STRING (0x03 0x42 0x00)   66 bytes, 0 unused bits
    /// ```
    ///
    /// The 65-byte uncompressed point follows, giving 91 bytes total.
    static let p256SPKIHeader = Data([
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
        0x42, 0x00,
    ])

    /// Length of an uncompressed P-256 point: `0x04` followed by two 32-byte coordinates.
    static let p256UncompressedPointCount = 65

    /// Accepted SPKI digests. An **empty set refuses everything** — see ``evaluate(_:host:)``.
    let pinnedSPKIHashes: Set<Data>

    /// The only host these pins speak for.
    let expectedHost: String

    init(pinnedSPKIHashes: Set<Data> = RelayEndpoint.pinnedSPKIHashes,
         expectedHost: String = RelayEndpoint.host) {
        self.pinnedSPKIHashes = pinnedSPKIHashes
        self.expectedHost = expectedHost
    }

    /// Why a connection was refused. Distinguished for tests and logs, never for the user:
    /// a pinning failure is not actionable by them and the detail is reconnaissance.
    enum Failure: Error, Equatable {
        /// The challenge was for a host these pins do not cover.
        case unexpectedHost(String)
        /// No pins configured. Refusing is the only safe reading — see ``evaluate(_:host:)``.
        case noPinsConfigured
        /// The platform rejected the chain: expiry, hostname, revocation, untrusted root.
        case chainRejected
        /// The chain was fine and the key was not one of ours. The interesting one.
        case pinMismatch
        /// The leaf's public key could not be read, or is not a supported type.
        case unreadablePublicKey
    }

    /// Evaluate a server trust object. Returns the trust to use, or throws.
    ///
    /// Every path that is not an explicit success throws, so a future edit that forgets a
    /// branch fails closed rather than falling through to "allow".
    func evaluate(_ trust: SecTrust, host: String) throws -> SecTrust {
        guard host == expectedHost else {
            throw Failure.unexpectedHost(host)
        }

        // An empty pin set means the configuration is broken, not that pinning is off.
        // Treating it as "no constraint" is how a pinning bug becomes no pinning at all.
        guard !pinnedSPKIHashes.isEmpty else {
            throw Failure.noPinsConfigured
        }

        // Platform validation FIRST. Hostname is re-asserted here rather than relying on the
        // policy URLSession attached, so the check does not depend on how we were called.
        let policy = SecPolicyCreateSSL(true, expectedHost as CFString)
        guard SecTrustSetPolicies(trust, policy) == errSecSuccess else {
            throw Failure.chainRejected
        }
        guard SecTrustEvaluateWithError(trust, nil) else {
            throw Failure.chainRejected
        }

        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
              let leaf = chain.first else {
            throw Failure.unreadablePublicKey
        }

        guard let digest = Self.spkiSHA256(of: leaf) else {
            throw Failure.unreadablePublicKey
        }

        guard pinnedSPKIHashes.contains(digest) else {
            throw Failure.pinMismatch
        }

        return trust
    }

    /// SHA-256 of the certificate's DER `SubjectPublicKeyInfo`, or `nil` if it cannot be built.
    ///
    /// `nil` is a refusal, not a soft failure: every caller treats it as a pin mismatch.
    static func spkiSHA256(of certificate: SecCertificate) -> Data? {
        guard let key = SecCertificateCopyKey(certificate) else { return nil }

        guard let attributes = SecKeyCopyAttributes(key) as? [CFString: Any],
              let keyType = attributes[kSecAttrKeyType] as? String,
              keyType == (kSecAttrKeyTypeECSECPrimeRandom as String),
              let sizeInBits = attributes[kSecAttrKeySizeInBits] as? Int,
              sizeInBits == 256 else {
            // Not P-256. See the type comment: refusing beats guessing a header.
            return nil
        }

        guard let raw = SecKeyCopyExternalRepresentation(key, nil) as Data? else { return nil }

        // Uncompressed point only. A compressed point (0x02/0x03) would need a different
        // header length and is not something Security framework hands back here, but checking
        // means an unexpected encoding refuses rather than hashes the wrong bytes.
        guard raw.count == p256UncompressedPointCount, raw.first == 0x04 else { return nil }

        var spki = p256SPKIHeader
        spki.append(raw)
        return Data(SHA256.hash(data: spki))
    }
}

// MARK: - URLSession integration

/// `URLSessionDelegate` that applies ``CertificatePinner`` to every server-trust challenge.
///
/// A separate object because `URLSession` retains its delegate for the session's lifetime, and
/// because the pinner itself stays a value type that tests can exercise without a session.
nonisolated final class PinningSessionDelegate: NSObject, URLSessionDelegate, Sendable {

    private let pinner: CertificatePinner

    init(pinner: CertificatePinner = CertificatePinner()) {
        self.pinner = pinner
        super.init()
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge
    ) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {

        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust else {
            // Not our concern — but note there is no client-certificate path here, so the
            // default handling is the only correct answer rather than a fallback.
            return (.performDefaultHandling, nil)
        }

        guard let trust = challenge.protectionSpace.serverTrust else {
            return (.cancelAuthenticationChallenge, nil)
        }

        do {
            let validated = try pinner.evaluate(trust, host: challenge.protectionSpace.host)
            return (.useCredential, URLCredential(trust: validated))
        } catch {
            // Deliberately no logging of which check failed. It is not actionable by the user,
            // and on a device that may be under attack it is a signal to whoever is watching.
            return (.cancelAuthenticationChallenge, nil)
        }
    }
}
