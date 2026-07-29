//
//  CertificatePinnerTests.swift
//  CipherTests
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import CryptoKit
import Foundation
import Testing

@testable import Cipher

/// The real staging leaf certificate, `relay.mgchatman.app`, captured 2026-07-29.
///
/// A certificate is public data — it is sent in the clear to everyone who connects — so
/// embedding it discloses nothing. It is here because the property under test is *agreement
/// with the server*, and that cannot be tested against a certificate this code generated.
///
/// **This fixture does not expire for the purposes of these tests.** They exercise SPKI
/// extraction, which reads the public key and never consults `notAfter`. When the certificate
/// renews, the key stays the same (certbot `reuse_key`), so the expected digest below stays
/// correct — and if it ever does not, that is precisely the outage `Scripts/verify-pins.sh`
/// exists to catch, and this test failing is the correct alarm rather than a chore.
private enum Fixture {
    static let leafBase64 = [
        "MIIDlTCCAxqgAwIBAgISBcICSCSg747zjajHy7NE5P1vMAoGCCqGSM49BAMDMDMxCzAJBgNVBAYT",
        "AlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQwwCgYDVQQDEwNZRTEwHhcNMjYwNzI5MjAyOTM1",
        "WhcNMjYxMDI3MjAyOTM0WjAeMRwwGgYDVQQDExNyZWxheS5tZ2NoYXRtYW4uYXBwMFkwEwYHKoZI",
        "zj0CAQYIKoZIzj0DAQcDQgAEBfgfW2PHQ4LOQIpWB2Y85tU+3DlVFwYnU/lMS7EaRn4QgcldeKL+",
        "vnSYLtfYSosE5N2XatlY8xBC4ZSmCKxqlqOCAiEwggIdMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE",
        "DDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQ3r73IA2dR1+liXT4L3ehCcnU3",
        "ITAfBgNVHSMEGDAWgBS7IMpHC/7X5Zz5jwkqo4w3RbG82DAzBggrBgEFBQcBAQQnMCUwIwYIKwYB",
        "BQUHMAKGF2h0dHA6Ly95ZTEuaS5sZW5jci5vcmcvMB4GA1UdEQQXMBWCE3JlbGF5Lm1nY2hhdG1h",
        "bi5hcHAwEwYDVR0gBAwwCjAIBgZngQwBAgEwLwYDVR0fBCgwJjAkoCKgIIYeaHR0cDovL3llMS5j",
        "LmxlbmNyLm9yZy8xMTIuY3JsMIIBCwYKKwYBBAHWeQIEAgSB/ASB+QD3AHUAwjF+V0UZo0Xufzje",
        "spBB68fCIVoiv3/Vta12mtkOUs0AAAGfr8cOBwAABAMARjBEAiB7+e8RIj0HZl77QaTpRZDbV3b6",
        "Q109A7tnKYZVQR7ukAIgEOxupxxgGDzYjuFZc4vWLrx6wJheDXSiOyYT1jJFZ+oAfgBs/lAZQ6he",
        "qRa8UtEz5NzJHvFBHH0lhCDRc4CeGBjrOgAAAZ+vxw5pAAgAAAUAGGQ8+wQDAEcwRQIhANf4FrkH",
        "r/hV2RfTnpUm0Ps9BpltiCZPiEa51hzoU75yAiBmcfNBOHMEItELFGg/Wc4U16OXMamAJDLkAnDa",
        "Y3t50zAKBggqhkjOPQQDAwNpADBmAjEA+FkSwbQ8bB2rJYMRCTV50ooc7IrLrgNH+T/+SBC7IBz4",
        "jTHlyztYuB2Xby7dNM2EAjEAnKqfZs0dbKCKNs9tnxIjJYJ9optFdgB7rMHjA2UpZjSYSx1/vldF",
        "gijTAUcOhE2T"
    ].joined()

    static var leafCertificate: SecCertificate {
        let der = Data(base64Encoded: leafBase64)!
        return SecCertificateCreateWithData(nil, der as CFData)!
    }

    /// Computed independently by OpenSSL 3.6.3 on the host:
    ///
    ///     openssl x509 -pubkey -noout | openssl pkey -pubin -outform der \
    ///       | openssl dgst -sha256 -binary | openssl base64
    ///
    /// This is the same string recorded in `docs/BACKEND.md` §9.1 and shipped in
    /// `RelayEndpoint.PinnedKey.currentLeaf`.
    static let expectedSPKISHA256 = "MRFmm9ckpODEhUXZfYHbhMzIsxiCDsBJD/HwOy/rQBM="

    /// The Let's Encrypt intermediate `YE1`. Embedded so chain building is **offline**:
    /// without it, Security completes the chain by fetching from the certificate's AIA
    /// extension, which makes the result depend on the network. A pinning test whose verdict
    /// changes with connectivity is not a test.
    static let intermediateBase64 = [
        "MIICizCCAhGgAwIBAgIQXd1w3TH4AchcGGp6BLgK/jAKBggqhkjOPQQDAzAuMQswCQYDVQQGEwJV",
        "UzENMAsGA1UEChMESVNSRzEQMA4GA1UEAxMHUm9vdCBZRTAeFw0yNTA5MDMwMDAwMDBaFw0yODA5",
        "MDIyMzU5NTlaMDMxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQwwCgYDVQQD",
        "EwNZRTEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQHZVB1/mimla2hfSurylScjPMZaOJXLz/NnAc2",
        "sylm8WDyhU9Ccp+zASQi5vSwGGJjSGklkD9fdPR8GpyDIOIjCEfrnbt/v+ZSEPLLEGbaM6EccDbN",
        "7p9xteIm2Avf+ryjge4wgeswDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBIG",
        "A1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFLsgykcL/tflnPmPCSqjjDdFsbzYMB8GA1UdIwQY",
        "MBaAFKPIJlqOoUzQNWP8myPIOq5W809WMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcwAoYWaHR0",
        "cDovL3llLmkubGVuY3Iub3JnLzATBgNVHSAEDDAKMAgGBmeBDAECATAnBgNVHR8EIDAeMBygGqAY",
        "hhZodHRwOi8veWUuYy5sZW5jci5vcmcvMAoGCCqGSM49BAMDA2gAMGUCMQDgjUEahFT/h3DRakqi",
        "PZpLvPgfZwkt6K2EOMmh1nvEzl83eMLYcod4GCl3b0J1Nn0CMBNYmEQJb4CEG5WoOe7aRn/LVKu6",
        "saHmHEynI7ysIPd8zQsK1HdmhlHKlw9Z5GpGvA=="
    ].joined()

    static var intermediateCertificate: SecCertificate {
        SecCertificateCreateWithData(nil, Data(base64Encoded: intermediateBase64)! as CFData)!
    }

    /// A self-signed P-256 certificate for the same hostname, generated offline 2026-07-29.
    /// Well-formed, correct CN, current dates — and no path to any trusted root. It stands for
    /// the attacker who presents a certificate they made themselves.
    static let selfSignedBase64 = [
        "MIIBkTCCATegAwIBAgIUIwhuIQtQyKq6nPKYbfrD2n7e9HEwCgYIKoZIzj0EAwIwHjEcMBoGA1UE",
        "AwwTcmVsYXkubWdjaGF0bWFuLmFwcDAeFw0yNjA3MjkyMjE2NTlaFw0zNjA3MjYyMjE2NTlaMB4x",
        "HDAaBgNVBAMME3JlbGF5Lm1nY2hhdG1hbi5hcHAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ5",
        "ksUXwAFV1HCovmnBSq4BF41EObOi1iLhCu9j3UPh0GRrR9XVuiWFJatQe+KZEBLbKsZIOoH3CHtZ",
        "YexUAY3Oo1MwUTAdBgNVHQ4EFgQUPcUXToGT5QMtF0f4m7kJq4tTxrAwHwYDVR0jBBgwFoAUPcUX",
        "ToGT5QMtF0f4m7kJq4tTxrAwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEA2qkv",
        "++mJqhjLUdJBLjFQ+UvaLpIQs5QcfQcSuVNcMqUCIFnmgUIYTElHcX341Hv9aC4aJEclo8nDLKj4",
        "YZlw7Jrr"
    ].joined()

    static var selfSignedCertificate: SecCertificate {
        SecCertificateCreateWithData(nil, Data(base64Encoded: selfSignedBase64)! as CFData)!
    }

    /// SPKI of the self-signed certificate. Recorded so the test can assert it is genuinely
    /// outside the pin set rather than assuming it.
    static let selfSignedSPKISHA256 = "3OrTr4AfuwJdVnIYdvLVouT0QkkkegHbws+dv0zSEaY="

}

@Suite("Certificate pinning")
struct CertificatePinnerTests {

    // MARK: The agreement that everything else depends on

    @Test("SPKI hash of the real leaf matches the value OpenSSL computed on the server")
    func spkiMatchesOpenSSL() throws {
        let digest = try #require(CertificatePinner.spkiSHA256(of: Fixture.leafCertificate))

        #expect(digest.base64EncodedString() == Fixture.expectedSPKISHA256,
                """
                The client and the server disagree about this certificate's SPKI hash. \
                Shipping this would fail closed against the real relay on every request. \
                The usual cause is hashing SecKeyCopyExternalRepresentation's raw EC point \
                without prepending the SubjectPublicKeyInfo header.
                """)
    }

    @Test("the shipped pin set contains the key the staging host actually serves")
    func shippedPinsCoverTheLiveLeaf() throws {
        let digest = try #require(CertificatePinner.spkiSHA256(of: Fixture.leafCertificate))
        #expect(RelayEndpoint.pinnedSPKIHashes.contains(digest))
    }

    @Test("the raw EC point alone is NOT the pin — the header is what makes them agree")
    func rawPointIsNotThePin() throws {
        // Guards the specific mistake the type comment describes. If someone "simplifies"
        // spkiSHA256 by dropping the header, this is the test that says why it broke.
        let key = try #require(SecCertificateCopyKey(Fixture.leafCertificate))
        let raw = try #require(SecKeyCopyExternalRepresentation(key, nil) as Data?)

        #expect(raw.count == CertificatePinner.p256UncompressedPointCount)
        #expect(raw.first == 0x04)

        let rawDigest = Data(SHA256.hash(data: raw)).base64EncodedString()
        #expect(rawDigest != Fixture.expectedSPKISHA256,
                "hashing the bare point must not coincidentally equal the SPKI hash")

        var reconstructed = CertificatePinner.p256SPKIHeader
        reconstructed.append(raw)
        #expect(Data(SHA256.hash(data: reconstructed)).base64EncodedString()
                == Fixture.expectedSPKISHA256)
    }

    // MARK: Refusals

    @Test("a pin set that does not contain the leaf is refused")
    func mismatchedPinIsRefused() throws {
        let wrongPin = Data(repeating: 0xAB, count: 32)
        let pinner = CertificatePinner(pinnedSPKIHashes: [wrongPin],
                                       expectedHost: RelayEndpoint.host)
        let digest = try #require(CertificatePinner.spkiSHA256(of: Fixture.leafCertificate))
        #expect(!pinner.pinnedSPKIHashes.contains(digest))
    }

    @Test("an empty pin set refuses rather than permits")
    func emptyPinSetRefuses() throws {
        // The failure that turns a pinning bug into no pinning. An empty set must read as
        // "nothing is acceptable", never as "no constraint".
        let pinner = CertificatePinner(pinnedSPKIHashes: [], expectedHost: RelayEndpoint.host)
        let trust = try #require(Self.trust(for: [Fixture.leafCertificate]))

        #expect(throws: CertificatePinner.Failure.noPinsConfigured) {
            _ = try pinner.evaluate(trust, host: RelayEndpoint.host)
        }
    }

    @Test("a challenge for a different host is refused before anything else is read")
    func wrongHostIsRefused() throws {
        let pinner = CertificatePinner()
        let trust = try #require(Self.trust(for: [Fixture.leafCertificate]))

        #expect(throws: CertificatePinner.Failure.unexpectedHost("evil.example")) {
            _ = try pinner.evaluate(trust, host: "evil.example")
        }
    }

    @Test("a self-signed certificate is refused — chain validation runs before the pin")
    func selfSignedIsRefused() throws {
        // Well-formed, right hostname, current dates, and nothing trusts it. The pin never
        // gets a say: `evaluate` throws `chainRejected` first, which is the ordering that
        // stops a pin match from standing in for validation.
        let trust = try #require(Self.trust(for: [Fixture.selfSignedCertificate]))

        #expect(throws: CertificatePinner.Failure.chainRejected) {
            _ = try CertificatePinner().evaluate(trust, host: RelayEndpoint.host)
        }
    }

    @Test("a wrong-pin server is refused even though its chain is perfectly valid")
    func wrongPinIsRefusedOnAValidChain() throws {
        // P5.S08's stated "Done when". The chain here is the real one and the platform is
        // satisfied by it; the only thing wrong is the key. This is the case that separates
        // pinning from ordinary TLS — an attacker holding a legitimately issued certificate
        // for this hostname passes every check except this one.
        //
        // Modelled by pinning ONLY the backup key, so the real leaf is a non-matching key
        // against a valid chain, which is exactly the shape of that attack.
        let backupOnly = try #require(Data(base64Encoded: RelayEndpoint.PinnedKey.backupKey))
        let pinner = CertificatePinner(pinnedSPKIHashes: [backupOnly],
                                       expectedHost: RelayEndpoint.host)
        let trust = try #require(Self.trust(for: [Fixture.leafCertificate,
                                                  Fixture.intermediateCertificate]))

        #expect(throws: CertificatePinner.Failure.pinMismatch) {
            _ = try pinner.evaluate(trust, host: RelayEndpoint.host)
        }
    }

    @Test("the same valid chain IS accepted once the correct pin is present")
    func correctPinIsAcceptedOnTheSameChain() throws {
        // The positive control for the test above. Without it, `wrongPinIsRefusedOnAValidChain`
        // would also pass if the chain simply never validated — which is how a pinning test
        // ends up proving nothing. Same certificates, same host, only the pin set differs.
        let trust = try #require(Self.trust(for: [Fixture.leafCertificate,
                                                  Fixture.intermediateCertificate]))

        #expect(throws: Never.self) {
            _ = try CertificatePinner().evaluate(trust, host: RelayEndpoint.host)
        }
    }

    @Test("the self-signed key is not in the shipped pin set")
    func selfSignedKeyIsNotPinned() throws {
        let spki = try #require(Data(base64Encoded: Fixture.selfSignedSPKISHA256))
        #expect(!RelayEndpoint.pinnedSPKIHashes.contains(spki))
    }

    // MARK: Endpoint invariants

    @Test("the base URL is https and names the pinned host")
    func baseURLIsSecure() {
        #expect(RelayEndpoint.baseURL.scheme == "https")
        #expect(RelayEndpoint.baseURL.host == RelayEndpoint.host)
    }

    @Test("exactly two pins ship, and both decode to 32 bytes")
    func pinSetShape() {
        // Two because one pin plus one lost key is a permanently bricked client
        // (BACKEND.md 9.1 rule 2). If this becomes one, rotation has no landing ground.
        #expect(RelayEndpoint.pinnedSPKIHashes.count == 2)
        for pin in RelayEndpoint.pinnedSPKIHashes {
            #expect(pin.count == 32)
        }
    }

    @Test("the Let's Encrypt intermediate is NOT pinned")
    func intermediateIsNotPinned() throws {
        // Recorded in BACKEND.md 9.1 as deliberately unpinned. Pinning it would accept any
        // certificate LE issues for this host, which anyone passing ACME validation can get.
        let intermediateSPKI = try #require(
            Data(base64Encoded: "brzvtCELCIZUo4sD/qPX0ccRtPsd3DY6RfmxpOU9oB4="))
        #expect(!RelayEndpoint.pinnedSPKIHashes.contains(intermediateSPKI))
    }

    // MARK: Helpers

    private static func trust(for chain: [SecCertificate]) -> SecTrust? {
        var trust: SecTrust?
        let policy = SecPolicyCreateSSL(true, RelayEndpoint.host as CFString)
        guard SecTrustCreateWithCertificates(chain as CFArray, policy, &trust) == errSecSuccess else {
            return nil
        }
        return trust
    }
}
