# Cipher — Security Audit Report

**Audit date:** 2026-07-30  
**Auditor role:** Senior application security engineer (read-only review)  
**Scope:** Full repository — iOS/Xcode client (`Cipher/`, `CipherCrypto/`), Go relay (`server/`), CocoaPods dependencies (`Pods/`), build/CI scripts (`Scripts/`, `.github/`), configuration, and supporting documentation.  
**Method:** Static source review, dependency inventory, `govulncheck` on server modules, CVE/GHSA/OSV research, cross-reference with existing `docs/AUDIT.md` and `docs/THREAT_MODEL.md`. No code, configuration, or dependencies were modified.

---

## 1. Executive Summary

Cipher is an invite-only, end-to-end encrypted messenger in active development. This audit reviewed **753 tracked source and configuration files** across the iOS client, crypto module, test suites, vendored Go dependencies, CocoaPods tree, CI workflows, and operational scripts.

**Bottom line:** The codebase demonstrates unusually mature security engineering for its stage. First-party controls — Signal Protocol via pinned libsignal, SPKI certificate pinning (fail-closed), Keychain-backed session credentials, AES-GCM sealed local storage, strict envelope parsing, redacted logging, and parameterized SQL — are implemented deliberately and tested. **No confirmed Critical or High exploitable vulnerabilities were found in first-party application code.**

The principal risks are **architectural residuals** (trust-on-first-use without safety-number verification, bounded prekey-replay witness eviction, absence of sealed sender, metadata visible to a hostile relay) and **supply-chain/process gaps** (unsigned libsignal FFI prebuild, CI required-check not enabled at repository level, one transitive Go dependency with a published DoS CVE). Several items are already tracked in `docs/AUDIT.md` with explicit acceptance rationale.

**Dependency vulnerability summary:** One reachable transitive vulnerability (`golang.org/x/text` → CVE-2026-56852). All direct dependencies are current; libsignal `v0.99.1` has no published CVE affecting `signalapp/libsignal` (distinct from third-party `libsignal-service-rs`).

---

## 2. Overall Risk Rating

### **32 / 100** (Low–Moderate)

| Factor | Contribution |
|--------|--------------|
| Strong crypto architecture & fail-closed transport | −25 |
| Documented, tested security gates (CI + scripts) | −15 |
| Open protocol/metadata gaps (no sealed sender, TOFU) | +12 |
| Supply-chain residual (unsigned FFI, mutable tags mitigated by commit pin) | +8 |
| Transitive Go DoS CVE (`golang.org/x/text`) | +5 |
| Pre-production state (not yet validated on two physical devices) | +7 |

*Scale: 0 = negligible residual risk, 100 = critical immediate compromise likely.*

---

## 3. Critical Findings

**None identified.**

No first-party code path was found that permits unauthenticated decryption, authentication bypass in Release builds, remote code execution, SQL injection, or TLS bypass. DEBUG-only authentication shortcuts are correctly fenced on both writers and readers, with `.development` credentials refused in Release.

---

## 4. High Severity Findings

**None identified.**

Note: Several items below would be High in a production messenger with a large user base but are **Medium** here because they are documented, partially compensated, or require a capable network adversary (malicious/compromised relay) rather than a remote unauthenticated attacker.

---

## 5. Medium Severity Findings

### M-01 — First-contact sender attribution is spoofable by a hostile relay

| Field | Detail |
|-------|--------|
| **Severity** | Medium |
| **Files** | `CipherCrypto/Sources/Engine/Messaging.swift` (lines 36–41, 269–317); `CipherCrypto/Sources/Store/CipherProtocolStore.swift` (lines 299–339); `Cipher/Messaging/ConversationStore.swift` (lines 22–25, 389–393); `CipherCrypto/Sources/Wire/Envelope.swift` (lines 15–26, 107–108) |
| **Status** | Open (AUDIT 3.3, 3.8) |

**Explanation:** `Envelope.sender` is explicitly documented as an attacker-controlled routing hint. For **session-establishing** (`preKey`) messages, the relay chooses the sender address; the identity key is extracted from inside the ciphertext. A malicious relay can deliver a genuine first message from party A labeled as party B. Established-session messages are protected (`testRewrittenEnvelopeSenderCannotMisattribute`).

**Exploitation scenario:** Attacker operates or compromises `relay.mgchatman.app`. Victim receives a valid first message from attacker-controlled identity under a contact label the victim trusts. Message content is authentic to the embedded key, but the **social label is wrong**.

**Likelihood:** Medium (requires relay compromise or operator malice; consistent with threat model §1.1).  
**Impact:** Medium (misattribution, social engineering; not plaintext disclosure).

**Evidence:**
```15:26:CipherCrypto/Sources/Wire/Envelope.swift
/// ## The envelope is NOT authenticated — this is the single most important thing about it
///
/// Every field here is attacker-controlled. The transport is a hostile network and the
/// server is untrusted, so a malicious or compromised relay can forge, replay, reorder, or
/// rewrite any header byte.
```

**Recommended fix:** Ship safety-number / QR verification UI (planned P5.S12). Surface unverified/first-contact warnings. Never attribute messages to `Envelope.sender` for preKey messages; use `senderIdentityKey` from decryption (already documented).

---

### M-02 — Bounded prekey base-key witness allows replay after FIFO eviction

| Field | Detail |
|-------|--------|
| **Severity** | Medium |
| **Files** | `CipherCrypto/Sources/Store/CipherProtocolStore.swift` (lines 432–476) |
| **Status** | Open (AUDIT 3.1) |

**Explanation:** Kyber last-resort prekeys are not consumed on use. Replay protection relies on a FIFO witness capped at **512** base-key digests per `(kyberId, signedPreKeyId)` pair. Oldest entries are evicted under pressure.

**Exploitation scenario:** Attacker captures a `PreKeySignalMessage`, then drives ≥512 fresh session establishments against the same published prekey pair (public bundle only), evicting the witness entry for the captured base key, then replays the old message to re-deliver its plaintext once.

**Likelihood:** Low–Medium (requires captured message + sustained session-setup traffic; server rate-limits prekey fetch 10/hour per caller).  
**Impact:** Medium (one-time plaintext re-delivery for a captured first message).

**Evidence:**
```468:475:CipherCrypto/Sources/Store/CipherProtocolStore.swift
        seen.append(digest)
        if seen.count > Self.baseKeyWitnessCapacity {
            seen.removeFirst(seen.count - Self.baseKeyWitnessCapacity)
```

**Recommended fix:** Implement prekey rotation and replenishment (AUDIT 2.4, P6.S01). Maintain server-side per-target rate limits. Consider lowering witness cap only with measured server limits.

---

### M-03 — No sealed sender; relay learns communication metadata

| Field | Detail |
|-------|--------|
| **Severity** | Medium |
| **Files** | `CipherCrypto/Sources/Wire/Envelope.swift`; `docs/AUDIT.md` (3.4) |
| **Status** | Open (P7.S01) |

**Explanation:** Sender ServiceId is sent in cleartext envelope headers. A seizable or malicious relay learns who messages whom and when, even though message bodies remain E2E encrypted.

**Exploitation scenario:** VPS provider or lawful seizure obtains Postgres snapshots (see M-10) containing sender/recipient metadata and timing.

**Likelihood:** High (by design today).  
**Impact:** Medium (metadata exposure, not content).

**Recommended fix:** Implement sealed sender in a future wire version; reserve envelope type space already exists.

---

### M-04 — libsignal FFI prebuild is checksum-pinned but not cryptographically attested

| Field | Detail |
|-------|--------|
| **Severity** | Medium (supply chain) |
| **Files** | `Vendor/libsignal/PINS.env`; `Podfile`; `docs/AUDIT.md` (1.1, 1.2, 1.3) |
| **Status** | Accepted |

**Explanation:** The iOS `libsignal_ffi.a` binary is downloaded at build time from `build-artifacts.signal.org` and verified by SHA-256. There is no signature or SLSA provenance attestation. A compromised artifact host that publishes a matching hash would be trusted.

**Exploitation scenario:** Supply-chain compromise of Signal's build artifact CDN or MITM during CI `pod install` (mitigated by checksum in `PINS.env` and independent `verify-supply-chain.sh`).

**Likelihood:** Low.  
**Impact:** Critical if realized (arbitrary code in app).

**Evidence:** `LIBSIGNAL_FFI_PREBUILD_CHECKSUM=c7b1ad515b0698497f051cb7a65e0d9a6e1e5d707db82aa334fa8c834e3e4fd8` in `Vendor/libsignal/PINS.env`.

**Recommended fix:** Prefer building FFI from audited source in reproducible CI; adopt signed provenance when Signal provides it. Keep weekly tag/commit re-resolution in CI (already scheduled).

---

### M-05 — Transitive Go dependency: infinite loop in `golang.org/x/text` (CVE-2026-56852)

| Field | Detail |
|-------|--------|
| **Severity** | Medium (availability / DoS) |
| **Files** | `server/go.mod` (indirect `golang.org/x/text v0.29.0`); reachable via `server/internal/store/postgres.go:59` → `pgxpool.NewWithConfig` |
| **CVE** | CVE-2026-56852 / GO-2026-5970 |
| **CVSS** | Not assigned in NVD at audit time |
| **Affected versions** | `golang.org/x/text` < v0.39.0 |
| **Fixed version** | v0.39.0 |
| **Project affected?** | **Yes** (confirmed by `govulncheck ./...` on 2026-07-30) |

**Explanation:** `norm.Iter` can infinite-loop on invalid UTF-8. Triggered through pgx's connection path if attacker-controlled invalid UTF-8 reaches normalization (e.g., malicious PostgreSQL server responses or crafted connection parameters in a compromised-DB scenario).

**Exploitation scenario:** Attacker compromises PostgreSQL or performs MITM on DB connection (DB is not exposed publicly; threat is insider/VPS compromise). Relay worker goroutine hangs indefinitely → DoS.

**Likelihood:** Low (requires DB-layer attacker; DB is firewalled).  
**Impact:** Medium (service availability).

**Recommended fix:** Bump `golang.org/x/text` to ≥ v0.39.0 via `go get` and re-vendor; add `govulncheck` to CI.

---

## 6. Low Severity Findings

### L-01 — Local user profile stored in plaintext UserDefaults

| Field | Detail |
|-------|--------|
| **Severity** | Low |
| **Files** | `Cipher/App/AppSession.swift` (lines 44–52, 186–194) |
| **Status** | Open (AUDIT 4.7) |

**Explanation:** Display name, username, and "about" are stored unencrypted in `UserDefaults`. Not cryptographic secrets, but PII identifying the device owner. Cleared on `signOut()`.

**Exploitation scenario:** Physical access, jailbreak, or backup extraction reads profile fields.

**Likelihood:** Medium. **Impact:** Low.

**Recommended fix:** Move to sealed record store (P5.S11).

---

### L-02 — Identity key Keychain accessibility is `AfterFirstUnlockThisDeviceOnly`

| Field | Detail |
|-------|--------|
| **Severity** | Low |
| **Files** | `CipherCrypto/Sources/Store/SecretStorage.swift` (lines 69–82, 138–161) |
| **Status** | Accepted (AUDIT 2.1) |

**Explanation:** Weaker than `WhenUnlocked` to allow future Notification Service Extension decryption. Session token correctly uses `WhenUnlockedThisDeviceOnly`.

**Exploitation scenario:** Malware running after first post-boot unlock reads identity key from Keychain.

**Likelihood:** Low (requires code execution). **Impact:** High if combined with execution — accepted tradeoff.

**Recommended fix:** Re-evaluate when NSE ships; gate weaker class behind extension requirement.

---

### L-03 — Secret buffer zeroization not guaranteed for libsignal/Rust allocations

| Field | Detail |
|-------|--------|
| **Severity** | Low |
| **Files** | `CipherCrypto/Sources/Crypto/SecretData.swift`; `CipherCryptoTests/ZeroizationRealityTests.swift` |
| **Status** | Accepted (AUDIT 2.2, 2.3) |

**Explanation:** `SecretData.wipe()` uses `memset_s` on owned copies; libsignal `serialize()` returns Rust-backed `Data` not zeroized on free.

**Recommended fix:** Minimize secret lifetime (already done); track upstream zeroization.

---

### L-04 — CocoaPods build script sandboxing disabled

| Field | Detail |
|-------|--------|
| **Severity** | Low (build-time) |
| **Files** | `Podfile` (lines 59–72, 100) |
| **Status** | Accepted (AUDIT 1.5) |

**Explanation:** `ENABLE_USER_SCRIPT_SANDBOXING = NO` applied broadly so libsignal's download script can run.

**Exploitation scenario:** Compromised pod script executes without sandbox on developer/CI machine.

**Recommended fix:** Scope sandbox disable to LibSignalClient target only; keep checksum gate.

---

### L-05 — No prekey rotation or replenishment

| Field | Detail |
|-------|--------|
| **Severity** | Low |
| **Files** | `CipherCrypto/Sources/Store/CipherProtocolStore.swift`; `docs/AUDIT.md` (2.4) |
| **Status** | Open (P6.S01) |

**Recommended fix:** Implement automatic prekey publish/rotate on consumption thresholds.

---

### L-06 — No user-facing safety-number verification screen

| Field | Detail |
|-------|--------|
| **Severity** | Low |
| **Files** | `Cipher/Features/Conversation/ChatInfoViews.swift`; `docs/AUDIT.md` (2.5) |
| **Status** | Open (P5.S12) |

**Explanation:** `Chat.isVerified` is not wired to real verification state.

**Recommended fix:** Implement fingerprint display and `acceptIdentity` UX.

---

### L-07 — Blob byte quota fails open on mid-upload Redis error

| Field | Detail |
|-------|--------|
| **Severity** | Low |
| **Files** | `server/internal/api/blobs.go` (lines 156–162) |
| **Status** | New finding |

**Explanation:** Post-upload byte quota charging loops Redis `Allow` calls but breaks on error without failing the upload, under-counting daily byte quota.

**Exploitation scenario:** Authenticated user uploads large blobs while inducing Redis pressure; byte cap becomes soft.

**Likelihood:** Low. **Impact:** Low (disk/bandwidth; count limit still applies).

**Recommended fix:** Single `Allow` with cost=megabytes; fail closed on Redis error.

---

### L-08 — `DELETE /v1/blobs/{id}` and `POST /v1/messages/ack` lack rate limits

| Field | Detail |
|-------|--------|
| **Severity** | Low |
| **Files** | `server/internal/api/blobs.go` (257–286); `server/internal/api/messages.go` (225–264) |

**Explanation:** Authenticated delete/ack endpoints are unthrottled. Blob IDs are 122-bit capabilities (not enumerable); risk is attachment shredding if an ID leaks.

**Recommended fix:** Add symmetric rate limits for delete and ack.

---

### L-09 — Rate-limit pepper regenerated on process restart

| Field | Detail |
|-------|--------|
| **Severity** | Low |
| **Files** | `server/cmd/relay/main.go` (lines 228–232) |
| **Status** | Documented |

**Explanation:** Per-process random pepper resets all Redis rate-limit buckets on restart.

**Recommended fix:** Persist configured pepper in secrets manager (planned P5+).

---

### L-10 — Provider daily disk snapshots retain deleted ciphertext up to 24h

| Field | Detail |
|-------|--------|
| **Severity** | Low |
| **Files** | `docs/AUDIT.md` (4.8); `docs/INFRASTRUCTURE.md` |
| **Status** | Accepted |

**Recommended fix:** Select provider with controllable snapshots at production (P9.S01).

---

### L-11 — No CAA DNS record for certificate issuance restriction

| Field | Detail |
|-------|--------|
| **Severity** | Low |
| **Files** | `docs/AUDIT.md` (5.17) |
| **Status** | Accepted |

**Explanation:** Registrar cannot create CAA. Mitigated by SPKI pinning in app.

**Recommended fix:** Use DNS provider with CAA at production domain selection.

---

## 7. Informational Findings

### I-01 — `URLError.cancelled` classified as TLS failure

| Field | Detail |
|-------|--------|
| **Severity** | Informational |
| **Files** | `Cipher/Networking/RelayClient.swift` (lines 188–202) |

Deliberate fail-safe: pin refusal and user cancellation both map to `.secureConnectionFailed`. User-cancelled requests are not retried.

---

### I-02 — DEBUG authentication bypass properly fenced

| Field | Detail |
|-------|--------|
| **Severity** | Informational (positive) |
| **Files** | `Cipher/Security/SessionCredential.swift` (132–137, 217–234); `Cipher/Features/Auth/AuthFlowView.swift`; `Cipher/App/AppSession.swift` |

`#if DEBUG` on readers and writers; `.development` origin refused in Release; Release binary audited for debug symbols.

---

### I-03 — `PlaintextContent` wire type explicitly refused (positive control)

| Field | Detail |
|-------|--------|
| **Severity** | Informational (positive) |
| **Files** | `CipherCrypto/Sources/Wire/Envelope.swift` (lines 67–91, 206) |

Mitigates a class of bugs similar to CVE-2025-24904 in third-party `libsignal-service-rs` (not used here).

---

### I-04 — libsignal `0.x` API instability

| Field | Detail |
|-------|--------|
| **Severity** | Informational |
| **Files** | `docs/AUDIT.md` (1.4); `CipherCryptoTests/LibsignalContractTests.swift` |

Upstream may break behavior between releases; contract tests mitigate.

---

### I-05 — CI `verify` job not marked required in GitHub branch protection

| Field | Detail |
|-------|--------|
| **Severity** | Informational (process) |
| **Files** | `docs/AUDIT.md` (1.6); `.github/workflows/verify.yml` |

Workflow exists and runs on push/PR/weekly schedule; repository setting to require it is outside the tree.

---

### I-06 — Messaging path not yet validated between two physical devices

| Field | Detail |
|-------|--------|
| **Severity** | Informational |
| **Files** | `docs/AUDIT.md` (5.1) |

End-to-end flow tested against stubbed relay and dual `CryptoEngine` in unit tests; staging device test (P5.S13) pending.

---

### I-07 — No `.entitlements` file / App Group (intentional)

| Field | Detail |
|-------|--------|
| **Severity** | Informational |
| **Files** | `Cipher.xcodeproj/project.pbxproj` |

Single-process design; NSE will require App Group + Keychain access group (AUDIT 4.4).

---

### I-08 — Privacy manifest correctly declares API usage

| Field | Detail |
|-------|--------|
| **Severity** | Informational (positive) |
| **Files** | `Cipher/PrivacyInfo.xcprivacy` |

Declares `UserDefaults` (CA92.1) and `FileTimestamp` (C617.1); no tracking; libsignal's `fstat` covered.

---

## 8. Vulnerable Dependencies

### 8.1 Direct dependencies — iOS (CocoaPods)

| Dependency | Version | Source | Commit / Pin | Known CVEs at this version |
|------------|---------|--------|--------------|----------------------------|
| **LibSignalClient** | 0.99.1 | `https://github.com/signalapp/libsignal.git` | Tag `v0.99.1` → commit `97801d22dcf9f5bf714f7b8fa3212cdc973ae1c8` (verified in `Vendor/libsignal/PINS.env`) | **None published for `signalapp/libsignal`** |
| **CocoaPods** (build tool) | 1.17.0 | RubyGems (`Gemfile.lock`) | SHA256-pinned gems | **None for client 1.17.0**; 2024 Trunk server CVEs (below) do not affect git-sourced pods |

**FFI prebuild:** `libsignal-client-ios-build-v0.99.1.tar.gz` — SHA-256 `c7b1ad515b0698497f051cb7a65e0d9a6e1e5d707db82aa334fa8c834e3e4fd8`

**Supply-chain controls:** Tag→commit re-resolution (`Scripts/verify-supply-chain.sh`), FFI checksum verification, `Pods/` committed for diff review, libsignal excluded from Dependabot.

---

### 8.2 Direct dependencies — Go relay

| Dependency | Version | Role | Known CVEs at this version |
|------------|---------|------|----------------------------|
| `github.com/google/uuid` | v1.6.0 | Identifiers | None known |
| `github.com/jackc/pgx/v5` | v5.10.0 | PostgreSQL driver | **Not affected** by CVE-2026-33816 (fixed in 5.9.0); includes hardening for CVE-2024-27304 |
| `github.com/redis/go-redis/v9` | v9.21.0 | Rate limiting | **Not affected** by CVE-2025-29923 (patched in 9.5.5/9.6.3/9.7.3; 9.21.0 is later) |

---

### 8.3 Indirect dependencies — Go (vendored)

| Dependency | Version | Known CVEs | Project affected? |
|------------|---------|------------|-------------------|
| `github.com/cespare/xxhash/v2` | v2.3.0 | None known | No |
| `github.com/jackc/puddle/v2` | v2.2.2 | None known | No |
| `go.uber.org/atomic` | v1.11.0 | None known | No |
| `golang.org/x/sync` | v0.17.0 | None known | No |
| **`golang.org/x/text`** | **v0.29.0** | **CVE-2026-56852** (GO-2026-5970) | **Yes** — see M-05 |
| `golang.org/x/sys` | v0.30.0 (go.sum) | None in use path | No |

---

### 8.4 Build / CI toolchain

| Component | Version | Notes |
|-----------|---------|-------|
| Xcode (verified) | 26.6 (`PINS.env`) | TLS 1.3 client floor |
| Go toolchain | 1.25.0 (`server/go.mod`) | |
| Ruby / Bundler | CocoaPods 1.17.0 via Bundler 4.0.16 | |
| GitHub Actions | Pinned to full commit SHAs | AUDIT 1.8 |

---

## 9. Public GitHub Vulnerabilities

### 9.1 Dependencies — detailed CVE table

| Vulnerability | CVE | CVSS | Affected package / versions | Fixed version | Severity | This project affected? | Impact if affected |
|---------------|-----|------|----------------------------|---------------|----------|------------------------|-------------------|
| Infinite loop in `norm.Iter` on invalid UTF-8 | CVE-2026-56852 | TBD | `golang.org/x/text` < 0.39.0 | 0.39.0 | Medium (DoS) | **Yes** | Relay worker hang |
| Out-of-order Redis responses on `CLIENT SETINFO` timeout | CVE-2025-29923 | 3.7 Low | go-redis 9.5.1–9.7.2 | 9.5.5, 9.6.3, 9.7.3 | Low | **No** (using 9.21.0) | Incorrect rate-limit decisions |
| pgx memory-safety in pgproto3 | CVE-2026-33816 | 9.8 Critical* | pgx < 5.9.0 | 5.9.0 | Critical* | **No** (using 5.10.0) | *Maintainer notes: only affects proxy builders using pgproto3 directly |
| pgx SQL injection via 4GB bind message | CVE-2024-27304 | — | pgx < 5.7.4 | 5.7.4+ | High | **No** (5.10.0 includes fix) | SQL injection |
| Plaintext envelope injection | CVE-2025-24904 | 8.5 High | `whisperfish/libsignal-service-rs` | commit 82d70f6 | High | **No** — different repo; Cipher uses `signalapp/libsignal` and refuses `PlaintextContent` on wire | Auth bypass |
| Sync message origin unchecked | CVE-2025-24903 | 8.5 High | `whisperfish/libsignal-service-rs` | commit 82d70f6 | High | **No** — not used | Device impersonation |
| CocoaPods Trunk RCE | CVE-2024-38366 | 10.0 Critical | CocoaPods **Trunk server** (2014–2023) | Server patched Oct 2023 | Critical | **Not directly** — libsignal fetched via **git tag**, not Trunk CDN | Pod substitution |
| CocoaPods session hijack | CVE-2024-38367 | 8.2 High | CocoaPods Trunk server | Server patched Oct 2023 | High | **Not directly** | Account takeover |
| Orphaned pod claim | CVE-2024-38368 | 9.3 Critical | CocoaPods Trunk server | Server patched Oct 2023 | Critical | **Not directly** | Supply-chain injection |

---

### 9.2 `signalapp/libsignal` repository investigation

| Check | Result |
|-------|--------|
| **Repository** | https://github.com/signalapp/libsignal — **Active** (official Signal project) |
| **Version in use** | v0.99.1 @ `97801d22dcf9f5bf714f7b8fa3212cdc973ae1c8` |
| **Published GHSA/CVE for this repo at this version** | **None found** in NVD/OSV/GitHub Advisory Database |
| **Recent security-related issues** | Issue #545 — Kyber side-channel hardening in `pqcrypto-kyber` (addressed in v0.38.0+; v0.99.1 is newer) |
| **Archived / abandoned** | No — actively maintained by Signal |
| **API stability** | Explicitly `0.x` — breaking changes expected (AUDIT 1.4) |
| **Malicious package risk** | Low — pinned git URL + commit + FFI checksum; not a typosquat npm package |
| **Unsigned releases** | FFI prebuild is SHA-256 only (M-04) |

**Related but NOT applicable:** `whisperfish/libsignal-service-rs` (third-party Signal *service client*) has GHSA-hrrc-wpfw-5hj2 and GHSA-r58q-66g9-h6g8. Cipher does not import this library. Cipher's analogous control is refusing `PlaintextContent` in `Envelope.swift`.

**Unrelated malware:** `GHSA-3qf5-vfww-7p7g` (`@rexxtheproject/elaina-libsignal` npm) — **not in this project**.

---

### 9.3 Other GitHub dependencies

| Repository | Version | Security posture |
|------------|---------|------------------|
| `github.com/jackc/pgx` | v5.10.0 | Active; recent CrowdStrike hardening release |
| `github.com/redis/go-redis` | v9.21.0 | Active; CVE-2025-29923 fixed in earlier branches |
| `github.com/google/uuid` | v1.6.0 | Stable; no recent CVEs |
| `github.com/JanRichtermoc/Cipher` | AGPL-3.0 | Self-hosted relay; invite-only auth |

---

## 10. Potential False Positives

| Finding | Why it may be a false positive | Auditor assessment |
|---------|-------------------------------|-------------------|
| CVE-2025-24904 / CVE-2025-24903 | Name contains "libsignal" | **False positive** — affects `whisperfish/libsignal-service-rs`, not `signalapp/libsignal`. Cipher additionally blocks plaintext wire type. |
| CVE-2026-33816 (pgx) | `govulncheck` may flag pgproto3 | **False positive for this app** — pgx maintainer states `Bind.Decode()` is not exercised in normal client driver use; project uses 5.10.0 anyway. |
| CVE-2024-38366/67/68 (CocoaPods) | Scanner flags "CocoaPods" | **False positive for runtime** — server-side Trunk issues; mitigated by git-sourced libsignal, not trunk CDN. Build-time CocoaPods tool remains trusted. |
| Hardcoded SPKI pins in `RelayEndpoint.swift` | Static analysis "hardcoded secrets" | **False positive** — SPKI hashes are public by construction (derived from TLS certificate). |
| `Bearer` token in `RelayClient` | Token in header | **False positive** — token loaded from Keychain at runtime, not embedded. |
| `fatalError` / `try!` in `Pods/LibSignalClient` | Crash on error | **Out of scope** — third-party library; not invoked on attacker-controlled paths in Cipher's usage surface. |
| Empty `User-Agent` header | Fingerprinting / blocking | **Intentional** — reduces client metadata leakage to relay (BACKEND.md §1). |

---

## 11. Recommended Fixes (Descriptions Only)

### Immediate (next sprint)

1. **Upgrade `golang.org/x/text` to ≥ v0.39.0** in `server/go.mod`, run `go mod vendor`, verify build and integration tests.
2. **Add `govulncheck ./...` to CI** (relay job) as a blocking gate.
3. **Enable GitHub branch protection** requiring the `verify` status check on `main` (AUDIT 1.6 residual).

### Short term (P5–P6)

4. **Safety-number verification UI** — close TOFU gap for first-contact and identity-change scenarios.
5. **Prekey rotation/replenishment** — reduce M-02 replay window and prekey exhaustion DoS.
6. **Move profile fields from UserDefaults** to sealed store.
7. **Fix blob byte-quota fail-open** — single Redis charge, fail closed on error.
8. **Add rate limits** to blob delete and message ack endpoints.
9. **Complete two-device staging validation** (P5.S13).

### Medium term (P7+)

10. **Sealed sender** — hide sender metadata from relay.
11. **Push notification hardening** (P7.S03) — encrypted APNs payloads, token rotation.
12. **Notification Service Extension** — requires transactional store, cross-process lock, Keychain access group (AUDIT 4.4).
13. **Production infrastructure review** — CAA, snapshot policy, jurisdiction (P9.S01).

### Supply chain (ongoing)

14. **Keep libsignal pin discipline** — never bump without `verify-supply-chain.sh`, contract tests, and FFI checksum update.
15. **Scope `ENABLE_USER_SCRIPT_SANDBOXING = NO`** to LibSignalClient only.
16. **Investigate reproducible FFI builds** from source when toolchain permits.

---

## 12. References

### Project documentation
- [docs/AUDIT.md](AUDIT.md) — Security audit ledger
- [docs/THREAT_MODEL.md](THREAT_MODEL.md) — Adversary model
- [docs/BACKEND.md](BACKEND.md) — Relay security design
- [Vendor/libsignal/PINS.env](../Vendor/libsignal/PINS.env) — libsignal supply-chain pins
- [Vendor/libsignal/DECISIONS.md](../Vendor/libsignal/DECISIONS.md) — Dependency decisions

### CVE / advisory links
- CVE-2026-56852 / GO-2026-5970: https://pkg.go.dev/vuln/GO-2026-5970
- CVE-2025-29923 / GHSA-92cp-5422-2mw7: https://github.com/advisories/GHSA-92cp-5422-2mw7
- CVE-2026-33816 / GHSA-9jj7-4m8r-rfcm: https://github.com/advisories/GHSA-9jj7-4m8r-rfcm
- CVE-2024-27304 / pgx: https://github.com/jackc/pgx/security/advisories/GHSA-m7wr-2xf7-cm9p
- CVE-2025-24904 / GHSA-hrrc-wpfw-5hj2 (libsignal-service-rs, **not used**): https://github.com/whisperfish/libsignal-service-rs/security/advisories/GHSA-hrrc-wpfw-5hj2
- CVE-2025-24903 / GHSA-r58q-66g9-h6g8 (libsignal-service-rs, **not used**): https://github.com/whisperfish/libsignal-service-rs/security/advisories/GHSA-r58q-66g9-h6g8
- CocoaPods Trunk CVEs (2024): CVE-2024-38366, CVE-2024-38367, CVE-2024-38368 — https://blog.cocoapods.org/CocoaPods-Trunk-RCEs-2023/

### Upstream repositories
- libsignal: https://github.com/signalapp/libsignal (tag v0.99.1, commit 97801d22dcf9f5bf714f7b8fa3212cdc973ae1c8)
- pgx: https://github.com/jackc/pgx
- go-redis: https://github.com/redis/go-redis
- google/uuid: https://github.com/google/uuid

### Tools used
- `govulncheck ./...` (golang.org/x/vuln v1.6.0) — 2026-07-30
- Static analysis via repository `Scripts/verify-all.sh` gate definitions (not executed as part of this read-only audit)

---

## Appendix A — Files Reviewed

### First-party iOS (60 Swift files)

**Cipher/** — 40 files including `Networking/*`, `Security/*`, `Messaging/*`, `Features/*`, `App/*`, `Components/*`, `DesignSystem/*`, `Models/*`, `CipherApp.swift`, `ContentView.swift`, `PrivacyInfo.xcprivacy`, `Localizable.xcstrings`.

**CipherCrypto/** — 20 files including `Engine/*`, `Store/*`, `Wire/*`, `Crypto/*`, `Logging/*`.

**CipherTests/** — 7 files. **CipherCryptoTests/** — 12 files.

### Xcode / build configuration
- `Cipher.xcodeproj/project.pbxproj` — deployment target 26.5, generated Info.plist, Face ID usage, no ATS exceptions, automatic code signing, no entitlements file.
- `Podfile`, `Podfile.lock`, `Gemfile.lock`, `Cipher.xcworkspace`.

### Scripts & CI (reviewed)
- `Scripts/verify-all.sh`, `verify-supply-chain.sh`, `verify-pins.sh`, `verify-api-boundary.sh`, `verify-privacy-manifest.sh`, `verify-relay-integration.sh`, `verify-localization.py`, `app-target-manifest.txt`.
- `.github/workflows/verify.yml`, `.github/dependabot.yml`.

### Go relay (first-party)
- `server/cmd/relay/main.go`
- `server/internal/api/*` (auth, invite, keys, messages, blobs)
- `server/internal/auth/*`, `server/internal/blob/*`, `server/internal/cache/*`
- `server/internal/config/*`, `server/internal/httpx/*`, `server/internal/ratelimit/*`
- `server/internal/store/*`, `server/internal/sweep/*`
- `server/internal/integration/*` (adversarial, auth, blobs, invite, keys, logging, messages)
- `server/go.mod`, `server/go.sum`, `server/docker-compose.yml`, `server/.env.example`

### Third-party (integration surface reviewed)
- `Pods/LibSignalClient/` — Swift wrapper and FFI integration (full tree present in repo).
- `server/vendor/` — vendored Go modules (inventory via `vendor/modules.txt`).

### Documentation (security-relevant)
- `docs/AUDIT.md`, `docs/THREAT_MODEL.md`, `docs/BACKEND.md`, `docs/INFRASTRUCTURE.md`, `docs/RUNBOOK-VPS.md`, `docs/CLAUDE_IMPLEMENTATION_PLAN.md`, `docs/PRIVACY_MANIFEST.md`, `Vendor/libsignal/DECISIONS.md`.

---

## Appendix B — Positive Security Controls Observed

| Control | Location |
|---------|----------|
| SPKI pinning, chain validation first, empty-pin fails closed | `CertificatePinner.swift` |
| TLS 1.3 minimum, ephemeral session, no cache/cookies | `RelayClient.swift` |
| HTTPS-only URL construction guard | `RelayRequest.urlRequest` |
| Keychain session credential; no UserDefaults auth | `SessionCredential.swift` |
| AES-GCM sealed records with slot-binding AAD | `EncryptedFileRecordStore.swift`, `SealedAppStore.swift` |
| Path traversal resistant record filenames (SHA-256) | `RecordStore.swift` |
| `@CryptoActor` isolation + `SerialGate` for RMW | `CryptoActor.swift`, `SerialGate.swift` |
| Strict envelope parser; max ciphertext 64 KiB | `Envelope.swift` |
| Refuse `PlaintextContent` on wire | `Envelope.swift` |
| Redacting logger; no `print`/`NSLog` in first-party code | `RedactingLogger.swift` |
| Secure pasteboard (local-only, expiry) | `SecurePasteboard.swift` |
| App switcher snapshot redaction | `RootView.swift` |
| Opaque session tokens, SHA-256 at rest, parameterized SQL | `server/internal/*` |
| Rate limiting fails closed | `server/internal/ratelimit/ratelimit.go` |
| Log redaction + integration tests | `server/internal/httpx/logging.go` |
| Adversarial integration tests | `server/internal/integration/adversarial_integration_test.go` |

---

*End of report. This document is the sole deliverable of the read-only security audit. No source code, dependencies, or project settings were modified.*

---

## Appendix C — Remediation record (added 2026-07-30, after the report)

The report above is left exactly as delivered: it is a dated artefact and editing its findings in
place would destroy the only record of what the tree looked like when it was reviewed. What follows
is what was **done** about each finding, and — as importantly — what was deliberately not.

Every fix below is in `docs/AUDIT.md` with its own permanent id, because that ledger is what the
project's own gates and code comments cite. This table is the crosswalk.

### Fixed

| Report | AUDIT id | What changed | Guarded by |
|---|---|---|---|
| **M-05** | 1.11 | `golang.org/x/text` v0.29.0 → **v0.39.0** (the minimum fixed version, so the diff is the fix and nothing else; it carries `golang.org/x/sync` v0.21.0 because v0.39.0 requires it). Re-vendored. | **New gate:** `Scripts/verify-vulns.sh` runs pinned `govulncheck` as gate 4 of `verify-all.sh`, and again in the release job. Negative-tested by reverting the module. |
| **#2** (immediate) | 1.11 | The gate above. Reachability-based, so it does not report vendored code we never call. Refuses to let the scan rewrite `go.mod`. | Itself; skipped only by `--offline`, which the release gate does not use. |
| **L-07** | **5.22** | **Worse than reported.** The byte quota was not "under-counted on error" — it was *never consulted*: the charge loop's result was discarded and nothing read the bucket, so the real daily ceiling was the 100-upload count limit, ten gigabytes. Now charged once (1 MB before the write, the remainder after), **saturating** so an overrun empties the bucket, and checked before the write. A limiter error removes the bytes and refuses. | 4 integration tests; negative-tested by removing the pre-check and by making `Charge` non-saturating. |
| **L-08** | **5.23** | Rate limits added to `POST /v1/messages/ack` (120/min) and `DELETE /v1/blobs/{id}` (200/hour), keyed by caller rather than by id. | 2 integration tests, each negative-tested by removing the check. |
| **L-09** | **5.24** | `RELAY_RATELIMIT_PEPPER` is now configurable, plumbed through compose, documented in `.env.example`, and **the unconfigured case logs a warning at startup** — previously the weakness was visible only to someone reading `main.go`. | `config` unit tests for the length floor; `BACKEND.md` §5 states both sides of the trade-off. |
| **L-04** | 1.5 | Narrowed, and the recommendation as written ("scope to LibSignalClient only") turns out **not to be implementable**: every target that *embeds* the pod framework needs the exemption, because `[CP] Embed Pods Frameworks` shells out to `rsync` and sandboxed it fails with `deny(1) file-write-unlink` on `LibSignalClient.framework/Info.plist`. Measured target by target. `CipherCrypto` links without embedding, so it is now sandboxed — the target where the identity key and record store live — and the **project default is now `YES`**, so a target added later starts sandboxed. | `bootstrap-targets.rb` asserts the value rather than omitting it (a dropped key survives from the last run that wrote it — AUDIT 6.11 in reverse). |

### Not fixed, deliberately

| Report | Why not |
|---|---|
| **M-01**, **L-06** | Safety-number verification is **P5.S12**, the next-but-one step, with its own gate ("two devices show matching numbers; a substituted identity visibly changes them"). Pulling it forward as a partial would mean shipping an accept-identity affordance without showing the user the key, which is the "Mark as Verified that verifies nothing" AUDIT 5.4 exists about. |
| **M-02**, **L-05** | Prekey rotation and replenishment is **P6.S01**. The witness cap is a documented trade-off (AUDIT 3.1) and lowering it without rotation makes the denial-of-service half worse. |
| **M-03** | Sealed sender is **P7.S01**, a phase of its own, and the wire format already reserves the type space for it. |
| **M-04** | AUDIT 1.1: a hash pins bytes, not origin. Nothing in this tree can fix that until Signal publishes signed provenance; building the FFI from source in reproducible CI is the real answer and is not a P5 change. |
| **L-01** | Profile fields move to the sealed store in **P5.S11** — the immediate next step. |
| **L-02**, **L-03**, **L-10**, **L-11** | Accepted trade-offs with the argument written down: AUDIT 2.1 (NSE needs after-first-unlock), 2.2/2.3 (Rust-side buffers are outside our control), 4.8 (provider snapshots), 5.17 (registrar has no CAA). |
| **#3**, **I-05** | GitHub branch protection is a repository setting, not a file in this tree. Still the operator's. |
| **I-06** | Two-device staging validation is **P5.S13**. |

### One finding the report did not have

**The committed Go vendor tree had drifted from upstream** (`docs/AUDIT.md` 1.12). Found while
re-vendoring for M-05, not by looking: `github.com/google/uuid`'s vendored copy had reformatted doc
comments, so the bytes in the repository were not the bytes upstream published. Comments only, this
time. It matters because `go mod verify` checks the module cache against `go.sum` while a
`-mod=vendor` build reads `vendor/` and compares it to nothing — the one place a modified dependency
could sit indefinitely. `Scripts/verify-relay.sh` now re-vendors to a temporary directory and
requires a byte-identical tree.

### One correction to the report

**§8.3 lists `golang.org/x/sys v0.30.0` as "None in use path".** It is not in `go.mod` at all — it
appears only in `go.sum`, as a checksum for a module the build does not select. That is worth
stating because "in go.sum" and "in the build" are routinely conflated, and a scanner that reads
`go.sum` will keep reporting modules this binary does not contain.

