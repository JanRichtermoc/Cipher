# libsignal — dependency decisions and M0 verification record

## Pinned dependency

| Field | Value |
|---|---|
| Library | `LibSignalClient` |
| Source | `https://github.com/signalapp/libsignal.git` |
| Pin | tag `v0.99.1` (released 2026-07-23T21:05:42Z) |
| License | **AGPL-3.0-only** — Cipher is therefore AGPL-3.0 |
| Integration | **CocoaPods** |
| Prebuilt FFI archive | `libsignal-client-ios-build-v0.99.1.tar.gz` from `build-artifacts.signal.org` |
| `LIBSIGNAL_FFI_PREBUILD_CHECKSUM` | `c7b1ad515b0698497f051cb7a65e0d9a6e1e5d707db82aa334fa8c834e3e4fd8` |

The checksum is taken verbatim from the official GitHub release asset
`libsignal-client-ios-build-v0.99.1.tar.gz.sha256`. That asset is the **only** authenticity anchor
Signal publishes for iOS — the binary is not signed and carries no SLSA provenance.

## Why not Swift Package Manager

Not a preference — it is impossible.

- There is **no `Package.swift` at the repository root**, so a remote SPM URL cannot resolve.
- `swift/Package.swift` uses `.systemLibrary` and `.unsafeFlags`; SwiftPM rejects `unsafeFlags` in a
  dependency graph.
- `swift/README.md` states verbatim: *"## Use as a Swift Package … is not supported."*

CocoaPods is the canonical path and is what Signal-iOS itself uses.

---

## M0 smoke test — verification record

Run 2026-07-27 against a throwaway copy of the project. **Result: all gates PASS.**

### Environment

| Component | Version |
|---|---|
| Xcode | 26.6 (17F113) |
| Swift | 6.3.3 |
| iOS SDK | 26.5 |
| CocoaPods | 1.17.0 (Homebrew, own Ruby 4.0.6 — system Ruby untouched) |
| `xcodeproj` gem | 1.28.1 |

### Gates

| # | Gate | Result |
|---|---|---|
| 1 | `xcodeproj` parses `objectVersion 77` and `PBXFileSystemSynchronizedRootGroup` | **PASS** |
| 2 | `pod install` integrates without corrupting the project; synchronized root group survives | **PASS** |
| 3 | Debug simulator build succeeds; `LibSignalClient.framework` embedded | **PASS** (826 `signal_*` symbols linked) |
| 4 | Downloaded archive hash matches the official release asset | **PASS** — recomputed `c7b1ad51…4e3e4fd8` over the 153 MB download; exact match |
| 5 | Release **arm64 device** build succeeds; framework embedded | **PASS** (647 `signal_*` symbols, `arm64`) |
| 6 | Real cryptography executes at runtime | **PASS** — 13/13, see below |

### Runtime gates (simulator, iPhone 17 Pro)

```
PASS bundle carries a Kyber prekey
PASS session established
PASS session is fully post-quantum          (hasCurrentState(requirePqRatio: 1.0))
PASS remote registration id matches
PASS first message is a preKey message
PASS Alice -> Bob decrypts correctly
PASS one-time prekey consumed by the library
PASS reply is a whisper message             (ratchet stepped)
PASS Bob -> Alice decrypts correctly
PASS replay rejected as duplicatedMessage
PASS safety numbers agree on both sides
PASS scannable fingerprints compare equal
PASS malformed public key rejected          (invalid-curve protection)
```

This confirms empirically, not just by reading source: PQXDH is mandatory and functioning, the
Double Ratchet steps, replays surface as `duplicatedMessage`, libsignal removes consumed one-time
prekeys itself, and fingerprint generation/comparison works.

### Required build settings (discovered, not guessed)

| Setting | Value | Why |
|---|---|---|
| `ENABLE_USER_SCRIPT_SANDBOXING` | **`NO`** | Was `YES` at `project.pbxproj:167` and `:231`. CocoaPods' script phases cannot run under sandboxing. **This is a real reduction in build-time isolation** — accepted, compensated by pinning and independent checksum verification. |
| `SWIFT_ENABLE_EXPLICIT_MODULES` | **`NO`** | The podspec only sets this under a testing env var, so a normal consumer must set it. |
| `use_frameworks!` | required | `LibSignalClient` is a Swift pod. |

### Answered open questions

- **Q1 — Does CocoaPods handle `objectVersion 77` + `PBXFileSystemSynchronizedRootGroup`?**
  **Yes.** `xcodeproj` 1.28.1 parses and round-trips it; the synchronized root group survives
  `pod install` intact.
- **Q2 — Does the pod ship a `PrivacyInfo.xcprivacy`?**
  **No.** Confirmed absent from both `Pods/LibSignalClient` and the built app. Cipher must supply
  its own privacy manifest, and the libsignal-attributable API usage must be declared there.
  Blocks App Store submission if left unhandled.

### Residual supply-chain gaps (accepted, must appear in `AUDIT.md`)

1. The iOS FFI binary is **not signed and not attested**. A SHA-256 pins bytes, not provenance.
2. `bin/fetch_archive.py` enforces the checksum with a bare Python `assert`, which `python -O`
   strips. We therefore verify independently rather than trusting the pod's own check.
3. `Podfile.lock` records the **tag**, not the resolved commit SHA. A tag is mutable upstream.
   Pin the commit explicitly (see `PINS.env`).
4. libsignal is deliberately `0.x`: Signal does not promise stability between releases, and the
   cadence is rapid (8 releases in the 13 days before v0.99.1).
