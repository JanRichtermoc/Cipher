# Required-reason API enumeration

**Closes:** AUDIT 6.1 · **Plan step:** P1.S11 (finishes in P8.S05)
**Verified:** 2026-07-28, against libsignal `v0.99.1` / `97801d22dcf9f5bf714f7b8fa3212cdc973ae1c8`
**Enforced by:** [`Scripts/verify-privacy-manifest.sh`](../Scripts/verify-privacy-manifest.sh),
invoked by [`Scripts/verify-all.sh`](../Scripts/verify-all.sh)

Apple requires a declared reason for five API categories. The requirement attaches to what is
**in the shipped bundle**, not to what the app calls — and libsignal is a *dynamic* framework, so
its entire 18 MB symbol surface ships whether or not one line of Cipher reaches it. Nothing is
dead-stripped. `Cipher.app/Cipher` is clean while `Frameworks/LibSignalClient.framework` beside it
is not; scanning the app binary alone gives a false all-clear, which is how the first pass at this
went wrong.

libsignal ships no `PrivacyInfo.xcprivacy` of its own (`Vendor/libsignal/DECISIONS.md`, Q2), so its
usage has to be enumerated here and merged into `Cipher/PrivacyInfo.xcprivacy`.

---

## Method, and what it does and does not prove

| Evidence | Strength | Applies to |
|---|---|---|
| `nm -u` on each Mach-O in the built `.app` | **Proof.** A C call cannot be made without an undefined external — `fstat()` is unreachable without `_fstat`. | The C half of each Apple list, in **all** code including the prebuilt Rust `.a` |
| `strings -a` for distinctive spellings | Evidence. `standardUserDefaults` is unambiguous; bare `creationDate` is not, so it is not matched here. | Objective-C selectors with distinctive names |
| Source grep | Proof for code we can read | `Cipher/`, `CipherCrypto/`, `Pods/LibSignalClient/swift/` |

The gap this leaves is Swift/Objective-C usage inside code we cannot read — the Rust core reached
through the Objective-C runtime. It is closed by construction rather than by scanning: the Rust
core is platform-agnostic and its Foundation link comes from the Swift wrapper, which is source-
grepped clean below. If a future libsignal version changes that, the C-symbol scan still holds and
the source grep still runs.

---

## Findings — all five categories

| Category | In bundle? | Evidence | Declared | Status |
|---|---|---|---|---|
| `…FileTimestamp` | **yes** | `_fstat`, undefined external in `LibSignalClient.framework` (Rust core, `signal_ffi-…cgu.0.rcgu.o`) | yes, `C617.1` | **VERIFIED** |
| `…UserDefaults` | **yes** | `standardUserDefaults` literal in the `Cipher` binary — `AppSession` onboarding/lock/display state | yes, `CA92.1` | **VERIFIED** |
| `…DiskSpace` | no | no `statfs`/`statvfs`/`fstatfs`/`fstatvfs`/`getattrlist` external in any binary; no volume-capacity key literal | not declared | **VERIFIED ABSENT** |
| `…SystemBootTime` | no | no `mach_absolute_time`, no `systemUptime`. libsignal reaches for time via `clock_gettime` and `gettimeofday`, **neither of which is on Apple's list** — see below | not declared | **VERIFIED ABSENT** (with a judgement call) |
| `…ActiveKeyboards` | no | no `activeInputModes` in any binary | not declared | **VERIFIED ABSENT** |

### Source grep — libsignal's Swift wrapper

All 136 files under `Pods/LibSignalClient/swift/Sources/`, searched for every symbol on all five
Apple lists: **no hits in any category.** Every required-reason API in the framework therefore
comes from the Rust core, which is why the binary scan is the load-bearing evidence.

---

## The two judgement calls

**1. `C617.1` as the reason for libsignal's `fstat`.** `C617.1` is "files inside the app container".
Cipher never hands libsignal a path: `CipherCrypto` owns all storage and passes `Data`, so any file
libsignal opens is one it created inside our container. The symbol most likely comes from Rust
`std`'s read path sizing a buffer. This holds **only while that stays true** — if a future step
gives libsignal a path (message-backup import/export is the realistic case), re-derive the reason
before shipping. Cipher's own `FileTimestamp` use is separate and already `C617.1`: the record
store reads directory contents for prekey counts and sets `isExcludedFromBackup`.

**2. `clock_gettime` and `gettimeofday` are not declared.** Both are present in
`LibSignalClient.framework`. Apple's `SystemBootTime` list names exactly two APIs — `systemUptime`
and `mach_absolute_time` — and neither of these is one of them, so no declaration is required as
the rule is written. Recorded rather than omitted because the *intent* of that category is close to
what `clock_gettime(CLOCK_UPTIME_RAW)` does, and Apple has expanded these lists before. If it is
ever expanded to cover them, this is where to look. `gettimeofday` comes from BoringSSL
(`ssl_lib.cc.o`) and is wall-clock, not boot time.

---

## On a libsignal bump

`Scripts/verify-privacy-manifest.sh` runs on every full `verify-all.sh` and fails if a category
appears in the bundle that the manifest does not declare — so a version bump that introduces one
fails the build rather than App Review. It also notes a declared category that is no longer
detected, which usually means the dependency changed under us.

Re-run the Swift source grep by hand on a bump; it is not automated because it depends on
`Pods/` being present, and the useful half (the C symbols) is already covered mechanically.

**Still outstanding for submission** — neither is an engineering determination:
`ITSAppUsesNonExemptEncryption` (AUDIT 6.3) and the libsignal acknowledgements screen (AUDIT 6.2).
