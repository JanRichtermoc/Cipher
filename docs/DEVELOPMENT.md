# Working on Cipher

The things a fresh checkout gets wrong. Everything else is in
[`CLAUDE_IMPLEMENTATION_PLAN.md`](CLAUDE_IMPLEMENTATION_PLAN.md) (what to build next),
[`AUDIT.md`](AUDIT.md) (what is broken), and [`THREAT_MODEL.md`](THREAT_MODEL.md) (who we
defend against).

## The one command

```sh
./Scripts/verify-all.sh          # everything, ~30 min
./Scripts/verify-all.sh --fast   # skips the Release device build and the two audits that need it
```

Ten gates, in dependency order, stopping at the first failure. CI runs this exact script —
one gate, one definition. Never parallelise it: the crypto tests are app-hosted (AUDIT 6.6)
and two `xcodebuild test` runs against one simulator fail preflight with `RequestDenied …
Busy`.

| # | Gate | Script |
|---|---|---|
| 1 | Supply chain — tag still resolves to the pinned commit, checksum matches | `verify-supply-chain.sh` |
| 2 | App-target file manifest | `verify-app-target-manifest.sh` |
| 3 | No `print`/`NSLog` in `CipherCrypto` | inline |
| 4 | UI honesty and localization drift | `verify-localization.py` |
| 5 | No LibSignalClient type in the public API | `verify-api-boundary.sh` |
| 6 | 105 crypto tests (app-hosted, serial) | inline |
| 7 | App builds (simulator) | inline |
| 8 | Release arm64 device build | inline |
| 9 | No debug affordance anywhere in the Release **bundle** | inline |
| 10 | Required-reason APIs declared | `verify-privacy-manifest.sh` |

Gates 4, 5, 9 and 10 were each **negative-tested** by reintroducing the defect they catch;
gate 4 carries that negative test as `--self-test` and runs it before its own verdict is
believed. Do not "fix" a gate by making it pass — a gate that stops running looks exactly
like a gate that passes, which has already happened here once.

## Environment gotchas

**Ruby.** `bundle` must be the Homebrew Ruby (4.0.6), not `/usr/bin/ruby` (2.6), which fails
with `Could not find 'bundler' (4.0.16)`. `Gemfile.lock` carries per-gem checksums that older
bundlers ignore rather than verify.

```sh
export PATH="/opt/homebrew/opt/ruby/bin:$PATH"
```

**Adding a file to `CipherCrypto` or `CipherCryptoTests`.** `pod install` does *not* pick it
up. The targets use explicit file references rather than a synchronized group, deliberately —
a file must not join a security-critical module by being dropped in a folder. After creating
one:

```sh
bundle exec ruby Scripts/bootstrap-targets.rb
```

The symptom of forgetting is `cannot find type 'X' in scope` for a type that plainly exists.
(The app target *does* use a synchronized folder, which is why gate 2 exists for it.)

**Simulator "Busy".** A bare `xcodebuild test` right after a build often fails with
`Application failed preflight checks … Busy`. `verify-all.sh` settles and retries; if running
`xcodebuild` directly, do it yourself first:

```sh
xcrun simctl shutdown all; xcrun simctl boot "iPhone 17 Pro"; xcrun simctl bootstatus "iPhone 17 Pro" -b
```

**Destination.** Always `OS=latest`. CI ships iOS 26.2, 26.4 and 26.5 runtimes while the
deployment target is 26.5, so a bare `name=` destination lets xcodebuild pick one that cannot
install the app.

**Build from the workspace, never the bare `.xcodeproj`** — `Scripts/require-workspace.sh` is
wired in as a build phase and will tell you, but the underlying symptom is
`No such module 'LibSignalClient'`.

## Toolchain

Pinned in [`../Vendor/libsignal/PINS.env`](../Vendor/libsignal/PINS.env), which is the single
source of truth — nothing may hard-code these values, including CI, which reads
`VERIFIED_XCODE` from it to choose an Xcode.

Xcode 26.6 · iOS deployment target 26.5 · CocoaPods 1.17.0 · Ruby 4.0.6 ·
libsignal v0.99.1 (`97801d22dcf9f5bf714f7b8fa3212cdc973ae1c8`)

`Pods/` **is committed**, deliberately: it keeps the libsignal Swift wrapper diffable on every
bump. The Rust binary is not in it — `libsignal_ffi.a` is fetched at build time and pinned by
checksum.

## Before you push

The repo is **public**. Two habits follow from that: commits are authored as
`194924887+JanRichtermoc@users.noreply.github.com` (a real address in git history cannot be
recalled), and `AUDIT.md` is read by strangers — which is fine and intended, but it means an
entry has to be accurate rather than reassuring.
