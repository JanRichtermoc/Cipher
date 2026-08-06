# Working on Cipher

This page records the fresh-checkout traps that are not obvious from the code. Start at
[`README.md`](README.md) for the documentation map; use
[`CLAUDE_IMPLEMENTATION_PLAN.md`](CLAUDE_IMPLEMENTATION_PLAN.md) for sequencing,
[`AUDIT.md`](AUDIT.md) for findings, and [`THREAT_MODEL.md`](THREAT_MODEL.md) for the security
model. When prose and an executable source disagree, the executable source wins.

## The one command

```sh
./Scripts/verify-all.sh          # release evidence
./Scripts/verify-all.sh --fast   # iteration only; skips Release-dependent checks
./Scripts/verify-all.sh --offline # iteration only; skips network-dependent checks
```

The script's ordered `step` calls are the current gate list and count; its output shows exactly
what ran or was skipped. CI invokes the same script, so do not copy that inventory or test totals
into documentation. A fresh successful run is the source for current totals, while named tests and
specific assertions are the source for claimed coverage.

Run the gates serially. The crypto tests are app-hosted (AUDIT 6.6), and concurrent
`xcodebuild test` processes against one simulator can fail preflight with `RequestDenied … Busy`.
Neither `--fast` nor `--offline` is release evidence; the full command must pass before release.

The security gates were **negative-tested** by reintroducing the defects they catch. The
localization gate carries its negative test as `--self-test` and runs it before its own verdict is
trusted. Do not "fix" a gate by making it stop running—a skipped gate can look like a passing one.

## Environment gotchas

**Ruby.** Put Homebrew Ruby before the system Ruby. [`.ruby-version`](../.ruby-version) owns the
Ruby version, and [`Gemfile.lock`](../Gemfile.lock) owns Bundler and gem resolution, including
per-gem checksums.

```sh
export PATH="/opt/homebrew/opt/ruby/bin:$PATH"
bundle install
```

The system Ruby is 2.6 and cannot load the pinned Bundler at all — it fails with
`Could not find 'bundler' (…) required by your Gemfile.lock`, which reads like a missing
gem rather than the wrong interpreter. Export the path first and the message disappears.

**CocoaPods needs a UTF-8 locale, and says so misleadingly.** Without one, `pod install`
dies inside its *error reporter* with
`Unicode Normalization not appropriate for ASCII-8BIT (Encoding::CompatibilityError)` and
a stack trace through `Pod::UserInterface::ErrorReport` — so the real error, whatever it
was, is never printed. Any genuine podspec or resolution failure looks like this until
the locale is set:

```sh
export LANG=en_US.UTF-8
bundle exec pod install
```

**Docker Desktop is not running by default.** `Scripts/verify-relay-integration.sh` needs
it and reports its absence clearly; `open -a Docker` starts it, and it takes a few tens of
seconds before `docker info` succeeds. `Scripts/verify-all.sh` does **not** need Docker —
its relay gate is the container-free half on purpose.

**Go.** Homebrew and the standard Go installer use different prefixes, so include both when the
relay verifier cannot find `go`. [`server/go.mod`](../server/go.mod) owns the required toolchain and
module graph.

```sh
export PATH="/opt/homebrew/bin:/usr/local/go/bin:$PATH"
```

**Adding a Swift or test file.** `pod install` does not update the explicit source membership for
`CipherCrypto`, `CipherCryptoTests`, or `CipherTests`. That is deliberate: dropping a file into a
folder must not silently add it to a security-critical target. After creating or moving one, run:

```sh
bundle exec ruby Scripts/bootstrap-targets.rb
```

The symptom of forgetting is `cannot find type 'X' in scope` for a type that plainly exists. The
app target uses a synchronized folder instead, which is why the app-target manifest gate exists.

**Simulator "Busy".** `verify-all.sh` owns the default simulator, uses `OS=latest`, settles it, and
retries transient preflight failures. Override the simulator only when the default is unavailable:

```sh
export CIPHER_TEST_SIMULATOR="<installed simulator name>"
xcrun simctl shutdown all
xcrun simctl boot "$CIPHER_TEST_SIMULATOR"
xcrun simctl bootstatus "$CIPHER_TEST_SIMULATOR" -b
```

Direct `xcodebuild` commands should mirror the destination assembled by `verify-all.sh`, including
`OS=latest`, so the selected runtime can install the app.

**Build from the workspace, never the bare `.xcodeproj`.** `Scripts/require-workspace.sh` enforces
this as a build phase; the underlying symptom is `No such module 'LibSignalClient'`.

## Toolchain sources

Mutable values belong in executable configuration, not in this page:

| Concern | Canonical source |
|---|---|
| Xcode, CocoaPods, and libsignal pins | [`Vendor/libsignal/PINS.env`](../Vendor/libsignal/PINS.env) |
| Ruby and bundled gems | [`.ruby-version`](../.ruby-version), [`Gemfile.lock`](../Gemfile.lock) |
| Resolved CocoaPods graph | [`Podfile.lock`](../Podfile.lock) |
| Go toolchain and modules | [`server/go.mod`](../server/go.mod), [`server/go.sum`](../server/go.sum) |
| iOS targets and build settings | [`Scripts/bootstrap-targets.rb`](../Scripts/bootstrap-targets.rb), [`Cipher.xcodeproj/project.pbxproj`](../Cipher.xcodeproj/project.pbxproj) |
| CI runner and setup | [`.github/workflows/verify.yml`](../.github/workflows/verify.yml) |

`Pods/` **is committed** so every libsignal Swift-wrapper change remains reviewable. The Rust
binary is fetched at build time and verified against the pin in `PINS.env`.

## Before you push

The repository is public. Keep `AUDIT.md` accurate for external readers, inspect the exact staged
diff, and run the full verifier. Check the Git identity that will become permanent commit metadata:

```sh
git config --get user.name
git config --get user.email
git diff --cached --check
./Scripts/verify-all.sh
```

Git commits require an author email field. Project documentation does not need to publish a
user-specific address; configure a hosting-provider no-reply identity locally when address privacy
is desired. Changing old commit metadata requires rewriting public history, so treat it as a
separate migration rather than routine cleanup.
