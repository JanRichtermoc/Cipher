---
paths:
  - "Cipher/**/*"
  - "CipherTests/**/*"
  - "Cipher.xcodeproj/**/*"
  - "Cipher.xcworkspace/**/*"
  - "Podfile"
  - "Podfile.lock"
---

# iOS and Xcode

- Read `docs/DEVELOPMENT.md` and the applicable `docs/AUDIT.md` rows before changing build, target,
  test, entitlement, manifest, resource, or UI behavior.
- Build and test through `Cipher.xcworkspace`, never the bare project. Serialize simulator tests.
- The app target uses synchronized membership; the framework and test targets use explicit Xcode
  membership. After adding a test file, run `bundle exec ruby Scripts/bootstrap-targets.rb` and
  prove the new test ran by its exact name.
- A successful zero-test run is a failure. Do not use a narrow `-only-testing` invocation as the only
  evidence for a newly added Swift Testing suite.
- `#if DEBUG` fences code, not localized resources. Remove orphaned/debug-only translations and run
  the localization and Release-bundle checks for UI changes.
- Do not change script-sandboxing, entitlements, privacy declarations, deployment target, or target
  membership as incidental cleanup.
