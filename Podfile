# Cipher — dependency manifest.
#
# Always invoke as `bundle exec pod install` so the CocoaPods version is the one
# pinned in Gemfile.lock. A bare `pod` may be a different version and will
# regenerate the project differently.
#
# Copyright (C) 2026 Jan Richter
# SPDX-License-Identifier: AGPL-3.0-only

# --- Supply-chain pins -------------------------------------------------------
# Read from Vendor/libsignal/PINS.env so there is exactly one place to audit and
# one place to diff. Nothing below is hard-coded.

PINS = File.readlines(File.join(__dir__, 'Vendor', 'libsignal', 'PINS.env'))
           .reject { |l| l.strip.empty? || l.strip.start_with?('#') }
           .map    { |l| l.strip.split('=', 2) }
           .to_h

%w[LIBSIGNAL_TAG LIBSIGNAL_COMMIT LIBSIGNAL_GIT_URL LIBSIGNAL_FFI_PREBUILD_CHECKSUM].each do |key|
  raise "PINS.env is missing #{key}" if PINS[key].to_s.empty?
end

# The podspec's script phase downloads a prebuilt libsignal_ffi.a and verifies it
# against this checksum. Its provenance is recorded in Vendor/libsignal/DECISIONS.md.
ENV['LIBSIGNAL_FFI_PREBUILD_CHECKSUM'] = PINS['LIBSIGNAL_FFI_PREBUILD_CHECKSUM']

platform :ios, '26.5'
use_frameworks!

# LibSignalClient is a Swift pod, so it cannot be a static library.
def libsignal
  pod 'LibSignalClient',
      git: PINS['LIBSIGNAL_GIT_URL'],
      tag: PINS['LIBSIGNAL_TAG']
end

# The app embeds the framework; CipherCrypto compiles and links against it;
# the test bundle needs it directly.
target 'Cipher' do
  libsignal
end

target 'CipherCrypto' do
  libsignal
end

target 'CipherCryptoTests' do
  libsignal
end

# CipherTests is hosted by the app and, from P5.S09, imports CipherCrypto directly
# (invite redemption publishes the real identity key). Without the pod here the
# bundle compiles against a CipherCrypto whose own dependency it cannot see, and
# fails with "Missing required module 'LibSignalClient'".
target 'CipherTests' do
  libsignal
end

post_install do |installer|
  # --- CocoaPods cannot run its script phases under user script sandboxing ----
  # This is a real reduction in build-time isolation, accepted and recorded as a
  # residual risk in Vendor/libsignal/DECISIONS.md. It is compensated by pinning
  # the tag to an immutable commit and verifying the binary checksum independently.
  # Scoped to the targets that actually run a script phase, rather than applied to
  # everything. Attempt at L-04 from the security audit.
  scripted = installer.pods_project.targets.select do |target|
    target.shell_script_build_phases.any?
  end
  scripted.each do |target|
    target.build_configurations.each do |config|
      config.build_settings['ENABLE_USER_SCRIPT_SANDBOXING'] = 'NO'
    end
  end

  # DO NOT raise the pod's IPHONEOS_DEPLOYMENT_TARGET.
  #
  # LibSignalClient.podspec declares `:ios, '15.0'` and that is the configuration
  # Signal builds and tests. Overriding it to 26.5 makes libsignal_ffi.a fail to
  # link with undefined C++ runtime symbols (___cxa_begin_catch,
  # ___gxx_personality_v0) — the archive contains C++ and the newer deployment
  # target changes how the C++ runtime is resolved. A pod built for iOS 15 links
  # correctly into a 26.5 app; there is no reason to touch this.
  # Verified by bisecting M0 against this build, 2026-07-27.

  # --- Consumers must be able to resolve the SignalFfi module ------------------
  # LibSignalClient's swiftmodule references the SignalFfi clang module, so any
  # target that `import LibSignalClient` needs the SignalFfi module map on its
  # search path. swift/README.md documents both halves of this; the podspec only
  # applies them to its own target (HEADER_SEARCH_PATHS/SWIFT_INCLUDE_PATHS live
  # in pod_target_xcconfig, and user_target_xcconfig is empty for a normal install).
  signal_ffi_dir = '"$(PODS_ROOT)/LibSignalClient/swift/Sources/SignalFfi"'

  # CipherTests joined this list in P5.S09: it imports CipherCrypto, whose
  # swiftmodule references SignalFfi, so it needs the module map on its path too.
  consumer_targets = %w[Cipher CipherCrypto CipherCryptoTests CipherTests]

  installer.aggregate_targets.each do |aggregate|
    project = aggregate.user_project

    project.build_configurations.each do |config|
      config.build_settings['SWIFT_ENABLE_EXPLICIT_MODULES'] = 'NO'
    end

    project.native_targets.each do |target|
      next unless consumer_targets.include?(target.name)

      target.build_configurations.each do |config|
        config.build_settings['SWIFT_ENABLE_EXPLICIT_MODULES'] = 'NO'
        # Non-recursive, and $(inherited) so the CocoaPods xcconfig values survive.
        config.build_settings['SWIFT_INCLUDE_PATHS'] = "$(inherited) #{signal_ffi_dir}"
        config.build_settings['HEADER_SEARCH_PATHS'] = "$(inherited) #{signal_ffi_dir}"
      end
    end

    project.save
  end
end
