#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Creates the CipherCrypto framework target and its test target.
#
# This is scripted rather than hand-edited so the project structure is reproducible
# and reviewable. It is idempotent: running it twice leaves the project unchanged.
#
# Run as:  bundle exec ruby Scripts/bootstrap-targets.rb
#
# Copyright (C) 2026 Jan Richter
# SPDX-License-Identifier: AGPL-3.0-only

require 'xcodeproj'

ROOT          = File.expand_path('..', __dir__)
PROJECT_PATH  = File.join(ROOT, 'Cipher.xcodeproj')
DEPLOYMENT    = '26.5'
TEAM          = '22C66TDMT9'
APP_TARGET    = 'Cipher'
FRAMEWORK     = 'CipherCrypto'
TEST_TARGET   = 'CipherCryptoTests'

project = Xcodeproj::Project.open(PROJECT_PATH)

abort "expected objectVersion 77, got #{project.object_version}" unless project.object_version.to_i == 77

app = project.targets.find { |t| t.name == APP_TARGET }
abort "app target #{APP_TARGET} not found" if app.nil?

# ---------------------------------------------------------------------------
# Build settings
# ---------------------------------------------------------------------------

# Applied to the crypto framework and its tests. The deliberate differences from
# the app target are the point of this module:
#
#   SWIFT_VERSION 6.0                  — full Swift 6 semantics, not 5-mode.
#   SWIFT_STRICT_CONCURRENCY complete  — data-race safety is enforced, not hoped for.
#   SWIFT_DEFAULT_ACTOR_ISOLATION      — nonisolated. The app project sets MainActor
#                                        at project level; crypto must NEVER implicitly
#                                        inherit main-actor isolation.
#   warnings as errors                 — a warning in this module is a defect.
CRYPTO_COMMON = {
  'IPHONEOS_DEPLOYMENT_TARGET'          => DEPLOYMENT,
  'SWIFT_VERSION'                       => '6.0',
  'SWIFT_STRICT_CONCURRENCY'            => 'complete',
  'SWIFT_DEFAULT_ACTOR_ISOLATION'       => 'nonisolated',
  'SWIFT_APPROACHABLE_CONCURRENCY'      => 'YES',
  'SWIFT_TREAT_WARNINGS_AS_ERRORS'      => 'YES',
  'GCC_TREAT_WARNINGS_AS_ERRORS'        => 'YES',
  'CLANG_ENABLE_MODULES'                => 'YES',
  'SWIFT_ENABLE_EXPLICIT_MODULES'       => 'NO',
  'ENABLE_USER_SCRIPT_SANDBOXING'       => 'NO',
  'TARGETED_DEVICE_FAMILY'              => '1',
  'CODE_SIGN_STYLE'                     => 'Automatic',
  'DEVELOPMENT_TEAM'                    => TEAM,
  'GENERATE_INFOPLIST_FILE'             => 'YES',
}.freeze

FRAMEWORK_SETTINGS = CRYPTO_COMMON.merge(
  'PRODUCT_NAME'                        => FRAMEWORK,
  'PRODUCT_BUNDLE_IDENTIFIER'           => "cz.janrichtermoc.#{FRAMEWORK}",
  'DEFINES_MODULE'                      => 'YES',
  'SKIP_INSTALL'                        => 'YES',
  'DYLIB_INSTALL_NAME_BASE'             => '@rpath',
  'LD_RUNPATH_SEARCH_PATHS'             => ['$(inherited)', '@executable_path/Frameworks',
                                            '@loader_path/Frameworks'],
  # No UI, no Objective-C interop surface to speak of.
  'SWIFT_OBJC_INTERFACE_HEADER_NAME'    => "#{FRAMEWORK}-Swift.h",
).freeze

TEST_SETTINGS = CRYPTO_COMMON.merge(
  'PRODUCT_NAME'                        => TEST_TARGET,
  'PRODUCT_BUNDLE_IDENTIFIER'           => "cz.janrichtermoc.#{TEST_TARGET}",
  'LD_RUNPATH_SEARCH_PATHS'             => ['$(inherited)', '@executable_path/Frameworks',
                                            '@loader_path/Frameworks'],
  # --- Hosted by the app, and it has to be -----------------------------------
  #
  # A host-less test bundle runs in the bare `xctest` runner, which belongs to no
  # application and therefore has no keychain access group: every SecItem call fails
  # with errSecMissingEntitlement (-34018). The Keychain holds this module's identity
  # private key, so leaving it as the one component with no coverage was not an option.
  #
  # Attaching entitlements directly to the bundle does not work either — for simulator
  # SDKs Xcode sets ENTITLEMENTS_REQUIRED = NO and skips entitlement processing for the
  # bundle entirely, so CODE_SIGN_ENTITLEMENTS is silently ignored (verified 2026-07-27).
  #
  # Hosting in the app is also the more faithful configuration: in production the crypto
  # module runs inside Cipher.app and uses the app's keychain access group, which is
  # exactly what the tests now exercise. The cost is that a broken app target blocks the
  # crypto suite; that is accepted and is why the app target stays a thin shell.
  'TEST_HOST'                           => "$(BUILT_PRODUCTS_DIR)/#{APP_TARGET}.app/" \
                                           "$(BUNDLE_EXECUTABLE_FOLDER_PATH)/#{APP_TARGET}",
  'BUNDLE_LOADER'                       => '$(TEST_HOST)',
  'TEST_TARGET_NAME'                    => APP_TARGET,
  # Warnings-as-errors stays on for tests too: test code is reviewed code.
).freeze

def apply(target, settings)
  target.build_configurations.each do |config|
    settings.each { |k, v| config.build_settings[k] = v }
  end
end

# ---------------------------------------------------------------------------
# Framework target
# ---------------------------------------------------------------------------

framework = project.targets.find { |t| t.name == FRAMEWORK }
if framework.nil?
  framework = project.new_target(:framework, FRAMEWORK, :ios, DEPLOYMENT)
  puts "created target #{FRAMEWORK}"
else
  puts "target #{FRAMEWORK} already exists"
end
apply(framework, FRAMEWORK_SETTINGS)

tests = project.targets.find { |t| t.name == TEST_TARGET }
if tests.nil?
  tests = project.new_target(:unit_test_bundle, TEST_TARGET, :ios, DEPLOYMENT)
  puts "created target #{TEST_TARGET}"
else
  puts "target #{TEST_TARGET} already exists"
end
apply(tests, TEST_SETTINGS)

# ---------------------------------------------------------------------------
# Source files — explicit references, deliberately NOT a synchronized group.
#
# Every file in the security-critical module must be an explicit, reviewable
# entry in the project file. A file cannot join this target by being dropped
# into a folder.
# ---------------------------------------------------------------------------

def sync_sources(project, target, dir_name)
  group = project.main_group[dir_name] || project.main_group.new_group(dir_name, dir_name)

  on_disk = Dir.glob(File.join(ROOT, dir_name, '**', '*.swift')).sort
  wanted  = on_disk.map { |p| Pathname.new(p).relative_path_from(Pathname.new(ROOT)).to_s }

  existing = target.source_build_phase.files.filter_map { |bf| bf.file_ref&.path }

  wanted.each do |rel|
    next if existing.include?(rel)

    ref = group.files.find { |f| f.path == rel } || group.new_reference(File.join(ROOT, rel))
    ref.path = rel
    ref.source_tree = 'SOURCE_ROOT'
    target.add_file_references([ref])
    puts "  + #{rel} -> #{target.name}"
  end

  # Remove references to files that no longer exist on disk.
  target.source_build_phase.files.dup.each do |bf|
    path = bf.file_ref&.path
    next if path.nil? || wanted.include?(path)
    next unless path.start_with?("#{dir_name}/")

    puts "  - #{path} (gone from disk)"
    bf.remove_from_project
  end
end

require 'pathname'
sync_sources(project, framework, 'CipherCrypto')
sync_sources(project, tests,     'CipherCryptoTests')

# ---------------------------------------------------------------------------
# Build guards
# ---------------------------------------------------------------------------

# A pure-Swift framework has no public headers to copy. The empty phase is not
# harmless: because CocoaPods requires ENABLE_USER_SCRIPT_SANDBOXING = NO, the
# build system reports "tasks in 'Copy Headers' are delayed by unsandboxed
# script phases" for it on every build. Removing a phase that has nothing to do
# removes the warning without suppressing anything.
framework.build_phases.select { |p| p.is_a?(Xcodeproj::Project::Object::PBXHeadersBuildPhase) }
         .each do |phase|
  next unless phase.files.empty?

  phase.remove_from_project
  puts "removed the empty Copy Headers phase from #{FRAMEWORK}"
end

# Building the bare .xcodeproj silently drops the Pods project from the build
# graph and fails with "no such module 'LibSignalClient'" inside CipherCrypto,
# pointing at a file that is not the problem. This makes the real cause the
# first thing the build says. It is placed first so it runs before compilation.
GUARD_PHASE_NAME = 'Guard: build from Cipher.xcworkspace'

[app, framework, tests].each do |target|
  existing = target.shell_script_build_phases.find { |p| p.name == GUARD_PHASE_NAME }
  phase = existing || target.new_shell_script_build_phase(GUARD_PHASE_NAME)

  phase.shell_path = '/bin/sh'
  phase.shell_script = %("${SRCROOT}/Scripts/require-workspace.sh"\n)
  # No inputs and no outputs: what this phase checks is which container Xcode was
  # launched from, which is not a file dependency. Dependency analysis would let it be
  # skipped in exactly the build where it needs to speak.
  phase.always_out_of_date = '1'
  phase.show_env_vars_in_log = '0'

  next if target.build_phases.first == phase

  target.build_phases.delete(phase)
  target.build_phases.unshift(phase)
  puts "#{target.name}: #{GUARD_PHASE_NAME} runs first"
end

# ---------------------------------------------------------------------------
# Wiring: tests depend on the framework; the app depends on and embeds it.
# ---------------------------------------------------------------------------

unless tests.dependencies.any? { |d| d.target == framework }
  tests.add_dependency(framework)
  puts "#{TEST_TARGET} depends on #{FRAMEWORK}"
end
# The test bundle is injected into the app (see TEST_HOST), so the app must be built and
# installed before the suite can run.
unless tests.dependencies.any? { |d| d.target == app }
  tests.add_dependency(app)
  puts "#{TEST_TARGET} depends on #{APP_TARGET} (test host)"
end
unless tests.frameworks_build_phase.files.any? { |f| f.display_name == "#{FRAMEWORK}.framework" }
  tests.frameworks_build_phase.add_file_reference(framework.product_reference)
end

unless app.dependencies.any? { |d| d.target == framework }
  app.add_dependency(framework)
  puts "#{APP_TARGET} depends on #{FRAMEWORK}"
end
unless app.frameworks_build_phase.files.any? { |f| f.display_name == "#{FRAMEWORK}.framework" }
  app.frameworks_build_phase.add_file_reference(framework.product_reference)
  puts "#{APP_TARGET} links #{FRAMEWORK}.framework"
end

# Embed the framework in the app bundle.
embed = app.copy_files_build_phases.find { |p| p.name == 'Embed CipherCrypto' }
if embed.nil?
  embed = app.new_copy_files_build_phase('Embed CipherCrypto')
  embed.symbol_dst_subfolder_spec = :frameworks
  puts "#{APP_TARGET} gained an Embed CipherCrypto phase"
end
unless embed.files.any? { |f| f.display_name == "#{FRAMEWORK}.framework" }
  bf = embed.add_file_reference(framework.product_reference)
  bf.settings = { 'ATTRIBUTES' => ['CodeSignOnCopy', 'RemoveHeadersOnCopy'] }
end

# The Embed phase must run before the Pods embed phase's code signing settles;
# keeping it immediately after Frameworks is the conventional, stable position.

# ---------------------------------------------------------------------------
# iPhone-only for the app (PLAN decision: TARGETED_DEVICE_FAMILY = 1)
# ---------------------------------------------------------------------------
app.build_configurations.each do |config|
  config.build_settings['TARGETED_DEVICE_FAMILY'] = '1'
end

project.save
puts "saved #{PROJECT_PATH}"
