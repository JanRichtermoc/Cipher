#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Creates SHARED schemes.
#
# This matters for correctness, not tidiness: a test target with no shared scheme
# means CI runs zero tests and reports success. Shared schemes are committed so
# every machine and CI runner builds and tests exactly the same thing.
#
# Run as:  PATH="/opt/homebrew/opt/ruby/bin:$PATH" bundle exec ruby Scripts/bootstrap-schemes.rb
#
# Copyright (C) 2026 Jan Richter
# SPDX-License-Identifier: AGPL-3.0-only

require 'xcodeproj'
require 'fileutils'

ROOT         = File.expand_path('..', __dir__)
PROJECT_PATH = File.join(ROOT, 'Cipher.xcodeproj')

project = Xcodeproj::Project.open(PROJECT_PATH)

def target!(project, name)
  project.targets.find { |t| t.name == name } or abort "target #{name} not found"
end

app       = target!(project, 'Cipher')
framework = target!(project, 'CipherCrypto')
tests     = target!(project, 'CipherCryptoTests')

shared_dir = File.join(PROJECT_PATH, 'xcshareddata', 'xcschemes')
FileUtils.mkdir_p(shared_dir)

# --- CipherCrypto: build the framework, run the crypto tests -----------------
# Debug for tests so assertions and the CryptoActor isolation preconditions are live.
crypto = Xcodeproj::XCScheme.new
crypto.add_build_target(framework)
crypto.add_test_target(tests)
crypto.set_launch_target(framework)
crypto.test_action.build_configuration  = 'Debug'
# Dependency order, not manual order. Xcode deprecated manual ordering and warns on every
# build; the ordering it replaces is already expressed as real target dependencies
# (tests -> framework -> Pods), so nothing is lost by letting the build system derive it.
crypto.build_action.parallelize_buildables = true
crypto.build_action.build_implicit_dependencies = true
crypto.launch_action.build_configuration = 'Debug'
crypto.analyze_action.build_configuration = 'Debug'
crypto.archive_action.build_configuration = 'Release'
crypto.profile_action.build_configuration = 'Release'
crypto.save_as(PROJECT_PATH, 'CipherCrypto', true)
puts 'shared scheme: CipherCrypto (builds framework, runs CipherCryptoTests)'

# --- Cipher: the app, with the crypto tests attached -------------------------
# Running the crypto suite from the app scheme means a plain `xcodebuild test`
# on the app cannot pass while the crypto contract tests are broken.
app_scheme = Xcodeproj::XCScheme.new
app_scheme.add_build_target(app)
app_scheme.add_test_target(tests)
app_scheme.set_launch_target(app)
app_scheme.test_action.build_configuration   = 'Debug'
app_scheme.launch_action.build_configuration = 'Debug'
app_scheme.analyze_action.build_configuration = 'Debug'
app_scheme.archive_action.build_configuration = 'Release'
app_scheme.profile_action.build_configuration = 'Release'
app_scheme.save_as(PROJECT_PATH, 'Cipher', true)
puts 'shared scheme: Cipher (builds app, runs CipherCryptoTests)'

# Remove the stale per-user schemes so there is no ambiguity about which is real.
Dir.glob(File.join(PROJECT_PATH, 'xcuserdata', '*', 'xcschemes', '*.xcscheme')).each do |path|
  next unless %w[Cipher.xcscheme CipherCrypto.xcscheme].include?(File.basename(path))

  FileUtils.rm_f(path)
  puts "removed user scheme #{path.sub("#{ROOT}/", '')}"
end

puts 'done'
