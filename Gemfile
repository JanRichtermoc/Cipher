# Build-toolchain pin.
#
# CocoaPods regenerates the Xcode project, so its version is part of the build's
# reproducibility surface. It is pinned here and locked in Gemfile.lock so every
# machine and CI runner produces an identical project.
#
# Always invoke as `bundle exec pod ...` — never a bare `pod`, which may resolve
# to a different Homebrew- or gem-installed version.

source "https://rubygems.org"

gem "cocoapods", "1.17.0"
