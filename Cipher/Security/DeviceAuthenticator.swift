//
//  DeviceAuthenticator.swift
//  Cipher
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import LocalAuthentication

/// The device-owner check behind the app lock.
///
/// A protocol so the lock can be tested. `LAContext` cannot be driven from a unit test —
/// there is no way to simulate a successful Face ID match, and a test that could would be
/// testing the simulator rather than the policy. What *is* worth testing is everything
/// around it: that a cancel is not a success, that an error is not a success, and that the
/// lock re-engages. Those are the parts that have historically been wrong.
protocol DeviceAuthenticator: Sendable {

    /// Whether the device can perform the check at all — a passcode is set.
    var isAvailable: Bool { get }

    /// Prompts, and returns **only** on an affirmative match.
    ///
    /// - Throws: `DeviceAuthenticationError` for every non-success. There is deliberately no
    ///   `Bool` return: a function returning `false` invites `if !ok { }` with an empty body,
    ///   and the entire class of bug this replaces is "treated a non-success as a success".
    func authenticate(reason: String) async throws
}

enum DeviceAuthenticationError: Error, Equatable {
    /// The user dismissed the prompt, or chose to fall back and then dismissed that.
    /// **Not** a success, and not silently retried.
    case cancelled
    /// No passcode set, biometry unavailable, or the policy cannot be evaluated.
    case unavailable
    /// Evaluation ran and refused: wrong face, wrong passcode, too many attempts.
    case failed
}

// MARK: - The real one

/// `LAContext`, with `.deviceOwnerAuthentication`.
///
/// `.deviceOwnerAuthentication` rather than `.deviceOwnerAuthenticationWithBiometrics`: the
/// former falls back to the device passcode when biometry is unavailable, locked out, or the
/// user prefers it. Requiring biometry would lock out anyone without it — and, worse, would
/// make the lock's protection depend on a hardware feature the user cannot choose, while the
/// passcode it falls back to is the same secret protecting the Keychain item underneath.
struct SystemDeviceAuthenticator: DeviceAuthenticator {

    var isAvailable: Bool {
        LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
    }

    func authenticate(reason: String) async throws {
        let context = LAContext()

        // No "Enter Password" fallback to an app-defined secret: there is no app password,
        // and offering one would be a second, weaker path to the same door.
        context.localizedFallbackTitle = ""

        var availabilityError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &availabilityError)
        else {
            throw DeviceAuthenticationError.unavailable
        }

        do {
            // `evaluatePolicy` returning `false` without throwing is not a documented state,
            // but it is representable — so it is handled as a refusal rather than assumed
            // away. Fail closed on anything that is not an explicit `true`.
            let success = try await context.evaluatePolicy(
                .deviceOwnerAuthentication, localizedReason: reason)
            guard success else { throw DeviceAuthenticationError.failed }
        } catch let error as LAError {
            switch error.code {
            case .userCancel, .appCancel, .systemCancel, .userFallback:
                throw DeviceAuthenticationError.cancelled
            case .passcodeNotSet, .biometryNotAvailable, .biometryNotEnrolled,
                .invalidContext, .notInteractive:
                throw DeviceAuthenticationError.unavailable
            default:
                throw DeviceAuthenticationError.failed
            }
        } catch let error as DeviceAuthenticationError {
            throw error
        } catch {
            // An unrecognised error is a refusal. Mapping the unknown to success is the bug
            // this whole type exists to make impossible.
            throw DeviceAuthenticationError.failed
        }
    }
}
