//
//  BoundedResponseLoader.swift
//  Cipher
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import Synchronization

/// Loads one relay response with a hard ceiling on the bytes it will buffer, and refuses to
/// follow a redirect.
///
/// ## Why `URLSession.data(for:)` is not enough
///
/// It buffers the whole body before returning it, and the only bound it honours is a timeout.
/// A relay that answers `Transfer-Encoding: chunked` and never stops costs the *server* nothing
/// and costs this device memory until it is killed — and nothing above the transport can
/// intervene, because by the time a `Data` exists for `JSONDecoder` to look at, the bytes are
/// already resident. `THREAT_MODEL.md` §1.1 assumes the relay is hostile or seized, so the
/// ceiling belongs at the point where bytes arrive, not at the point where they are parsed.
///
/// The declared `Content-Length` is checked first, but that is an **early-out and not the
/// control**: a chunked response declares no length at all, and the party declaring it is the
/// same party sending the body. The counter over the arriving bytes is what actually bounds it.
///
/// ## Why it also refuses redirects
///
/// `URLSession` follows them by default. Every authenticated relay request carries a bearer
/// token in an `Authorization` header, and a 302 to another host would re-send that token
/// wherever the relay pointed — to a host these pins say nothing about. A redirect is handed
/// back to the caller as an ordinary unrecognised status instead.
///
/// ## What this deliberately does not do
///
/// It never handles an authentication challenge. Pinning has exactly one home
/// (``PinningSessionDelegate``, installed as the *session* delegate), and a task delegate that
/// implemented a challenge method would silently take that dispatch away from it — the failure
/// mode being a client that still works, with no pinning. `RelayTransportTests` asserts this
/// class does not respond to either challenge selector.
nonisolated final class BoundedResponseLoader: NSObject, URLSessionDataDelegate, @unchecked Sendable {

    /// Why a load produced no usable response.
    enum Failure: Error, Equatable {
        /// The body exceeded ``byteCeiling``, or declared that it would. The task was cancelled.
        case responseTooLarge
        /// The response was not HTTP.
        case notHTTP
    }

    private struct State {
        var body = Data()
        var response: HTTPURLResponse?
        var continuation: CheckedContinuation<(HTTPURLResponse, Data), any Error>?
        /// Set before the task is cancelled for exceeding the ceiling, so the `URLError`
        /// that cancellation produces is reported as what it is rather than being classified
        /// as a transport or TLS fault.
        var overflowed = false
        var finished = false
    }

    private let state = Mutex(State())
    private let byteCeiling: Int

    init(byteCeiling: Int) {
        self.byteCeiling = byteCeiling
        super.init()
    }

    /// Runs `request` on `session` and returns its response and body, or throws.
    ///
    /// The loader is the task's delegate, so one instance serves one request; `RelayClient`
    /// makes a fresh one per attempt.
    func load(_ request: URLRequest, on session: URLSession) async throws -> (HTTPURLResponse, Data) {
        let task = session.dataTask(with: request)
        task.delegate = self

        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let alreadyFinished = state.withLock { state -> Bool in
                    guard !state.finished else { return true }
                    state.continuation = continuation
                    return false
                }
                // Cancellation can land between `dataTask(with:)` and here, in which case the
                // handler below has already run and the task will never call back.
                if alreadyFinished {
                    continuation.resume(throwing: CancellationError())
                    return
                }
                task.resume()
            }
        } onCancel: {
            state.withLock { $0.finished = true }
            task.cancel()
        }
    }

    /// Resumes the waiting caller exactly once. Every completion path goes through here.
    private func finish(_ result: Result<(HTTPURLResponse, Data), any Error>) {
        let continuation = state.withLock { state -> CheckedContinuation<(HTTPURLResponse, Data), any Error>? in
            guard !state.finished else { return nil }
            state.finished = true
            defer { state.continuation = nil }
            return state.continuation
        }
        continuation?.resume(with: result)
    }

    // MARK: - URLSessionTaskDelegate

    /// Refuses the redirect. Passing `nil` leaves the 3xx as the task's own response, which is
    /// what the caller then sees — an unrecognised status, handled like any other.
    func urlSession(_ session: URLSession,
                    task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: (any Error)?) {
        // The overflow flag wins over the error: cancelling the task to enforce the ceiling
        // surfaces as `URLError.cancelled`, which is also how a refused pin arrives.
        if state.withLock({ $0.overflowed }) {
            finish(.failure(Failure.responseTooLarge))
            return
        }
        if let error {
            finish(.failure(error))
            return
        }
        let captured = state.withLock { ($0.response, $0.body) }
        guard let response = captured.0 else {
            finish(.failure(Failure.notHTTP))
            return
        }
        finish(.success((response, captured.1)))
    }

    // MARK: - URLSessionDataDelegate

    func urlSession(_ session: URLSession,
                    dataTask: URLSessionDataTask,
                    didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard let http = response as? HTTPURLResponse else {
            completionHandler(.cancel)
            finish(.failure(Failure.notHTTP))
            return
        }

        // An honest `Content-Length` saves reading a body that is already known to be refused.
        // A dishonest or absent one changes nothing: the counter below is the actual bound.
        if response.expectedContentLength > Int64(byteCeiling) {
            state.withLock { $0.overflowed = true }
            completionHandler(.cancel)
            return
        }

        state.withLock { $0.response = http }
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        let exceeded = state.withLock { state -> Bool in
            guard !state.overflowed else { return true }
            guard state.body.count + data.count <= byteCeiling else {
                state.overflowed = true
                return true
            }
            state.body.append(data)
            return false
        }
        if exceeded {
            // Stop the transfer rather than merely refusing the result: the point is not to
            // receive the rest of an unbounded body.
            dataTask.cancel()
        }
    }

    /// Nothing about a relay response may reach the URL cache. The session is already
    /// ephemeral with `urlCache = nil`; this is the same decision stated where a future
    /// configuration change cannot quietly undo it.
    func urlSession(_ session: URLSession,
                    dataTask: URLSessionDataTask,
                    willCacheResponse proposedResponse: CachedURLResponse,
                    completionHandler: @escaping (CachedURLResponse?) -> Void) {
        completionHandler(nil)
    }
}
