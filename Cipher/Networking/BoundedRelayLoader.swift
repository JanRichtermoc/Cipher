//
//  BoundedRelayLoader.swift
//  Cipher
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import Synchronization

/// Runs one relay request with a hard ceiling on the bytes it will accept, refusing redirects,
/// and applying the pin to the server-trust challenge.
///
/// ## Why this is not `URLSession.data(for:)`
///
/// `data(for:)` accumulates the whole body in memory with no ceiling. Under
/// `THREAT_MODEL.md` §1.1 the relay is assumed hostile or seized, and a hostile relay does not
/// have to answer with the response the endpoint documents: a chunked reply that never ends
/// costs the server nothing and terminates the app. Nothing above this layer can bound it —
/// by the time `RelayMailbox` decodes JSON, the bytes are already resident.
///
/// A declared `Content-Length` is not the control either, only the cheap half of it: it is a
/// claim by the same party, and a chunked response declares nothing at all
/// (`expectedContentLength` is then `NSURLSessionTransferSizeUnknown`). So the ceiling is
/// enforced twice — the claim is refused before a byte is read, and the bytes are counted as
/// they arrive with the task cancelled the moment they exceed it.
///
/// ## Why the delegate, and why it repeats the pinning
///
/// Bounding delivery requires seeing the body arrive, which is a `URLSessionDataDelegate`
/// callback, which in turn requires a task started with `dataTask(with:)` rather than one of
/// the convenience methods. `URLSession` consults a task's own delegate in preference to the
/// session's, falling back to the session delegate for methods the task delegate does not
/// implement — so a task delegate that stayed silent about authentication challenges would
/// leave the pin depending on a dispatch detail. It would still be applied today, and the
/// symptom of ever being wrong would be silence: connections succeeding unpinned.
///
/// This delegate therefore evaluates the same ``CertificatePinner`` itself. Two objects
/// applying one pinner is the point — whichever one `URLSession` asks, the answer is the same,
/// and `PinningSessionDelegate` remains the session-wide floor for any request that does not
/// come through here.
nonisolated struct BoundedRelayLoader: Sendable {

    private let pinner: CertificatePinner

    init(pinner: CertificatePinner = CertificatePinner()) {
        self.pinner = pinner
    }

    /// Performs `request`, refusing more than `maxResponseBytes` of body.
    ///
    /// - Throws: ``RelayClient/TransportError`` for a refusal this layer decides, `URLError`
    ///   for one the system decides (mapped by ``RelayClient/classify(_:)``), or
    ///   `CancellationError` if the calling task was cancelled.
    func load(
        _ request: URLRequest,
        on session: URLSession,
        maxResponseBytes: Int
    ) async throws -> (body: Data, response: HTTPURLResponse) {

        try Task.checkCancellation()

        let task = session.dataTask(with: request)
        let delegate = Delegate(maxResponseBytes: maxResponseBytes, pinner: pinner)
        task.delegate = delegate

        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                // Attached before `resume`, so no callback can arrive with nowhere to go.
                delegate.attach(continuation)
                task.resume()
            }
        } onCancel: {
            task.cancel()
        }
    }

    // MARK: - Delegate

    /// One request's worth of state. A fresh instance per task, so there is no cross-request
    /// state to reason about and no lifetime tied to the session.
    private final class Delegate: NSObject, URLSessionDataDelegate, Sendable {

        typealias Continuation = CheckedContinuation<(body: Data, response: HTTPURLResponse), any Error>

        private struct State {
            var body = Data()
            var response: HTTPURLResponse?
            /// Set when the ceiling was hit. The task is cancelled to stop the transfer, so
            /// completion arrives as `URLError.cancelled` — this is what distinguishes
            /// "we refused it" from "the user cancelled".
            var exceededLimit = false
            var continuation: Continuation?
            var isFinished = false
        }

        private let state = Mutex(State())
        private let maxResponseBytes: Int
        private let pinner: CertificatePinner

        init(maxResponseBytes: Int, pinner: CertificatePinner) {
            self.maxResponseBytes = maxResponseBytes
            self.pinner = pinner
            super.init()
        }

        func attach(_ continuation: Continuation) {
            state.withLock { $0.continuation = continuation }
        }

        /// Resumes exactly once. Every later completion is dropped rather than trapping: the
        /// task can report cancellation after we have already answered, and a crash there
        /// would be a denial of service a hostile relay could trigger by timing.
        private func finish(_ result: Result<(body: Data, response: HTTPURLResponse), any Error>) {
            let continuation = state.withLock { state -> Continuation? in
                guard !state.isFinished else { return nil }
                state.isFinished = true
                defer { state.continuation = nil }
                return state.continuation
            }
            continuation?.resume(with: result)
        }

        // MARK: Bounding

        func urlSession(
            _ session: URLSession,
            dataTask: URLSessionDataTask,
            didReceive response: URLResponse,
            completionHandler: @escaping (URLSession.ResponseDisposition) -> Void
        ) {
            guard let http = response as? HTTPURLResponse else {
                finish(.failure(RelayClient.TransportError.malformedResponse))
                completionHandler(.cancel)
                return
            }

            // The cheap half: a declared length over the ceiling is refused before any body
            // arrives. `expectedContentLength` is -1 for a chunked response, which is not a
            // pass — it just means the counting below is the only check that applies.
            if http.expectedContentLength > Int64(maxResponseBytes) {
                state.withLock { $0.exceededLimit = true }
                completionHandler(.cancel)
                return
            }

            state.withLock { $0.response = http }
            completionHandler(.allow)
        }

        func urlSession(
            _ session: URLSession,
            dataTask: URLSessionDataTask,
            didReceive data: Data
        ) {
            let overLimit = state.withLock { state -> Bool in
                guard !state.exceededLimit else { return true }
                // Counted before appending: appending first would allocate the very bytes the
                // ceiling exists to refuse.
                guard state.body.count + data.count <= maxResponseBytes else {
                    state.exceededLimit = true
                    state.body = Data()
                    return true
                }
                state.body.append(data)
                return false
            }
            if overLimit { dataTask.cancel() }
        }

        // MARK: Redirects

        /// Refuses every redirect.
        ///
        /// Following one is a decision made by the party we are defending against. A 302 to
        /// another host leaves the pinned origin — the bearer token in the request would be
        /// re-sent to wherever the relay pointed, since `URLSession` carries headers across a
        /// cross-host redirect it initiates — and a 302 back to the same host is a
        /// request the client did not make, with no endpoint on the relay that ever needs one
        /// (`BACKEND.md`: every route answers directly).
        ///
        /// Returning `nil` hands the 3xx back as the response, which every caller's `switch`
        /// already treats as unrecognised. There is no silent failure mode: the request does
        /// not succeed by another route, it fails.
        func urlSession(
            _ session: URLSession,
            task: URLSessionTask,
            willPerformHTTPRedirection response: HTTPURLResponse,
            newRequest request: URLRequest,
            completionHandler: @escaping (URLRequest?) -> Void
        ) {
            completionHandler(nil)
        }

        // MARK: Pinning

        /// The same evaluation `PinningSessionDelegate` performs. See the type comment for why
        /// it is here as well rather than left to delegate fallback.
        func urlSession(
            _ session: URLSession,
            task: URLSessionTask,
            didReceive challenge: URLAuthenticationChallenge,
            completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
        ) {
            guard challenge.protectionSpace.authenticationMethod
                == NSURLAuthenticationMethodServerTrust else {
                completionHandler(.performDefaultHandling, nil)
                return
            }
            guard let trust = challenge.protectionSpace.serverTrust else {
                completionHandler(.cancelAuthenticationChallenge, nil)
                return
            }
            do {
                let validated = try pinner.evaluate(trust, host: challenge.protectionSpace.host)
                completionHandler(.useCredential, URLCredential(trust: validated))
            } catch {
                // No logging of which check refused — see `PinningSessionDelegate`.
                completionHandler(.cancelAuthenticationChallenge, nil)
            }
        }

        // MARK: Completion

        func urlSession(
            _ session: URLSession,
            task: URLSessionTask,
            didCompleteWithError error: (any Error)?
        ) {
            let snapshot = state.withLock { ($0.body, $0.response, $0.exceededLimit) }

            // Checked before the error, because hitting the ceiling cancels the task and the
            // system then reports `URLError.cancelled`. Reading that as a cancellation would
            // report an oversized response as "the user went away".
            if snapshot.2 {
                finish(.failure(RelayClient.TransportError.responseTooLarge))
                return
            }
            if let error {
                finish(.failure(error))
                return
            }
            guard let response = snapshot.1 else {
                finish(.failure(RelayClient.TransportError.malformedResponse))
                return
            }
            finish(.success((snapshot.0, response)))
        }
    }
}
