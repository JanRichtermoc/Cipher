//
//  RelayClient.swift
//  Cipher
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

/// HTTP transport for the relay. HTTPS only, TLS 1.3 only, public-key pinned, failing closed.
///
/// This type owns the *transport* and nothing above it: no invite redemption, no message
/// encoding, no session refresh. Those arrive in P5.S09 and P5.S10 and will be built on top of
/// ``send(_:)``. Keeping them out means the pinning and retry behaviour has one place to be
/// audited rather than being re-implemented per endpoint.
nonisolated struct RelayClient: Sendable {

    /// Transport-level outcomes. HTTP status codes are *not* errors here — a 401 is a fact
    /// about the response, and deciding what it means belongs to the caller that knows what it
    /// asked for.
    enum TransportError: Error, Equatable {
        /// TLS failed, most likely the pin. Indistinguishable from other TLS faults on purpose:
        /// the pinner does not report which check refused (see `PinningSessionDelegate`).
        case secureConnectionFailed
        /// Network unreachable, DNS failure, timeout, cancelled.
        case unreachable
        /// The server answered with something that is not an HTTP response.
        case malformedResponse
        /// The body exceeded the ceiling for this request and the transfer was cancelled.
        /// Never retried: a relay that answers with too much answers with too much again.
        case responseTooLarge
        /// Retries were exhausted while the server kept returning a retryable status.
        case exhaustedRetries(lastStatus: Int)
    }

    struct Response: Sendable {
        let status: Int
        let body: Data
        /// Keys are **lowercased**. `HTTPURLResponse` canonicalises header names today, so
        /// this is defence against a platform behaviour this code does not control rather
        /// than a break anyone has observed — but a case-sensitive lookup for `Retry-After`
        /// is a rate limit silently ignored, which is the shape of failure that turns a
        /// limiter into a stampede.
        let headers: [String: String]

        /// Case-insensitive by construction; see ``headers``.
        func header(_ name: String) -> String? { headers[name.lowercased()] }
    }

    /// How long any single attempt may take before it is abandoned.
    ///
    /// Deliberately shorter than the relay's own 120 s proxy read timeout for ordinary calls:
    /// the client should give up and retry before Nginx does, so a stuck request costs one
    /// backoff rather than two minutes of a spinner. Blob transfer overrides this.
    static let requestTimeout: TimeInterval = 30

    /// Ceiling on a whole call including retries.
    ///
    /// `URLSessionConfiguration.timeoutIntervalForResource` bounds **one task**, and a call
    /// here is up to ``maxAttempts`` tasks with backoff between them — so on its own that
    /// setting named a bound the code did not have. ``send(_:)`` enforces this one against
    /// `ContinuousClock`, which is monotonic: a clock correction cannot extend or collapse a
    /// call already in flight.
    static let resourceTimeout: TimeInterval = 120

    /// Attempts, not retries: 1 means "try once, never retry".
    static let maxAttempts = 3

    /// Bytes a relay response may occupy before the transfer is cancelled.
    ///
    /// Every endpoint but the fetch answers with a small JSON object — a session token, a
    /// prekey bundle, two counts — so 64 KiB is generous by two orders of magnitude and is
    /// still a bound. See ``BoundedResponseLoader``.
    static let defaultResponseCeiling = 64 * 1024

    /// The fetch ceiling, **derived from the relay's own limits rather than picked**: one
    /// batch is at most `api.maxFetchBatch` messages, each a base64 envelope of at most
    /// `store.MaxEnvelopeBytes`, plus the id and JSON punctuation around it.
    ///
    /// Deriving it means a relay-side limit change makes this wrong loudly (the arithmetic no
    /// longer matches the constants it cites) rather than quietly refusing legitimate batches.
    static let fetchResponseCeiling: Int = {
        let base64EnvelopeBytes = 4 * ((RelayMailbox.maxEnvelopeBytes + 2) / 3)
        // id, field names, quotes, commas, and room for the `more` flag and object braces.
        // Generous on purpose: a margin costs memory only in the worst case, while a margin
        // that is too thin refuses a legitimate full batch.
        let perMessageOverhead = 256
        return RelayMailbox.maxFetchBatch * (base64EnvelopeBytes + perMessageOverhead) + 1024
    }()

    private let session: URLSession
    private let baseURL: URL

    /// Injectable so tests can drive the retry logic without sleeping. Returns seconds.
    private let jitter: @Sendable (ClosedRange<Double>) -> Double

    /// The whole-call ceiling this instance enforces. Injectable for the same reason as
    /// ``jitter``: a test that proves the deadline is one budget across attempts should not
    /// take ``resourceTimeout`` seconds to say so.
    private let callDeadline: TimeInterval

    init(baseURL: URL = RelayEndpoint.baseURL,
         session: URLSession? = nil,
         callDeadline: TimeInterval = RelayClient.resourceTimeout,
         jitter: @escaping @Sendable (ClosedRange<Double>) -> Double = { Double.random(in: $0) }) {
        self.baseURL = baseURL
        self.jitter = jitter
        self.callDeadline = callDeadline
        self.session = session ?? Self.makeSession()
    }

    /// The session configuration, and the three settings that are load-bearing.
    static func makeSession(delegate: URLSessionDelegate = PinningSessionDelegate()) -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral

        // TLS 1.3 floor. This is a *tightening*, not an ATS exception — App Transport Security
        // requires 1.2 and this refuses anything below 1.3. Nothing in Info.plist is relaxed;
        // `NSAllowsArbitraryLoads` and per-domain exceptions stay absent, which the plan names
        // as P5.S08's anti-goal.
        configuration.tlsMinimumSupportedProtocolVersion = .TLSv13

        // Ephemeral: nothing about a request or response reaches disk. A URL cache would
        // persist relay responses — prekey bundles, envelope ciphertext — into an on-disk
        // store outside the encrypted container, which is the retention the whole design
        // avoids server-side. Cookies likewise: the relay authenticates with a bearer token
        // from the Keychain and has no session cookie to keep.
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.httpCookieAcceptPolicy = .never
        configuration.httpShouldSetCookies = false

        configuration.timeoutIntervalForRequest = requestTimeout
        configuration.timeoutIntervalForResource = resourceTimeout

        // We do our own retries with jitter; letting the system also wait would compound the
        // delay invisibly and make a "30 second timeout" mean something else.
        configuration.waitsForConnectivity = false

        return URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
    }

    // MARK: - Requests

    /// Perform a request, retrying transient failures with exponential backoff and full jitter.
    ///
    /// ## What is retried, and what must never be
    ///
    /// Retries are limited to requests the caller marks idempotent, plus transport failures on
    /// any request that provably never reached the server. Blindly retrying a `POST /v1/messages`
    /// that timed out after the relay accepted it would deliver the message twice.
    ///
    /// Status codes retried: **429** and **5xx**. A 4xx other than 429 is the caller's fault and
    /// will fail identically next time; retrying it is a way to turn one bad request into three.
    ///
    /// ## Why full jitter
    ///
    /// `sleep(random(0, base * 2^attempt))` rather than `base * 2^attempt`. A fixed backoff
    /// synchronises every client that failed at the same moment — the relay recovers, and the
    /// entire circle retries in the same instant, which is how a brief outage becomes a longer
    /// one. Full jitter spreads them across the whole window.
    func send(_ request: RelayRequest) async throws -> Response {
        let deadline = ContinuousClock.now.advanced(by: .seconds(callDeadline))
        var lastStatus = 0

        for attempt in 0..<Self.maxAttempts {
            if attempt > 0 {
                // 0.5s, 1s, 2s ceilings; the actual wait is uniform within each.
                let ceiling = 0.5 * pow(2.0, Double(attempt - 1))
                try await Self.sleep(jitter(0...ceiling), notPast: deadline)
            }

            // The deadline is checked before each attempt rather than only between them, so a
            // call cannot start a fresh 30-second request one second before its own ceiling.
            let remaining = Self.secondsRemaining(until: deadline)
            guard remaining > 0 else {
                throw lastStatus == 0
                    ? TransportError.unreachable
                    : TransportError.exhaustedRetries(lastStatus: lastStatus)
            }

            do {
                let response = try await perform(request,
                                                 timeout: min(Self.requestTimeout, remaining))

                guard Self.isRetryable(status: response.status), request.isIdempotent else {
                    return response
                }
                lastStatus = response.status

                // Respect Retry-After when the server sends one: it knows more than our
                // backoff curve does, and ignoring it is how a rate limit becomes a stampede.
                // Looked up case-insensitively — see ``Response/headers``.
                if let after = response.header("Retry-After").flatMap(Double.init),
                   after > 0, attempt < Self.maxAttempts - 1 {
                    let capped = min(after, callDeadline / Double(Self.maxAttempts))
                    try await Self.sleep(capped, notPast: deadline)
                }
            } catch let error as TransportError {
                // A TLS failure is not transient in any useful sense — the pin does not start
                // matching on the second attempt, and retrying an attacker's endpoint three
                // times is three chances rather than one. An oversized body is equally settled:
                // the relay will answer the same way again, at the same cost to this device.
                if error == .secureConnectionFailed || error == .responseTooLarge { throw error }

                // Retry a transport failure only when the request is idempotent or is known
                // not to have been received.
                guard request.isIdempotent, attempt < Self.maxAttempts - 1 else { throw error }
            }
        }

        throw TransportError.exhaustedRetries(lastStatus: lastStatus)
    }

    /// Sleeps for `seconds`, never past `deadline`, and lets cancellation through.
    ///
    /// The `try?` this replaces was a real defect, not a tidy-up: it swallowed the
    /// `CancellationError`, the loop continued, and the cancelled `URLSessionTask` then
    /// surfaced as `URLError.cancelled` — which ``classify(_:)`` maps to
    /// ``TransportError/secureConnectionFailed`` because that is also how a refused pin
    /// arrives. A user leaving a screen was told the connection had been attacked.
    private static func sleep(_ seconds: Double, notPast deadline: ContinuousClock.Instant) async throws {
        let bounded = min(seconds, secondsRemaining(until: deadline))
        guard bounded > 0 else { return }
        try await Task.sleep(nanoseconds: UInt64(bounded * 1_000_000_000))
    }

    private static func secondsRemaining(until deadline: ContinuousClock.Instant) -> Double {
        let components = ContinuousClock.now.duration(to: deadline).components
        return max(0, Double(components.seconds) + Double(components.attoseconds) / 1e18)
    }

    private func perform(_ request: RelayRequest, timeout: TimeInterval) async throws -> Response {
        var urlRequest = try request.urlRequest(relativeTo: baseURL)
        urlRequest.timeoutInterval = timeout

        // One loader per attempt: it is the task's delegate and holds that task's state.
        let loader = BoundedResponseLoader(byteCeiling: request.responseByteCeiling)

        let http: HTTPURLResponse
        let data: Data
        do {
            (http, data) = try await loader.load(urlRequest, on: session)
        } catch let error as BoundedResponseLoader.Failure {
            switch error {
            case .responseTooLarge: throw TransportError.responseTooLarge
            case .notHTTP: throw TransportError.malformedResponse
            }
        } catch let error as URLError {
            // Cancelling *this* task is how the caller leaves; cancelling *the challenge* is
            // how the pinner refuses. Both arrive as `URLError.cancelled`, so the difference
            // has to be read from our own task, and it is read first. Everything else keeps
            // the deliberate conflation `classify` documents.
            if Task.isCancelled { throw CancellationError() }
            throw Self.classify(error)
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            if Task.isCancelled { throw CancellationError() }
            throw TransportError.unreachable
        }

        var headers: [String: String] = [:]
        for (key, value) in http.allHeaderFields {
            if let key = key as? String, let value = value as? String {
                headers[key.lowercased()] = value
            }
        }

        return Response(status: http.statusCode, body: data, headers: headers)
    }

    /// Map `URLError` onto our two transport outcomes.
    ///
    /// The TLS family is collapsed into one case on purpose: a pin mismatch surfaces as
    /// `.cancelled` or `.secureConnectionFailed` depending on where in the handshake the
    /// delegate refused, and treating those differently would leak which check failed into
    /// behaviour the caller can observe.
    static func classify(_ error: URLError) -> TransportError {
        switch error.code {
        case .secureConnectionFailed,
             .serverCertificateUntrusted,
             .serverCertificateHasBadDate,
             .serverCertificateHasUnknownRoot,
             .serverCertificateNotYetValid,
             .clientCertificateRejected,
             .clientCertificateRequired,
             .cancelled:
            return .secureConnectionFailed
        default:
            return .unreachable
        }
    }

    static func isRetryable(status: Int) -> Bool {
        status == 429 || (500...599).contains(status)
    }
}

/// A request the relay understands.
///
/// `isIdempotent` is stated by the caller rather than inferred from the HTTP method, because
/// the relay has POSTs in both categories: `POST /v1/messages/ack` may safely be repeated —
/// acknowledging an already-deleted message is a no-op — while `POST /v1/messages` may not,
/// and `POST /v1/invite/redeem` must not, since it consumes a single-use code.
nonisolated struct RelayRequest: Sendable {
    let method: String
    let path: String
    let body: Data?
    let contentType: String?
    let bearerToken: String?
    let isIdempotent: Bool
    /// Bytes this request's response may occupy. See ``BoundedResponseLoader``.
    let responseByteCeiling: Int

    init(method: String,
         path: String,
         body: Data? = nil,
         contentType: String? = "application/json",
         bearerToken: String? = nil,
         isIdempotent: Bool,
         responseByteCeiling: Int = RelayClient.defaultResponseCeiling) {
        self.method = method
        self.path = path
        self.body = body
        self.contentType = contentType
        self.bearerToken = bearerToken
        self.isIdempotent = isIdempotent
        self.responseByteCeiling = responseByteCeiling
    }

    enum BuildError: Error, Equatable {
        /// The composed URL was not `https`, or the path escaped the base URL's origin.
        case insecureOrMalformedURL
        /// The base URL is not a bare `https://host` origin — see ``requireBareOrigin(_:)``.
        case malformedBaseURL
    }

    func urlRequest(relativeTo base: URL) throws -> URLRequest {
        try Self.requireBareOrigin(base)

        // A relative path would resolve against the base's own path and a `..` would climb out
        // of it. Neither can reach another host, but both can reach an endpoint other than the
        // one this request says it is calling.
        guard path.hasPrefix("/"), !path.contains("..") else {
            throw BuildError.insecureOrMalformedURL
        }

        guard let url = URL(string: path, relativeTo: base)?.absoluteURL,
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.scheme?.lowercased() == "https",
              components.host == base.host,
              components.port == nil,
              components.user == nil,
              components.password == nil else {
            // Belt and braces against a path like "//evil.example" or "http://…", which
            // `URL(string:relativeTo:)` will happily resolve into a different origin — taking
            // the request outside the pinned host, where these pins say nothing.
            throw BuildError.insecureOrMalformedURL
        }

        var request = URLRequest(url: url)
        request.httpMethod = method
        request.httpBody = body
        if let contentType, body != nil {
            request.setValue(contentType, forHTTPHeaderField: "Content-Type")
        }
        if let bearerToken {
            request.setValue("Bearer \(bearerToken)", forHTTPHeaderField: "Authorization")
        }
        // The default `User-Agent` names the app and OS build. The relay does not need it and
        // BACKEND.md §1 forbids the server recording version information; not sending it is
        // cheaper than trusting the server not to log it.
        request.setValue("", forHTTPHeaderField: "User-Agent")
        return request
    }

    /// Requires `base` to be nothing but `https://host`.
    ///
    /// Each rejected part is a way the request could stay syntactically valid while ceasing to
    /// be the request this code believes it is making:
    ///
    /// - **Credentials.** `URLSession` turns `https://user:pass@host` into an
    ///   `Authorization: Basic` header, which *displaces* the bearer token set below — the
    ///   request would then be unauthenticated, and a 401 is the good outcome.
    /// - **A port.** `CertificatePinner` matches on host, so `host:8443` stays pinned while
    ///   reaching a different service on the same machine.
    /// - **A path.** Every caller passes an absolute path, so a base path is silently dropped
    ///   rather than prefixed — a base of `https://host/v2` would keep calling `/v1`.
    /// - **A query or fragment.** Resolving an absolute path against them discards both, so a
    ///   base carrying either is a statement about the request that is not true of it.
    static func requireBareOrigin(_ base: URL) throws {
        guard let components = URLComponents(url: base, resolvingAgainstBaseURL: false),
              components.scheme?.lowercased() == "https",
              let host = components.host, !host.isEmpty,
              components.user == nil,
              components.password == nil,
              components.port == nil,
              components.path.isEmpty || components.path == "/",
              components.query == nil,
              components.fragment == nil else {
            throw BuildError.malformedBaseURL
        }
    }
}
