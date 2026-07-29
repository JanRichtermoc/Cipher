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
        /// Retries were exhausted while the server kept returning a retryable status.
        case exhaustedRetries(lastStatus: Int)
    }

    struct Response: Sendable {
        let status: Int
        let body: Data
        let headers: [String: String]
    }

    /// How long any single attempt may take before it is abandoned.
    ///
    /// Deliberately shorter than the relay's own 120 s proxy read timeout for ordinary calls:
    /// the client should give up and retry before Nginx does, so a stuck request costs one
    /// backoff rather than two minutes of a spinner. Blob transfer overrides this.
    static let requestTimeout: TimeInterval = 30

    /// Ceiling on a whole call including retries.
    static let resourceTimeout: TimeInterval = 120

    /// Attempts, not retries: 1 means "try once, never retry".
    static let maxAttempts = 3

    private let session: URLSession
    private let baseURL: URL

    /// Injectable so tests can drive the retry logic without sleeping. Returns seconds.
    private let jitter: @Sendable (ClosedRange<Double>) -> Double

    init(baseURL: URL = RelayEndpoint.baseURL,
         session: URLSession? = nil,
         jitter: @escaping @Sendable (ClosedRange<Double>) -> Double = { Double.random(in: $0) }) {
        self.baseURL = baseURL
        self.jitter = jitter
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
        var lastStatus = 0

        for attempt in 0..<Self.maxAttempts {
            if attempt > 0 {
                // 0.5s, 1s, 2s ceilings; the actual wait is uniform within each.
                let ceiling = 0.5 * pow(2.0, Double(attempt - 1))
                let delay = jitter(0...ceiling)
                try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            }

            do {
                let response = try await perform(request)

                guard Self.isRetryable(status: response.status), request.isIdempotent else {
                    return response
                }
                lastStatus = response.status

                // Respect Retry-After when the server sends one: it knows more than our
                // backoff curve does, and ignoring it is how a rate limit becomes a stampede.
                if let after = response.headers["Retry-After"].flatMap(Double.init),
                   after > 0, attempt < Self.maxAttempts - 1 {
                    let capped = min(after, Self.resourceTimeout / Double(Self.maxAttempts))
                    try? await Task.sleep(nanoseconds: UInt64(capped * 1_000_000_000))
                }
            } catch let error as TransportError {
                // A TLS failure is not transient in any useful sense — the pin does not start
                // matching on the second attempt, and retrying an attacker's endpoint three
                // times is three chances rather than one.
                if error == .secureConnectionFailed { throw error }

                // Retry a transport failure only when the request is idempotent or is known
                // not to have been received.
                guard request.isIdempotent, attempt < Self.maxAttempts - 1 else { throw error }
            }
        }

        throw TransportError.exhaustedRetries(lastStatus: lastStatus)
    }

    private func perform(_ request: RelayRequest) async throws -> Response {
        let urlRequest = try request.urlRequest(relativeTo: baseURL)

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: urlRequest)
        } catch let error as URLError {
            throw Self.classify(error)
        } catch {
            throw TransportError.unreachable
        }

        guard let http = response as? HTTPURLResponse else {
            throw TransportError.malformedResponse
        }

        var headers: [String: String] = [:]
        for (key, value) in http.allHeaderFields {
            if let key = key as? String, let value = value as? String { headers[key] = value }
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

    init(method: String,
         path: String,
         body: Data? = nil,
         contentType: String? = "application/json",
         bearerToken: String? = nil,
         isIdempotent: Bool) {
        self.method = method
        self.path = path
        self.body = body
        self.contentType = contentType
        self.bearerToken = bearerToken
        self.isIdempotent = isIdempotent
    }

    enum BuildError: Error, Equatable {
        /// The composed URL was not `https`, or the path escaped the base URL's host.
        case insecureOrMalformedURL
    }

    func urlRequest(relativeTo base: URL) throws -> URLRequest {
        guard let url = URL(string: path, relativeTo: base)?.absoluteURL,
              url.scheme?.lowercased() == "https",
              url.host == base.host else {
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
}
