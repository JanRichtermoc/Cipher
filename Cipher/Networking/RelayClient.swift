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
        /// Network unreachable, DNS failure, timeout.
        case unreachable
        /// The server answered with something that is not an HTTP response.
        case malformedResponse
        /// The response body exceeded the ceiling for this request, and was refused rather
        /// than buffered. See ``BoundedRelayLoader``.
        case responseTooLarge
        /// The whole call — every attempt and every backoff — ran past ``resourceTimeout``.
        case deadlineExceeded
        /// Retries were exhausted while the server kept returning a retryable status.
        case exhaustedRetries(lastStatus: Int)
    }

    struct Response: Sendable {
        let status: Int
        let body: Data

        /// Header fields with **lowercased names**. HTTP field names are case-insensitive
        /// (RFC 9110 §5.1) and `HTTPURLResponse` reports them as the server spelled them, so a
        /// relay answering `retry-after` would be invisible to a lookup for `Retry-After`.
        /// Read through ``header(_:)`` rather than subscripting.
        let headers: [String: String]

        /// Case-insensitive header lookup.
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
    /// Enforced by ``send(_:)`` against a monotonic clock, not only by
    /// `timeoutIntervalForResource`: that setting bounds one `URLSessionTask`, and this client
    /// makes up to ``maxAttempts`` of them with a backoff between each. Left to the
    /// configuration alone the constant would name a bound the code does not have — three
    /// attempts could each spend the full resource timeout and the caller would wait far past
    /// it, which for the receive path means a message cycle that never returns.
    static let resourceTimeout: TimeInterval = 120

    /// Attempts, not retries: 1 means "try once, never retry".
    static let maxAttempts = 3

    /// How much response body a request accepts unless it says otherwise.
    ///
    /// Every relay response except a message fetch is small: a redeemed session, a rotated
    /// token, a prekey bundle (a Kyber-1024 key is the largest field at 1568 bytes) or an
    /// acknowledgement count. 64 KiB is far above all of them and far below anything that
    /// costs the device something, so the ordinary case needs no ceiling of its own.
    /// `RelayMailbox.fetch` is the one endpoint whose response is legitimately large and it
    /// sets its own bound from the relay's documented batch and envelope limits.
    static let defaultMaxResponseBytes = 64 * 1024

    private let session: URLSession
    private let baseURL: URL
    private let loader: BoundedRelayLoader

    /// The whole-call budget this instance enforces. Injectable for the same reason ``jitter``
    /// is: a test that had to prove the deadline by waiting for it would take two minutes to
    /// run and would therefore be written once and then deleted.
    private let resourceTimeout: TimeInterval

    /// Injectable so tests can drive the retry logic without sleeping. Returns seconds.
    private let jitter: @Sendable (ClosedRange<Double>) -> Double

    init(baseURL: URL = RelayEndpoint.baseURL,
         session: URLSession? = nil,
         pinner: CertificatePinner = CertificatePinner(),
         resourceTimeout: TimeInterval = RelayClient.resourceTimeout,
         jitter: @escaping @Sendable (ClosedRange<Double>) -> Double = { Double.random(in: $0) }) {
        self.baseURL = baseURL
        self.jitter = jitter
        self.resourceTimeout = resourceTimeout
        self.session = session ?? Self.makeSession()
        self.loader = BoundedRelayLoader(pinner: pinner)
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
    /// ## Cancellation is cancellation, not a TLS failure
    ///
    /// A cancelled `URLSessionTask` surfaces as `URLError.cancelled`, which ``classify(_:)``
    /// deliberately reports as ``TransportError/secureConnectionFailed`` because that is also
    /// how a refused pin arrives. Both readings cannot be right, and the one that matters is
    /// decided by whether *this task* was cancelled: a caller that walked away must not be
    /// told the connection was attacked. So cancellation is checked first and rethrown as
    /// `CancellationError`, and the conflation stays intact for every other case.
    func send(_ request: RelayRequest) async throws -> Response {
        // Monotonic: a wall-clock jump — an NTP correction, a user changing the date — must
        // not extend or collapse the budget for a call already in flight.
        let deadline = ContinuousClock.now.advanced(by: .seconds(resourceTimeout))
        var lastStatus = 0

        for attempt in 0..<Self.maxAttempts {
            try Task.checkCancellation()

            if attempt > 0 {
                // 0.5s, 1s, 2s ceilings; the actual wait is uniform within each.
                let ceiling = 0.5 * pow(2.0, Double(attempt - 1))
                try await sleep(jitter(0...ceiling), before: deadline)
            }

            // One attempt may never outlive the whole-call budget, so the per-request timeout
            // is whichever is nearer. Without this the last attempt could start with a second
            // left and still run for the full 30.
            let remaining = Self.seconds(until: deadline)
            guard remaining > 0 else { throw TransportError.deadlineExceeded }

            do {
                let response = try await perform(
                    request, timeout: min(Self.requestTimeout, remaining))

                guard Self.isRetryable(status: response.status), request.isIdempotent else {
                    return response
                }
                lastStatus = response.status

                // Respect Retry-After when the server sends one: it knows more than our
                // backoff curve does, and ignoring it is how a rate limit becomes a stampede.
                // `isFinite` because `Double("inf")` parses, and an infinite wait capped by
                // the ceiling below would still be a wait nobody asked for.
                if let after = response.header("Retry-After").flatMap(Double.init),
                   after.isFinite, after > 0, attempt < Self.maxAttempts - 1 {
                    let capped = min(after, resourceTimeout / Double(Self.maxAttempts))
                    try await sleep(capped, before: deadline)
                }
            } catch let error as TransportError {
                // A TLS failure is not transient in any useful sense — the pin does not start
                // matching on the second attempt, and retrying an attacker's endpoint three
                // times is three chances rather than one. An oversized body and an exhausted
                // deadline are equally settled: the relay does not answer differently next
                // time, and there is by definition no budget left to ask.
                if error == .secureConnectionFailed
                    || error == .responseTooLarge
                    || error == .deadlineExceeded { throw error }

                // Retry a transport failure only when the request is idempotent or is known
                // not to have been received.
                guard request.isIdempotent, attempt < Self.maxAttempts - 1 else { throw error }
            }
        }

        throw TransportError.exhaustedRetries(lastStatus: lastStatus)
    }

    /// Waits `seconds`, never past `deadline`, and propagates cancellation.
    private func sleep(_ seconds: Double, before deadline: ContinuousClock.Instant) async throws {
        let remaining = Self.seconds(until: deadline)
        guard remaining > 0 else { throw TransportError.deadlineExceeded }
        let capped = min(seconds, remaining)
        guard capped > 0 else { return }
        // `try`, not `try?`: swallowing this is what made a cancelled call keep going and then
        // report the eventual URLError.cancelled as a pin failure.
        try await Task.sleep(nanoseconds: UInt64(capped * 1_000_000_000))
    }

    private static func seconds(until deadline: ContinuousClock.Instant) -> Double {
        let components = ContinuousClock.now.duration(to: deadline).components
        return Double(components.seconds) + Double(components.attoseconds) * 1e-18
    }

    private func perform(_ request: RelayRequest, timeout: TimeInterval) async throws -> Response {
        var urlRequest = try request.urlRequest(relativeTo: baseURL)
        urlRequest.timeoutInterval = timeout

        let body: Data
        let http: HTTPURLResponse
        do {
            (body, http) = try await loader.load(
                urlRequest, on: session, maxResponseBytes: request.maxResponseBytes)
        } catch let error as TransportError {
            throw error
        } catch let error as URLError {
            if error.code == .cancelled, Task.isCancelled { throw CancellationError() }
            throw Self.classify(error)
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw TransportError.unreachable
        }

        var headers: [String: String] = [:]
        for (key, value) in http.allHeaderFields {
            if let key = key as? String, let value = value as? String {
                headers[key.lowercased()] = value
            }
        }

        return Response(status: http.statusCode, body: body, headers: headers)
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
    /// How much response body this request will accept before it is refused unread.
    let maxResponseBytes: Int

    init(method: String,
         path: String,
         body: Data? = nil,
         contentType: String? = "application/json",
         bearerToken: String? = nil,
         isIdempotent: Bool,
         maxResponseBytes: Int = RelayClient.defaultMaxResponseBytes) {
        self.method = method
        self.path = path
        self.body = body
        self.contentType = contentType
        self.bearerToken = bearerToken
        self.isIdempotent = isIdempotent
        self.maxResponseBytes = maxResponseBytes
    }

    enum BuildError: Error, Equatable {
        /// The base was not a bare `https` origin, or the composed URL left it.
        case insecureOrMalformedURL
    }

    func urlRequest(relativeTo base: URL) throws -> URLRequest {
        // The base is checked on every call rather than once at construction, because it is
        // injectable and because this is the only place that can still refuse it. See
        // `RelayEndpoint.isBareOrigin(_:)` for what each rejected component would mean.
        guard RelayEndpoint.isBareOrigin(base),
              // Absolute path only. A relative one resolves against the base's directory,
              // which makes where a request lands depend on the base's trailing slash.
              path.hasPrefix("/"),
              // Not a traversal: "/v1/../v1/auth" resolves, and a path that can climb is a
              // path whose endpoint is not the one written at the call site.
              !path.contains(".."),
              let url = URL(string: path, relativeTo: base)?.absoluteURL,
              url.scheme?.lowercased() == "https",
              // `URLSession` turns URL credentials into an `Authorization: Basic` header, so
              // a path that smuggled them in would put a secret on the wire — and would
              // overwrite the bearer token this request actually authenticates with.
              url.user == nil,
              url.password == nil,
              // The pin is keyed by host, so a port change stays pinned while reaching a
              // different service.
              url.port == nil,
              let host = url.host, let baseHost = base.host,
              // Host names are case-insensitive; comparing them literally would let
              // "RELAY.example" read as a different origin and be refused, or — with the
              // comparison the other way round in some future edit — accepted as one.
              host.lowercased() == baseHost.lowercased() else {
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
