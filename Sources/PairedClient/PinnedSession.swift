#if canImport(Security) && !canImport(FoundationNetworking)
import Foundation
import PairingLink
import Security

// A URLSession that trusts a paired server's own certificate by its pins, and every other name by the system's trust:
// at a host that presents the server's own (PinTrust: an IP, a `.local` name, a bare name), the leaf is matched against
// the pins and refused when none match; any other host (a tailnet's `*.ts.net`, a domain) is the system's to judge.
// Data, downloads, uploads from a file and WebSockets alike, since all of them meet the same session's challenge. One
// session may serve several servers: their pins are looked up by host. A redirect is followed only to the same origin
// (scheme, host and port), never down to plain HTTP or off to another host, which may not be the pinned server.
// Apple's systems: Linux's Foundation gives a delegate no server trust to check.

public final class PinnedSession: @unchecked Sendable {
    /// Kept to itself: a task given a delegate of its own would take the trust decision from the pins.
    let session: URLSession
    let delegate: PinningDelegate

    /// One server's pins, for every host. `isPinned` says which hosts present the server's own certificate
    /// (PinTrust's by default).
    public convenience init(pins: PinSet, configuration: URLSessionConfiguration = .ephemeral,
                            isPinned: @escaping @Sendable (String) -> Bool = PinTrust.isPinned(host:)) {
        self.init(configuration: configuration, isPinned: isPinned) { _, _ in pins }
    }

    /// Several servers' pins, looked up by the host (lowercased, without brackets) and port a connection is to (two
    /// servers may share an address); an empty set for one no server is known at refuses its own certificate.
    public init(configuration: URLSessionConfiguration = .ephemeral,
                isPinned: @escaping @Sendable (String) -> Bool = PinTrust.isPinned(host:),
                pinsFor: @escaping @Sendable (_ host: String, _ port: Int) -> PinSet) {
        delegate = PinningDelegate(pinsFor: pinsFor, isPinned: isPinned)
        session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
    }

    deinit { session.finishTasksAndInvalidate() }

    public func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        try await session.data(for: request)
    }

    /// The answer's bytes as they come. The pins' check is given to the task itself too: a streamed task's
    /// challenge may not reach the session's delegate.
    public func bytes(for request: URLRequest) async throws -> (URLSession.AsyncBytes, URLResponse) {
        try await session.bytes(for: request, delegate: delegate)
    }

    public func download(for request: URLRequest) async throws -> (URL, URLResponse) {
        try await session.download(for: request)
    }

    public func upload(for request: URLRequest, fromFile file: URL) async throws -> (Data, URLResponse) {
        try await session.upload(for: request, fromFile: file)
    }

    public func webSocketTask(with request: URLRequest) -> URLSessionWebSocketTask {
        session.webSocketTask(with: request)
    }

    /// A host as `pinsFor` is asked it: lowercased, without IPv6's brackets.
    static func bare(_ host: String) -> String {
        var lower = host.lowercased()
        if lower.hasPrefix("["), lower.hasSuffix("]") { lower = String(lower.dropFirst().dropLast()) }
        return lower
    }

    /// Whether `next` is `from`'s origin: the same scheme, host and port (the scheme's own where none is given).
    static func sameOrigin(_ from: URL?, _ next: URL?) -> Bool {
        guard let from, let next, let scheme = from.scheme?.lowercased(), scheme == next.scheme?.lowercased(),
              let host = from.host?.lowercased(), host == next.host?.lowercased() else { return false }
        func port(_ url: URL) -> Int? { url.port ?? (scheme == "https" || scheme == "wss" ? 443 : scheme == "http" || scheme == "ws" ? 80 : nil) }
        return port(from) == port(next)
    }

    /// The pins' verdict on a server trust at `host`: nil for the system's own evaluation.
    static func evaluate(_ trust: SecTrust, host: String, pins: PinSet, isPinned: (String) -> Bool) -> Bool? {
        guard isPinned(host) else { return nil }
        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], let leaf = chain.first else { return false }
        let der = [UInt8](SecCertificateCopyData(leaf) as Data)
        let shown = CertificatePins.of(der: der)
        return PinTrust.decide(host: host, pins: pins, spki: shown?.spki, certificate: shown?.certificate, isPinned: isPinned) == .accept
    }
}

final class PinningDelegate: NSObject, URLSessionDelegate, URLSessionTaskDelegate, @unchecked Sendable {
    let pinsFor: @Sendable (String, Int) -> PinSet
    let isPinned: @Sendable (String) -> Bool

    init(pinsFor: @escaping @Sendable (String, Int) -> PinSet, isPinned: @escaping @Sendable (String) -> Bool) {
        self.pinsFor = pinsFor
        self.isPinned = isPinned
    }

    /// A protection space's port: its own, or its scheme's where it gives none.
    static func port(_ space: URLProtectionSpace) -> Int {
        if space.port > 0 { return space.port }
        return space.protocol?.lowercased() == "http" ? 80 : 443
    }

    /// A task's own challenge: the same check as the session's.
    func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        urlSession(session, didReceive: challenge, completionHandler: completionHandler)
    }

    /// A redirect followed only within its origin; any other is answered with the redirect itself.
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        completionHandler(PinnedSession.sameOrigin(task.currentRequest?.url ?? response.url, request.url) ? request : nil)
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            return completionHandler(.performDefaultHandling, nil)
        }
        let host = challenge.protectionSpace.host
        switch PinnedSession.evaluate(trust, host: host, pins: pinsFor(PinnedSession.bare(host), Self.port(challenge.protectionSpace)), isPinned: isPinned) {
        case nil: completionHandler(.performDefaultHandling, nil)
        case true?: completionHandler(.useCredential, URLCredential(trust: trust))
        case false?: completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
#endif
