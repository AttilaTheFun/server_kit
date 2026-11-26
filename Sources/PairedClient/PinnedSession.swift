#if canImport(Security) && !canImport(FoundationNetworking)
import Foundation
import PairingLink
import Security

// A URLSession that trusts a paired server's own certificate by its pins, and every other name by the system's trust:
// at a host that presents the server's own (PinTrust: an IP, a `.local` name, a bare name), the leaf is matched against
// the pins and refused when none match; any other host (a tailnet's `*.ts.net`, a domain) is the system's to judge.
// Data, downloads, uploads from a file and WebSockets alike, since all of them meet the same session's challenge.
// Apple's systems: Linux's Foundation gives a delegate no server trust to check.

public final class PinnedSession: @unchecked Sendable {
    public let session: URLSession
    public let pins: PinSet

    /// `isPinned` says which hosts present the server's own certificate (PinTrust's by default).
    public init(pins: PinSet, configuration: URLSessionConfiguration = .ephemeral,
                isPinned: @escaping @Sendable (String) -> Bool = PinTrust.isPinned(host:)) {
        self.pins = pins
        session = URLSession(configuration: configuration, delegate: PinningDelegate(pins: pins, isPinned: isPinned), delegateQueue: nil)
    }

    deinit { session.finishTasksAndInvalidate() }

    public func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        try await session.data(for: request)
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
    let pins: PinSet
    let isPinned: @Sendable (String) -> Bool

    init(pins: PinSet, isPinned: @escaping @Sendable (String) -> Bool) {
        self.pins = pins
        self.isPinned = isPinned
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            return completionHandler(.performDefaultHandling, nil)
        }
        switch PinnedSession.evaluate(trust, host: challenge.protectionSpace.host, pins: pins, isPinned: isPinned) {
        case nil: completionHandler(.performDefaultHandling, nil)
        case true?: completionHandler(.useCredential, URLCredential(trust: trust))
        case false?: completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
#endif
