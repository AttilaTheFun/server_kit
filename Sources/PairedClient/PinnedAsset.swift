#if canImport(AVFoundation) && canImport(Security) && !canImport(FoundationNetworking)
import AVFoundation
import Foundation
import UniformTypeIdentifiers

// Media from a paired server for AVPlayer, over the server's own certificate: AVPlayer fetches an https URL itself,
// with the system's trust, which refuses a certificate only pins vouch for. So the asset is given a URL of a private
// scheme instead, and its loads come here: each of AVPlayer's byte ranges asked of the server through a PinnedSession
// (`Range`, answered 206), with the app's own headers (a session's bearer), streamed back as it comes.

/// An AVURLAsset whose bytes come through a PinnedSession. Keep it while the asset plays: AVFoundation holds its loader
/// weakly.
public final class PinnedAsset: NSObject, AVAssetResourceLoaderDelegate, @unchecked Sendable {
    /// The asset to play.
    public let asset: AVURLAsset
    let url: URL
    let session: PinnedSession
    let headers: [String: String]
    private let lock = NSLock()
    private var loads: [ObjectIdentifier: Task<Void, Never>] = [:]
    private let queue = DispatchQueue(label: "server-kit.pinned-asset")

    /// The scheme the asset's URL is given in place of `https`.
    static let scheme = "x-serverkit-pinned"

    /// The asset for `url` (`https`), its bytes asked for through `session` with `headers` on each request.
    public init?(url: URL, session: PinnedSession, headers: [String: String] = [:]) {
        guard url.scheme?.lowercased() == "https", var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return nil }
        components.scheme = Self.scheme
        guard let hidden = components.url else { return nil }
        self.url = url
        self.session = session
        self.headers = headers
        asset = AVURLAsset(url: hidden)
        super.init()
        asset.resourceLoader.setDelegate(self, queue: queue)
    }

    deinit {
        for task in lock.withLock({ Array(loads.values) }) { task.cancel() }
    }

    public func resourceLoader(_ resourceLoader: AVAssetResourceLoader,
                               shouldWaitForLoadingOfRequestedResource loadingRequest: AVAssetResourceLoadingRequest) -> Bool {
        guard loadingRequest.request.url?.scheme == Self.scheme else { return false }
        let key = ObjectIdentifier(loadingRequest)
        let request = Request(loadingRequest)
        let task = Task { [self] in
            await load(request)
            _ = lock.withLock { loads.removeValue(forKey: key) }
        }
        lock.withLock { loads[key] = task }
        return true
    }

    public func resourceLoader(_ resourceLoader: AVAssetResourceLoader, didCancel loadingRequest: AVAssetResourceLoadingRequest) {
        lock.withLock { loads.removeValue(forKey: ObjectIdentifier(loadingRequest)) }?.cancel()
    }

    /// A loading request, carried across to the task that answers it (AVFoundation's objects aren't Sendable, but
    /// a loading request may be answered from any thread).
    struct Request: @unchecked Sendable {
        let loading: AVAssetResourceLoadingRequest
        init(_ loading: AVAssetResourceLoadingRequest) { self.loading = loading }
    }

    /// The range a loading request asks for: what it wants of the data (to the end where it asks for all), or the
    /// first two bytes where it asks only what the resource is.
    static func range(of loading: AVAssetResourceLoadingRequest) -> (start: Int64, end: Int64?) {
        guard let data = loading.dataRequest else { return (0, 1) }
        let start = data.currentOffset != 0 ? data.currentOffset : data.requestedOffset
        if data.requestsAllDataToEndOfResource { return (start, nil) }
        return (start, data.requestedOffset + Int64(data.requestedLength) - 1)
    }

    func load(_ request: Request) async {
        let loading = request.loading
        let (start, end) = Self.range(of: loading)
        var asked = URLRequest(url: url)
        for (name, value) in headers { asked.setValue(value, forHTTPHeaderField: name) }
        asked.setValue("bytes=\(start)-\(end.map(String.init) ?? "")", forHTTPHeaderField: "Range")
        do {
            let (response, pieces) = try await session.stream(for: asked)
            guard let http = response as? HTTPURLResponse, http.statusCode == 206 || http.statusCode == 200 else {
                throw Failure(status: (response as? HTTPURLResponse)?.statusCode ?? 0)
            }
            if let information = loading.contentInformationRequest {
                Self.describe(information, from: http)
            }
            if let data = loading.dataRequest {
                // A 200 is the whole resource: what's before the range skipped. The range's end kept to, whatever more
                // comes.
                var skip = http.statusCode == 200 ? start : 0
                var position = start
                for try await var piece in pieces {
                    if skip > 0 {
                        let dropped = Int(min(Int64(piece.count), skip))
                        piece.removeFirst(dropped)
                        skip -= Int64(dropped)
                        if piece.isEmpty { continue }
                    }
                    if let end, position + Int64(piece.count) > end + 1 { piece = piece.prefix(Int(end + 1 - position)) }
                    data.respond(with: piece)
                    position += Int64(piece.count)
                    if let end, position > end { break }
                }
            }
            try Task.checkCancellation()
            loading.finishLoading()
        } catch is CancellationError {
            // Cancelled by AVFoundation: nothing more to say.
        } catch {
            if !Task.isCancelled { loading.finishLoading(with: error) }
        }
    }

    /// What the resource is, from an answer: its length (from `Content-Range`'s total, or a whole answer's length),
    /// its type, and whether it's read by ranges.
    static func describe(_ information: AVAssetResourceLoadingContentInformationRequest, from http: HTTPURLResponse) {
        if let length = length(of: http) { information.contentLength = length }
        if let mime = http.mimeType, let type = UTType(mimeType: mime) { information.contentType = type.identifier }
        information.isByteRangeAccessSupported = http.statusCode == 206
    }

    static func length(of http: HTTPURLResponse) -> Int64? {
        if let range = http.value(forHTTPHeaderField: "Content-Range"), let slash = range.lastIndex(of: "/") {
            return Int64(range[range.index(after: slash)...].trimmingCharacters(in: .whitespaces))
        }
        return http.statusCode == 200 && http.expectedContentLength >= 0 ? http.expectedContentLength : nil
    }

    public struct Failure: Error, CustomStringConvertible {
        public var status: Int
        public var description: String { "the server answered \(status)" }
    }
}
#endif
