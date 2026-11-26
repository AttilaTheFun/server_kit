#if canImport(AVFoundation) && canImport(Security) && !canImport(FoundationNetworking)
import AVFoundation
import Foundation
import NIOConcurrencyHelpers
import NIOCore
import NIOPosix
import PairingLink
import ServerIdentity
import ServerTLS
import Testing
@testable import PairedClient

/// A second of silence as a WAV: 8 kHz, mono, 16-bit.
let wav: [UInt8] = {
    let samples = 8000, data = samples * 2
    func le32(_ v: Int) -> [UInt8] { [UInt8(v & 0xFF), UInt8(v >> 8 & 0xFF), UInt8(v >> 16 & 0xFF), UInt8(v >> 24 & 0xFF)] }
    func le16(_ v: Int) -> [UInt8] { [UInt8(v & 0xFF), UInt8(v >> 8 & 0xFF)] }
    return Array("RIFF".utf8) + le32(36 + data) + Array("WAVE".utf8) + Array("fmt ".utf8) + le32(16) + le16(1) + le16(1)
        + le32(8000) + le32(16000) + le16(2) + le16(16) + Array("data".utf8) + le32(data) + [UInt8](repeating: 0, count: data)
}()

/// A media server's stand-in behind the front: answers `Range` with 206 and the bytes asked for, or the whole with
/// 200; refuses a request without the bearer. Counts the ranges asked.
final class Media: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    let asked: NIOLockedValueBox<[String]>
    var head = ""

    init(asked: NIOLockedValueBox<[String]>) { self.asked = asked }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = unwrapInboundIn(data)
        head += buffer.readString(length: buffer.readableBytes) ?? ""
        guard head.contains("\r\n\r\n") else { return }
        let lines = head.split(separator: "\r\n").map(String.init)
        head = ""
        let range = lines.first { $0.lowercased().hasPrefix("range:") }
        let authorized = lines.contains { $0.lowercased() == "authorization: bearer token" }
        var answer = context.channel.allocator.buffer(capacity: wav.count + 200)
        if !authorized {
            answer.writeString("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        } else if let range, let spec = range.split(separator: "=").last {
            asked.withLockedValue { $0.append(String(spec)) }
            let parts = spec.split(separator: "-", omittingEmptySubsequences: false)
            let start = Int(parts[0]) ?? 0
            let end = min(parts.count > 1 ? Int(parts[1]) ?? wav.count - 1 : wav.count - 1, wav.count - 1)
            answer.writeString("HTTP/1.1 206 Partial Content\r\nContent-Type: audio/wav\r\nContent-Range: bytes \(start)-\(end)/\(wav.count)\r\n"
                + "Content-Length: \(end - start + 1)\r\nConnection: close\r\n\r\n")
            answer.writeBytes(wav[start...end])
        } else {
            answer.writeString("HTTP/1.1 200 OK\r\nContent-Type: audio/wav\r\nContent-Length: \(wav.count)\r\nConnection: close\r\n\r\n")
            answer.writeBytes(wav)
        }
        let channel = context.channel
        channel.writeAndFlush(answer).whenComplete { _ in channel.close(promise: nil) }
    }
}

@Test func anAssetPlaysFromTheServersOwnCertificateByItsPins() async throws {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let asked = NIOLockedValueBox<[String]>([])
    let inner = try await ServerBootstrap(group: group)
        .childChannelInitializer { channel in
            channel.eventLoop.makeCompletedFuture {
                try channel.pipeline.syncOperations.addHandler(ProxyV1Handler(secret: secret))
                try channel.pipeline.syncOperations.addHandler(Media(asked: asked))
            }
        }
        .bind(host: "127.0.0.1", port: 0).get()
    let identity = try ServerIdentity.make(commonName: "Mac", dnsNames: ["mac.local"], ipv4: ["127.0.0.1"])
    let front = TLSFront(group: group)
    let port = try await front.start(host: "127.0.0.1", port: 0, inner: inner.localAddress!.port!, secret: secret,
                                     certificates: ServerCertificates(ca: nil, own: PEMPair(chain: identity.chain, key: identity.key)))
    let url = URL(string: "https://127.0.0.1:\(port)/media/silence.wav")!

    // By its pins, with the bearer: AVFoundation reads it, in ranges.
    let pinned = try #require(PinnedAsset(url: url, session: PinnedSession(pins: identity.pins), headers: ["Authorization": "Bearer token"]))
    let duration = try await pinned.asset.load(.duration)
    #expect(abs(duration.seconds - 1.0) < 0.05)
    #expect(!asked.withLockedValue { $0 }.isEmpty, "read by ranges")
    let tracks = try await pinned.asset.loadTracks(withMediaType: .audio)
    #expect(tracks.count == 1)

    // Another server's pins: nothing read.
    let other = try ServerIdentity.make(commonName: "Other", dnsNames: ["other.local"])
    let refused = try #require(PinnedAsset(url: url, session: PinnedSession(pins: other.pins), headers: ["Authorization": "Bearer token"]))
    await #expect(throws: (any Error).self) { _ = try await refused.asset.load(.duration) }
    // No bearer: the server's refusal, said.
    let unauthorized = try #require(PinnedAsset(url: url, session: PinnedSession(pins: identity.pins)))
    await #expect(throws: (any Error).self) { _ = try await unauthorized.asset.load(.duration) }
    // Only https is taken.
    #expect(PinnedAsset(url: URL(string: "http://127.0.0.1/x.wav")!, session: PinnedSession(pins: identity.pins)) == nil)

    await front.stop()
    try await inner.close()
    try await group.shutdownGracefully()
}
#endif
