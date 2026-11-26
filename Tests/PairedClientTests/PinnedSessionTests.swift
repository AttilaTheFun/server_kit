#if canImport(Security) && !canImport(FoundationNetworking)
import Foundation
import NIOCore
import NIOPosix
import PairingLink
import ServerIdentity
import ServerTLS
import Testing
@testable import PairedClient

/// A plain HTTP server's stand-in behind the TLS front: reads the front's two lines, answers `ok`.
final class Answer: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    var bytes: [UInt8] = []
    var answered = false

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = unwrapInboundIn(data)
        bytes += buffer.readBytes(length: buffer.readableBytes) ?? []
        guard !answered, case .success? = ProxyV1.parse(bytes, secret: "s"), bytes.suffix(4) == Array("\r\n\r\n".utf8) else { return }
        answered = true
        var answer = context.channel.allocator.buffer(capacity: 80)
        answer.writeString("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        let channel = context.channel
        channel.writeAndFlush(answer).whenComplete { _ in channel.close(promise: nil) }
    }
}

@Test func aPinnedSessionTrustsTheServersOwnCertificateByItsPinsAlone() async throws {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    defer { try? group.syncShutdownGracefully() }
    let inner = try await ServerBootstrap(group: group)
        .childChannelInitializer { channel in channel.eventLoop.makeCompletedFuture { try channel.pipeline.syncOperations.addHandler(Answer()) } }
        .bind(host: "127.0.0.1", port: 0).get()
    let identity = try ServerIdentity.make(commonName: "Mac", dnsNames: ["mac.local"], ipv4: ["127.0.0.1"])
    let front = TLSFront()
    let port = try front.start(host: "127.0.0.1", port: 0, inner: inner.localAddress!.port!, secret: "s",
                               certificates: ServerCertificates(ca: nil, own: PEMPair(chain: identity.chain, key: identity.key)))
    defer {
        front.stop()
        try? inner.close().wait()
    }
    let url = URL(string: "https://127.0.0.1:\(port)/v1/hello")!

    let (data, response) = try await PinnedSession(pins: identity.pins).data(for: URLRequest(url: url))
    #expect((response as? HTTPURLResponse)?.statusCode == 200 && data == Data("ok".utf8))
    // By its SPKI pin alone, as a server gives it now.
    let (_, spkiOnly) = try await PinnedSession(pins: PinSet([identity.spkiPin])).data(for: URLRequest(url: url))
    #expect((spkiOnly as? HTTPURLResponse)?.statusCode == 200)
    // Another server's pins, or none: refused.
    let other = try ServerIdentity.make(commonName: "Other", dnsNames: ["other.local"])
    await #expect(throws: (any Error).self) { _ = try await PinnedSession(pins: other.pins).data(for: URLRequest(url: url)) }
    await #expect(throws: (any Error).self) { _ = try await PinnedSession(pins: PinSet([])).data(for: URLRequest(url: url)) }
}
#endif
