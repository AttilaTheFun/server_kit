#if canImport(Security) && !canImport(FoundationNetworking)
import Foundation
import NIOCore
import NIOPosix
import PairingLink
import ServerIdentity
import ServerTLS
import Testing
@testable import PairedClient

let secret = "0123456789abcdefSECRET"

/// A plain HTTP server's stand-in behind the TLS front: reads the front's two lines, answers `ok`.
final class Answer: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    var bytes: [UInt8] = []
    var answered = false

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = unwrapInboundIn(data)
        bytes += buffer.readBytes(length: buffer.readableBytes) ?? []
        guard !answered, case .success? = ProxyV1.parse(bytes, secret: secret), bytes.suffix(4) == Array("\r\n\r\n".utf8) else { return }
        answered = true
        var answer = context.channel.allocator.buffer(capacity: 80)
        answer.writeString("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        let channel = context.channel
        channel.writeAndFlush(answer).whenComplete { _ in channel.close(promise: nil) }
    }
}

@Test func aPinnedSessionTrustsTheServersOwnCertificateByItsPinsAlone() async throws {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let inner = try await ServerBootstrap(group: group)
        .childChannelInitializer { channel in channel.eventLoop.makeCompletedFuture { try channel.pipeline.syncOperations.addHandler(Answer()) } }
        .bind(host: "127.0.0.1", port: 0).get()
    let identity = try ServerIdentity.make(commonName: "Mac", dnsNames: ["mac.local"], ipv4: ["127.0.0.1"])
    let front = TLSFront(group: group)
    let port = try await front.start(host: "127.0.0.1", port: 0, inner: inner.localAddress!.port!, secret: secret,
                               certificates: ServerCertificates(ca: nil, own: PEMPair(chain: identity.chain, key: identity.key)))
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
    // One session for several servers: pins looked up by host.
    let shared = PinnedSession { host, at in host == "127.0.0.1" && at == port ? identity.pins : PinSet([]) }
    let otherPort = PinnedSession { host, at in host == "127.0.0.1" && at == port + 1 ? identity.pins : PinSet([]) }
    await #expect(throws: (any Error).self, "the same host, another port's pins") { _ = try await otherPort.data(for: URLRequest(url: url)) }
    let (_, viaShared) = try await shared.data(for: URLRequest(url: url))
    #expect((viaShared as? HTTPURLResponse)?.statusCode == 200)
    let elsewhere = PinnedSession { _, _ in other.pins }
    await #expect(throws: (any Error).self) { _ = try await elsewhere.data(for: URLRequest(url: url)) }
    await front.stop()
    try await inner.close()
    try await group.shutdownGracefully()
}

@Test func redirectsStayWithinTheirOrigin() {
    let from = URL(string: "https://127.0.0.1:8443/a")!
    #expect(PinnedSession.sameOrigin(from, URL(string: "https://127.0.0.1:8443/b")!))
    #expect(!PinnedSession.sameOrigin(from, URL(string: "http://127.0.0.1:8443/b")!), "down to plain HTTP")
    #expect(!PinnedSession.sameOrigin(from, URL(string: "https://localhost:8443/b")!), "another host")
    #expect(!PinnedSession.sameOrigin(from, URL(string: "https://127.0.0.1:9443/b")!), "another port")
    #expect(PinnedSession.sameOrigin(URL(string: "https://a.example.com/x")!, URL(string: "https://A.example.com:443/y")!))
}
#endif
