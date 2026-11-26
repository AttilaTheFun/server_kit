import Foundation
import NIOConcurrencyHelpers
import NIOCore
import NIOPosix
import NIOSSL
import ServerIdentity
import Testing
@testable import ServerTLS

/// The inner listener's stand-in, behind ProxyV1Handler: answers `<client> said <what it got>` once it has 4 bytes,
/// or, streaming, writes a byte every `every` for `count` bytes and closes. Counts its connections.
final class Inner: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    let stream: (every: TimeAmount, count: Int)?
    var client = "?"
    var got: [UInt8] = []
    var answered = false

    init(stream: (every: TimeAmount, count: Int)? = nil) { self.stream = stream }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let header = event as? ProxyV1.Header { client = header.client }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = unwrapInboundIn(data)
        got += buffer.readBytes(length: buffer.readableBytes) ?? []
        guard !answered, got.count >= 4 else { return }
        answered = true
        let channel = context.channel
        if let stream {
            for index in 1...stream.count {
                channel.eventLoop.scheduleTask(in: TimeAmount.nanoseconds(stream.every.nanoseconds * Int64(index))) {
                    var byte = channel.allocator.buffer(capacity: 1)
                    byte.writeString("x")
                    channel.writeAndFlush(byte).whenComplete { _ in if index == stream.count { channel.close(promise: nil) } }
                }
            }
            return
        }
        var answer = channel.allocator.buffer(capacity: 64)
        answer.writeString("\(client) said \(String(decoding: got, as: UTF8.self))")
        channel.writeAndFlush(answer).whenComplete { _ in channel.close(promise: nil) }
    }
}

/// A running front over an inner listener, both on loopback.
struct Rig {
    let group: MultiThreadedEventLoopGroup
    let inner: Channel
    let front: TLSFront
    let port: Int
    let own: ServerIdentity
    let ca: ServerIdentity
    let connections: NIOLockedValueBox<Int>
    let logged: NIOLockedValueBox<[String]>

    static func start(limits: TLSFront.Limits = TLSFront.Limits(), stream: (every: TimeAmount, count: Int)? = nil) async throws -> Rig {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let connections = NIOLockedValueBox(0), logged = NIOLockedValueBox<[String]>([])
        let inner = try await ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                connections.withLockedValue { $0 += 1 }
                return channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(ProxyV1Handler(secret: secret))
                    try channel.pipeline.syncOperations.addHandler(Inner(stream: stream))
                }
            }
            .bind(host: "127.0.0.1", port: 0).get()
        let own = try ServerIdentity.make(commonName: "Own", dnsNames: ["mac.local"], ipv4: ["127.0.0.1"])
        let ca = try ServerIdentity.make(commonName: "CA's", dnsNames: ["mac.example.ts.net"])
        let front = TLSFront(limits: limits, group: group) { line in logged.withLockedValue { $0.append(line) } }
        let port = try await front.start(host: "127.0.0.1", port: 0, inner: inner.localAddress!.port!, secret: secret,
                                         certificates: ServerCertificates(caNames: ["mac.example.ts.net"], ca: PEMPair(chain: ca.chain, key: ca.key),
                                                                          own: PEMPair(chain: own.chain, key: own.key)))
        return Rig(group: group, inner: inner, front: front, port: port, own: own, ca: ca, connections: connections, logged: logged)
    }

    func stop() async throws {
        await front.stop()
        try await inner.close()
        try await group.shutdownGracefully()
    }

    /// Sends `ping` over TLS naming `serverName`, checks the certificate by `trusting`'s pins, and gives back all it's
    /// answered until the server closes.
    func ask(_ serverName: String?, trusting identity: ServerIdentity) async throws -> String {
        let context = try NIOSSLContext(configuration: {
            var configuration = TLSConfiguration.makeClientConfiguration()
            configuration.certificateVerification = .noHostnameVerification
            return configuration
        }())
        let done = group.next().makePromise(of: String.self)
        let pins = identity.pins
        _ = try await ClientBootstrap(group: group)
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    let verify: NIOSSLCustomVerificationCallback = { chain, promise in
                        let shown = chain.first.flatMap { try? ServerIdentity.pins(ofCertificateDER: $0.toDERBytes()) }
                        promise.succeed(shown == pins ? .certificateVerified : .failed)
                    }
                    try channel.pipeline.syncOperations.addHandler(try NIOSSLClientHandler(context: context, serverHostname: serverName,
                                                                                            customVerificationCallback: verify))
                    try channel.pipeline.syncOperations.addHandler(Client(done: done))
                }
            }
            .connect(host: "127.0.0.1", port: port).get()
        return try await done.futureResult.get()
    }

    /// A plain TCP connection that sends `bytes` and says nothing more; its channel.
    func plain(_ bytes: String = "") async throws -> Channel {
        let channel = try await ClientBootstrap(group: group).connect(host: "127.0.0.1", port: port).get()
        if !bytes.isEmpty {
            var buffer = channel.allocator.buffer(capacity: bytes.utf8.count)
            buffer.writeString(bytes)
            try await channel.writeAndFlush(buffer).get()
        }
        return channel
    }
}

/// A TLS client's stand-in: sends `ping`, collects the answer.
final class Client: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    let done: EventLoopPromise<String>
    var answer = ""

    init(done: EventLoopPromise<String>) { self.done = done }

    func channelActive(context: ChannelHandlerContext) {
        var buffer = context.channel.allocator.buffer(capacity: 4)
        buffer.writeString("ping")
        context.writeAndFlush(NIOAny(buffer), promise: nil)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = unwrapInboundIn(data)
        answer += buffer.readString(length: buffer.readableBytes) ?? ""
    }

    func channelInactive(context: ChannelHandlerContext) { done.succeed(answer) }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        done.fail(error)
        context.close(promise: nil)
    }
}

@Test func aTLSConnectionReachesTheInnerListenerNamedByItsClient() async throws {
    let rig = try await Rig.start()
    // Each hello shown the certificate its name picks: checked as a paired client checks it, by its pins.
    #expect(try await rig.ask(nil, trusting: rig.own) == "127.0.0.1 said ping")
    #expect(try await rig.ask("mac.example.ts.net", trusting: rig.ca) == "127.0.0.1 said ping")
    await #expect(throws: (any Error).self) { _ = try await rig.ask("mac.example.ts.net", trusting: rig.own) }
    try await rig.stop()
}

@Test func aStreamToAQuietClientOutlivesTheIdleLimit() async throws {
    // The client sends 4 bytes and then nothing; the server writes for 4 times the idle limit.
    let rig = try await Rig.start(limits: TLSFront.Limits(idle: .milliseconds(400)), stream: (.milliseconds(100), 16))
    #expect(try await rig.ask(nil, trusting: rig.own) == String(repeating: "x", count: 16))
    try await rig.stop()
}

@Test func nothingReachesTheInnerListenerBeforeAHandshake() async throws {
    let rig = try await Rig.start(limits: TLSFront.Limits(handshake: .milliseconds(300)))
    // A plain-HTTP client and a silent socket: neither connects inward, and both are closed at the handshake's limit.
    let http = try await rig.plain("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    let silent = try await rig.plain()
    try await http.closeFuture.get()
    try await silent.closeFuture.get()
    #expect(rig.connections.withLockedValue { $0 } == 0)
    #expect(rig.logged.withLockedValue { $0 }.contains { $0.contains("no handshake in time") || $0.contains("handshake") })
    try await rig.stop()
}

@Test func oneAddressCantTakeEveryConnection() async throws {
    let rig = try await Rig.start(limits: TLSFront.Limits(maxPerAddress: 2, handshake: .seconds(5)))
    let held = [try await rig.plain(), try await rig.plain()]
    // A third from the same address: closed at once (its handshake can't begin).
    await #expect(throws: (any Error).self) { _ = try await rig.ask(nil, trusting: rig.own) }
    #expect(rig.logged.withLockedValue { $0 }.contains { $0.contains("too many connections from that address") })
    for channel in held { try await channel.close() }
    try await Task.sleep(for: .milliseconds(100))
    #expect(try await rig.ask(nil, trusting: rig.own) == "127.0.0.1 said ping", "room again once they close")
    try await rig.stop()
}

@Test func aFrontWontStartWithAWeakSecret() async throws {
    let identity = try ServerIdentity.make(commonName: "Own", dnsNames: ["mac.local"])
    let front = TLSFront()
    await #expect(throws: TLSFront.BadSecret.self) {
        try await front.start(host: "127.0.0.1", port: 0, inner: 1, secret: "short",
                              certificates: ServerCertificates(ca: nil, own: PEMPair(chain: identity.chain, key: identity.key)))
    }
}
