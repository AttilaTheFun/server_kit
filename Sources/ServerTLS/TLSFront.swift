import Foundation
import NIOConcurrencyHelpers
import NIOCore
import NIOPosix
import NIOSSL

// A server's TLS front: it ends TLS on every interface, with the pair ServerCertificates picks for each hello's SNI,
// and passes each connection's bytes to the server's own plain listener on loopback, after the start's secret and a
// PROXY v1 line naming the client (ProxyV1), so the server knows a request came over TLS, and from whom, and never
// takes a TLS client for this machine. New certificates (a CA's renewed) are taken up by connections made after
// `use`, without a restart.

public final class TLSFront: @unchecked Sendable {
    public struct Limits: Sendable {
        /// Connections at once; more are closed as they come.
        public var maxConnections: Int
        /// A connection that sends nothing this long (its handshake stalled, or idle) is closed.
        public var idle: TimeAmount
        /// What a connection may send before the inner listener answers its connect; more and it's closed.
        public var waitingCap: Int

        public init(maxConnections: Int = 256, idle: TimeAmount = .minutes(5), waitingCap: Int = 1 << 20) {
            self.maxConnections = maxConnections
            self.idle = idle
            self.waitingCap = waitingCap
        }
    }

    public struct NoCertificate: Error, CustomStringConvertible {
        public var description: String { "no certificate to answer with" }
    }

    let limits: Limits
    private let group: MultiThreadedEventLoopGroup
    private let state = NIOLockedValueBox(State())

    struct State {
        var context: NIOSSLContext?
        var channel: Channel?
        var open = 0
    }

    public init(limits: Limits = Limits(), threads: Int = 2) {
        self.limits = limits
        group = MultiThreadedEventLoopGroup(numberOfThreads: threads)
    }

    deinit { try? group.syncShutdownGracefully() }

    /// A pair's certificates and key, read.
    struct Parsed: @unchecked Sendable {
        var chain: [NIOSSLCertificateSource]
        var key: NIOSSLPrivateKeySource

        init(_ pair: PEMPair) throws {
            let certificates = try NIOSSLCertificate.fromPEMBytes(Array(pair.chain.utf8))
            guard !certificates.isEmpty else { throw NoCertificate() }
            chain = certificates.map { .certificate($0) }
            key = .privateKey(try NIOSSLPrivateKey(bytes: Array(pair.key.utf8), format: .pem))
        }
    }

    /// The context: answering with the server's own pair by default (a hello naming no server), and each hello, by
    /// its SNI, with the one ServerCertificates picks.
    static func context(_ certificates: ServerCertificates) throws -> NIOSSLContext {
        let ca = try certificates.ca.map(Parsed.init), own = try certificates.own.map(Parsed.init)
        guard let first = own ?? ca else { throw NoCertificate() }
        var configuration = TLSConfiguration.makeServerConfiguration(certificateChain: first.chain, privateKey: first.key)
        configuration.minimumTLSVersion = .tlsv12
        if let ca, let own {
            configuration.sslContextCallback = { values, promise in
                let chosen = certificates.choice(for: values.serverHostname) == .ca ? ca : own
                var override = NIOSSLContextConfigurationOverride()
                override.certificateChain = chosen.chain
                override.privateKey = chosen.key
                promise.succeed(override)
            }
        }
        return try NIOSSLContext(configuration: configuration)
    }

    /// Answer with these from the next connection on.
    public func use(_ certificates: ServerCertificates) throws {
        let made = try Self.context(certificates)
        state.withLockedValue { $0.context = made }
    }

    /// Listens on `port` (0: one the system picks) of `host`: every interface by default, IPv6 and IPv4 alike, or IPv4's
    /// alone where the machine has no IPv6. Each connection is passed to `inner` on loopback. The port it listens on.
    @discardableResult
    public func start(host: String? = nil, port: Int, inner: Int, secret: String, certificates: ServerCertificates) throws -> Int {
        try use(certificates)
        let limits = limits, state = state
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.backlog, value: 256)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                let admitted: NIOSSLContext? = state.withLockedValue {
                    guard $0.open < limits.maxConnections, let context = $0.context else { return nil }
                    $0.open += 1
                    return context
                }
                guard let context = admitted else { return channel.close() }
                channel.closeFuture.whenComplete { _ in state.withLockedValue { $0.open -= 1 } }
                return channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: context))
                    try channel.pipeline.syncOperations.addHandler(IdleStateHandler(readTimeout: limits.idle))
                    try channel.pipeline.syncOperations.addHandler(Splice(inner: inner, secret: secret, waitingCap: limits.waitingCap))
                }
            }
        let bound: Channel
        if let host {
            bound = try bootstrap.bind(host: host, port: port).wait()
        } else {
            do {
                bound = try bootstrap.bind(host: "::", port: port).wait()
            } catch {
                bound = try bootstrap.bind(host: "0.0.0.0", port: port).wait()
            }
        }
        state.withLockedValue { $0.channel = bound }
        return bound.localAddress?.port ?? port
    }

    /// Stops listening; connections open now run on until they close.
    public func stop() {
        let bound = state.withLockedValue { value -> Channel? in
            defer { value.channel = nil }
            return value.channel
        }
        try? bound?.close().wait()
    }
}

/// A TLS connection's plaintext, passed to the inner listener behind its preamble and PROXY v1 line, and its answers
/// back.
final class Splice: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    let inner: Int
    let secret: String
    let waitingCap: Int
    private var waiting: [ByteBuffer] = []
    private var waitingBytes = 0
    private var peer: Channel?
    private var closed = false

    init(inner: Int, secret: String, waitingCap: Int) {
        self.inner = inner
        self.secret = secret
        self.waitingCap = waitingCap
    }

    func channelActive(context: ChannelHandlerContext) {
        let ours = context.channel
        let client = ours.remoteAddress, local = ours.localAddress
        let line = ProxyV1.preamble(secret) + ProxyV1.line(client: Self.address(client), clientPort: client?.port ?? 0,
                                                           server: Self.address(local), serverPort: local?.port ?? 0)
        let loop = context.eventLoop
        ClientBootstrap(group: loop)
            .channelInitializer { peer in
                peer.eventLoop.makeCompletedFuture { try peer.pipeline.syncOperations.addHandler(Back(to: ours)) }
            }
            .connect(host: "127.0.0.1", port: inner)
            .hop(to: loop)
            .whenComplete { [self] result in
                switch result {
                case .success(let peer):
                    guard !closed else { return peer.close(promise: nil) }
                    self.peer = peer
                    var head = peer.allocator.buffer(capacity: line.utf8.count)
                    head.writeString(line)
                    peer.write(head, promise: nil)
                    for buffer in waiting { peer.write(buffer, promise: nil) }
                    waiting = []
                    peer.flush()
                case .failure:
                    ours.close(promise: nil)
                }
            }
        context.fireChannelActive()
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let buffer = unwrapInboundIn(data)
        if let peer {
            peer.writeAndFlush(buffer, promise: nil)
            // The inner listener reading slower than the client sends: the client read no more until it catches up
            // (Back's writability), so nothing piles up here.
            if !peer.isWritable { context.channel.setOption(ChannelOptions.autoRead, value: false).whenComplete { _ in } }
            return
        }
        waitingBytes += buffer.readableBytes
        guard waitingBytes <= waitingCap else { return context.close(promise: nil) }
        waiting.append(buffer)
    }

    /// The client reading again (its side writable): the inner listener's answers read again.
    func channelWritabilityChanged(context: ChannelHandlerContext) {
        if context.channel.isWritable { peer?.setOption(ChannelOptions.autoRead, value: true).whenComplete { _ in } }
        context.fireChannelWritabilityChanged()
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        // Nothing read for the idle limit: a stalled handshake, or a connection left open.
        if event is IdleStateHandler.IdleStateEvent { return context.close(promise: nil) }
        context.fireUserInboundEventTriggered(event)
    }

    func channelInactive(context: ChannelHandlerContext) {
        closed = true
        peer?.close(promise: nil)
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }

    /// An address as the PROXY line names it: its IP, IPv4-mapped IPv6 as IPv4.
    static func address(_ socket: SocketAddress?) -> String {
        guard let ip = socket?.ipAddress else { return "0.0.0.0" }
        return ip.hasPrefix("::ffff:") && ip.contains(".") ? String(ip.dropFirst(7)) : ip
    }
}

/// The inner listener's answers, back over TLS.
final class Back: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    let to: Channel

    init(to: Channel) { self.to = to }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        to.writeAndFlush(unwrapInboundIn(data), promise: nil)
        // The client reading slower than the server answers (a big download): the inner listener read no more until
        // it catches up (Splice's writability).
        if !to.isWritable { context.channel.setOption(ChannelOptions.autoRead, value: false).whenComplete { _ in } }
    }

    /// The inner listener taking writes again: the client's bytes read again.
    func channelWritabilityChanged(context: ChannelHandlerContext) {
        if context.channel.isWritable { to.setOption(ChannelOptions.autoRead, value: true).whenComplete { _ in } }
        context.fireChannelWritabilityChanged()
    }

    func channelInactive(context: ChannelHandlerContext) {
        to.close(promise: nil)
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }
}
