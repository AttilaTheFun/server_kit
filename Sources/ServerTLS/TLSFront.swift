import NIOConcurrencyHelpers
import NIOCore
import NIOPosix
import NIOSSL
import NIOTLS
import NetworkCore

// A server's TLS front: it ends TLS on every interface, with the pair ServerCertificates picks for each hello's SNI,
// and passes each connection's bytes to the server's own plain listener on loopback, once its handshake is done, after
// the secret's line and a PROXY v1 line naming the client (ProxyV1), so the server knows a request came over TLS, and
// from whom, and never takes a TLS client for this machine. New certificates (a CA's renewed) are taken up by
// connections made after `use`, without a restart.

public final class TLSFront: Sendable {
    public struct Limits: Sendable {
        /// Connections at once; more are closed as they come.
        public var maxConnections: Int
        /// Connections at once from one address (nil: no limit of its own).
        public var maxPerAddress: Int?
        /// A connection whose handshake isn't done in this long is closed.
        public var handshake: TimeAmount
        /// A connection with nothing read or written this long, either way, is closed (a stream the server writes to
        /// a quiet client stays open).
        public var idle: TimeAmount
        /// What a connection may send before the inner listener answers its connect; more and it's closed.
        public var waitingCap: Int

        public init(maxConnections: Int = 256, maxPerAddress: Int? = nil, handshake: TimeAmount = .seconds(10),
                    idle: TimeAmount = .minutes(5), waitingCap: Int = 1 << 20) {
            self.maxConnections = maxConnections
            self.maxPerAddress = maxPerAddress
            self.handshake = handshake
            self.idle = idle
            self.waitingCap = waitingCap
        }
    }

    public struct NoCertificate: Error, CustomStringConvertible {
        public var description: String { "no certificate to answer with" }
    }

    public struct BadSecret: Error, CustomStringConvertible {
        public var description: String { "the secret must be 16 or more printable ASCII characters, without spaces" }
    }

    let limits: Limits
    let group: any EventLoopGroup
    let log: RefusalLog?
    private let state = NIOLockedValueBox(State())

    struct State {
        var context: NIOSSLContext?
        var channel: Channel?
        var open = 0
        var perAddress: [String: Int] = [:]
    }

    /// `log` is told why connections are refused or closed early (a cap, a failed or slow handshake), at most a line
    /// of each kind every 10 seconds with a count of the rest; nothing of what they carry.
    public init(limits: Limits = Limits(), group: any EventLoopGroup = MultiThreadedEventLoopGroup.singleton,
                log: (@Sendable (String) -> Void)? = nil) {
        self.limits = limits
        self.group = group
        self.log = log.map { RefusalLog($0) }
    }

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

    /// Listens on `port` (0: one the system picks) of `host`: every interface by default, IPv6 and IPv4 alike, or
    /// IPv4's alone where the machine has no IPv6. Each connection is passed to `inner` on loopback, behind `secret`
    /// (ProxyV1.isValidSecret). The port it listens on.
    @discardableResult
    public func start(host: String? = nil, port: Int, inner: Int, secret: String, certificates: ServerCertificates) async throws -> Int {
        guard ProxyV1.isValidSecret(secret) else { throw BadSecret() }
        try use(certificates)
        let limits = limits, state = state, log = log
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.backlog, value: 256)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                let address = Splice.address(channel.remoteAddress), place = Self.place(of: address)
                let admitted: Result<NIOSSLContext, Refusal> = state.withLockedValue {
                    guard let context = $0.context else { return .failure(.noCertificate) }
                    guard $0.open < limits.maxConnections else { return .failure(.tooMany) }
                    let fromThere = $0.perAddress[place, default: 0]
                    if let most = limits.maxPerAddress, fromThere >= most { return .failure(.tooManyFrom) }
                    $0.open += 1
                    $0.perAddress[place] = fromThere + 1
                    return .success(context)
                }
                let context: NIOSSLContext
                switch admitted {
                case .success(let admitted): context = admitted
                case .failure(let refusal):
                    log?.say("refused \(refusal)", "refused a connection from \(address): \(refusal)")
                    return channel.close()
                }
                channel.closeFuture.whenComplete { _ in
                    state.withLockedValue {
                        $0.open -= 1
                        let left = ($0.perAddress[place] ?? 1) - 1
                        $0.perAddress[place] = left > 0 ? left : nil
                    }
                }
                return channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: context))
                    try channel.pipeline.syncOperations.addHandler(IdleStateHandler(allTimeout: limits.idle))
                    try channel.pipeline.syncOperations.addHandler(Splice(inner: inner, secret: secret, limits: limits, log: log))
                }
            }
        let bound: Channel
        if let host {
            bound = try await bootstrap.bind(host: host, port: port).get()
        } else {
            do {
                bound = try await bootstrap.bind(host: "::", port: port).get()
            } catch {
                bound = try await bootstrap.bind(host: "0.0.0.0", port: port).get()
            }
        }
        state.withLockedValue { $0.channel = bound }
        return bound.localAddress?.port ?? port
    }

    /// Stops listening; connections open now run on until they close.
    public func stop() async {
        let bound = state.withLockedValue { value -> Channel? in
            defer { value.channel = nil }
            return value.channel
        }
        try? await bound?.close().get()
    }

    /// Where connections are counted from for `maxPerAddress`: an IPv4 address, or an IPv6 host's /64 (one host has
    /// all of it to pick addresses from).
    static func place(of address: String) -> String {
        guard address.contains(":"), let prefix = IPv6.prefix64(address) else { return address }
        return prefix + "/64"
    }

    enum Refusal: Error, CustomStringConvertible {
        case noCertificate, tooMany, tooManyFrom
        var description: String {
            switch self {
            case .noCertificate: "no certificate"
            case .tooMany: "too many connections"
            case .tooManyFrom: "too many connections from that address"
            }
        }
    }
}

/// A TLS connection's plaintext, passed to the inner listener behind its preamble and PROXY v1 line once its handshake
/// is done, and its answers back.
final class Splice: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    let inner: Int
    let secret: String
    let limits: TLSFront.Limits
    let log: RefusalLog?
    private var waiting: [ByteBuffer] = []
    private var waitingBytes = 0
    private var peer: Channel?
    private var closed = false
    private var handshakeDeadline: Scheduled<Void>?

    init(inner: Int, secret: String, limits: TLSFront.Limits, log: RefusalLog?) {
        self.inner = inner
        self.secret = secret
        self.limits = limits
        self.log = log
    }

    func handlerAdded(context: ChannelHandlerContext) {
        // A handshake not done in time: a scan, a plain-HTTP client, a socket held open to use up the caps.
        let channel = context.channel, log = log, address = Self.address(channel.remoteAddress)
        handshakeDeadline = context.eventLoop.scheduleTask(in: limits.handshake) {
            log?.say("handshake timeout", "closed a connection from \(address): no handshake in time")
            channel.close(promise: nil)
        }
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let event = event as? TLSUserEvent, case .handshakeCompleted = event {
            handshakeDeadline?.cancel()
            handshakeDeadline = nil
            connect(context: context)
        }
        // Nothing read or written for the idle limit: a connection left open.
        if event is IdleStateHandler.IdleStateEvent { return context.close(promise: nil) }
        context.fireUserInboundEventTriggered(event)
    }

    /// The inner listener, reached only for a client that finished its handshake.
    func connect(context: ChannelHandlerContext) {
        let ours = context.channel
        let client = ours.remoteAddress, local = ours.localAddress
        let line = ProxyV1.preamble(secret) + ProxyV1.line(client: Self.address(client), clientPort: client?.port ?? 0,
                                                           server: Self.address(local), serverPort: local?.port ?? 0)
        let loop = context.eventLoop, log = log
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
                case .failure(let error):
                    log?.say("inner", "couldn't reach the inner listener: \(error)")
                    ours.close(promise: nil)
                }
            }
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
        guard waitingBytes <= limits.waitingCap else { return context.close(promise: nil) }
        waiting.append(buffer)
    }

    /// The client reading again (its side writable): the inner listener's answers read again.
    func channelWritabilityChanged(context: ChannelHandlerContext) {
        if context.channel.isWritable { peer?.setOption(ChannelOptions.autoRead, value: true).whenComplete { _ in } }
        context.fireChannelWritabilityChanged()
    }

    func channelInactive(context: ChannelHandlerContext) {
        closed = true
        handshakeDeadline?.cancel()
        peer?.close(promise: nil)
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        if peer == nil, error is NIOSSLError || error is BoringSSLError {
            log?.say("handshake failed", "a handshake from \(Self.address(context.channel.remoteAddress)) failed: \(error)")
        }
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
