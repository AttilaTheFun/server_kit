import NIOCore

/// The inner listener's side of the hand-off, for a SwiftNIO listener: first in a connection's pipeline, it refuses a
/// connection from anywhere but loopback, reads the front's header (ProxyV1.Reader) within `timeout`, then sends the
/// header on as a user inbound event (`ProxyV1.Header`), the bytes after it as the connection's first read, and takes
/// itself out of the pipeline. Anything else closes the connection.
public final class ProxyV1Handler: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    public typealias InboundIn = ByteBuffer
    public typealias InboundOut = ByteBuffer

    private var reader: ProxyV1.Reader
    let timeout: TimeAmount
    private var deadline: Scheduled<Void>?
    private var done = false

    public init(secret: String, timeout: TimeAmount = .seconds(5)) {
        reader = ProxyV1.Reader(secret: secret)
        self.timeout = timeout
    }

    public func handlerAdded(context: ChannelHandlerContext) {
        guard Self.isLoopback(context.channel.remoteAddress) else { return context.close(promise: nil) }
        let channel = context.channel
        deadline = context.eventLoop.scheduleTask(in: timeout) { channel.close(promise: nil) }
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = unwrapInboundIn(data)
        guard !done else { return context.fireChannelRead(data) }
        switch reader.feed(buffer.readBytes(length: buffer.readableBytes) ?? []) {
        case .more:
            return
        case .refused:
            deadline?.cancel()
            context.close(promise: nil)
        case .done(let header, let rest):
            done = true
            deadline?.cancel()
            context.fireUserInboundEventTriggered(header)
            if !rest.isEmpty {
                var first = context.channel.allocator.buffer(capacity: rest.count)
                first.writeBytes(rest)
                context.fireChannelRead(wrapInboundOut(first))
            }
            context.pipeline.syncOperations.removeHandler(context: context, promise: nil)
        }
    }

    public func channelInactive(context: ChannelHandlerContext) {
        deadline?.cancel()
        context.fireChannelInactive()
    }

    static func isLoopback(_ address: SocketAddress?) -> Bool {
        guard let ip = address?.ipAddress else { return false }
        return ip == "::1" || ip.hasPrefix("127.") || ip.hasPrefix("::ffff:127.")
    }
}
