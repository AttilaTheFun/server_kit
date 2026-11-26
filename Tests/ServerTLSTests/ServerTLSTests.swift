import Foundation
import NIOCore
import NIOPosix
import NIOSSL
import ServerIdentity
import Testing
@testable import ServerTLS

let caPair = PEMPair(chain: "ca chain", key: "ca key")
let ownPair = PEMPair(chain: "own chain", key: "own key")

@Test func aHelloGetsTheCAsPairForItsNamesAndTheServersOwnForTheRest() {
    let certificates = ServerCertificates(caNames: ["Mac.Example.ts.net"], caSuffixes: [".ts.net"], ca: caPair, own: ownPair)
    #expect(certificates.choice(for: "mac.example.ts.net") == .ca)
    #expect(certificates.choice(for: "MAC.example.ts.net.") == .ca, "any case, a trailing dot")
    #expect(certificates.choice(for: "other.example.ts.net") == .ca, "under its suffix")
    for name: String? in [nil, "", "192.168.1.5", "mac.local", "studio", "example.com"] {
        #expect(certificates.choice(for: name) == .own, "\(name ?? "no name")")
    }
    #expect(certificates.pair(for: "mac.example.ts.net") == caPair && certificates.pair(for: nil) == ownPair)
    // One missing: the other, whatever's asked.
    #expect(ServerCertificates(caNames: ["a.ts.net"], ca: nil, own: ownPair).pair(for: "a.ts.net") == ownPair)
    #expect(ServerCertificates(ca: caPair, own: nil).pair(for: "10.0.0.2") == caPair)
}

@Test func aProxyLineIsWrittenAndRead() {
    let bytes = Array((ProxyV1.preamble("s3cret") + ProxyV1.line(client: "192.168.1.9", clientPort: 50000, server: "192.168.1.5", serverPort: 7445) + "GET /").utf8)
    let read = try? ProxyV1.parse(bytes, secret: "s3cret")?.get()
    #expect(read?.client == "192.168.1.9" && read.map { Array(bytes[$0.length...]) } == Array("GET /".utf8))
    let six = Array((ProxyV1.preamble("s") + ProxyV1.line(client: "fe80::1", clientPort: 1, server: "::1", serverPort: 2)).utf8)
    #expect((try? ProxyV1.parse(six, secret: "s")?.get())?.client == "fe80::1")
}

@Test func aProxyLineNotAllThereIsWaitedFor() {
    let whole = Array((ProxyV1.preamble("s3cret") + ProxyV1.line(client: "10.0.0.1", clientPort: 1, server: "10.0.0.2", serverPort: 2)).utf8)
    for count in [0, 3, 14, 20, whole.count - 1] { #expect(ProxyV1.parse(Array(whole.prefix(count)), secret: "s3cret") == nil, "\(count)") }
}

@Test func whatIsntTheListenersIsRefused() {
    func refused(_ text: String, _ why: Comment) {
        let result = ProxyV1.parse(Array(text.utf8), secret: "s3cret")
        if case .failure = result {} else { Issue.record(why) }
    }
    refused("GET / HTTP/1.1\r\n", "no preamble")
    refused("SERVERKIT-TLS other!\r\nPROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n", "another's secret")
    refused("SERVERKIT-TLS s3cret\r\nPROXY UNKNOWN\r\n", "UNKNOWN")
    refused("SERVERKIT-TLS s3cret\r\nPROXY TCP4 fe80::1 5.6.7.8 1 2\r\n", "an address of the other family")
    refused("SERVERKIT-TLS s3cret\r\nPROXY TCP4 1.2.3.4 5.6.7.8 1 70000\r\n", "a port that isn't one")
    refused("SERVERKIT-TLS s3cret\r\nPROXY TCP4 1.2.3.4 5.6.7.8 +1 2\r\n", "a sign")
    refused("SERVERKIT-TLS s3cret\r\n" + String(repeating: "x", count: 120), "too long, no line end")
}

@Test func tailnetNamesAreTold() {
    #expect(TailscaleCertificate.isName("mac.example.ts.net"))
    for name in ["ts.net", ".ts.net", "mac.example.com", "mac;rm.ts.net", "-x.ts.net"] { #expect(!TailscaleCertificate.isName(name), "\(name)") }
    #expect(TailscaleCertificate(name: "mac.example.ts.net", folder: URL(fileURLWithPath: "/tmp"), tool: nil) == nil, "no Tailscale")
}

@Test func tailscalesAnswerIsReadAndKept() async throws {
    // A stand-in for Tailscale's command: prints a chain and a key, as `tailscale cert --cert-file=- --key-file=-` does.
    let place = NSTemporaryDirectory() + "server-tls-\(UUID().uuidString)"
    defer { try? FileManager.default.removeItem(atPath: place) }
    try FileManager.default.createDirectory(atPath: place, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(atPath: place + "/bin", withIntermediateDirectories: true)
    let tool = place + "/bin/tailscale"
    let pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n"
        + "-----BEGIN EC PRIVATE KEY-----\nCCCC\n-----END EC PRIVATE KEY-----\n"
    try "#!/bin/sh\ncat <<'EOF'\n\(pem)EOF\n".write(toFile: tool, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: tool)
    let certificate = try #require(TailscaleCertificate(name: "mac.example.ts.net", folder: URL(fileURLWithPath: place), tool: tool))
    let pair = try await certificate.refresh().get()
    #expect(pair.chain.contains("AAAA") && pair.chain.contains("BBBB") && pair.key.contains("CCCC"))
    #expect(certificate.kept() == pair)
    let mode = try FileManager.default.attributesOfItem(atPath: certificate.keyFile.path)[.posixPermissions] as? Int
    #expect(mode == 0o600)

    // A failure: said, with what it said.
    try "#!/bin/sh\necho 'not logged in' >&2\nexit 3\n".write(toFile: tool, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: tool)
    guard case .failure(let failure) = await certificate.refresh() else { Issue.record("not refused"); return }
    #expect(failure.description.contains("exit 3") && failure.description.contains("not logged in"))
    #expect(certificate.kept() == pair, "the last one kept")
}

/// The inner listener's stand-in: reads the preamble and PROXY line, then answers with the client it names and what
/// came after.
final class Inner: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    let secret: String
    var bytes: [UInt8] = []
    var answered = false

    init(secret: String) { self.secret = secret }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = unwrapInboundIn(data)
        bytes += buffer.readBytes(length: buffer.readableBytes) ?? []
        guard !answered, let result = ProxyV1.parse(bytes, secret: secret) else { return }
        guard case .success(let read) = result else { return context.close(promise: nil) }
        let rest = Array(bytes[read.length...])
        guard rest.count >= 4 else { return }
        answered = true
        var answer = context.channel.allocator.buffer(capacity: 64)
        answer.writeString("\(read.client) said \(String(decoding: rest, as: UTF8.self))")
        context.writeAndFlush(NIOAny(answer)).whenComplete { _ in context.close(promise: nil) }
    }
}

/// A TLS client's stand-in: sends `ping`, collects the answer and the certificate it was shown.
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

    func channelInactive(context: ChannelHandlerContext) { done.completeWith(.success(answer)) }
    func errorCaught(context: ChannelHandlerContext, error: Error) {
        done.fail(error)
        context.close(promise: nil)
    }
}

@Test func aTLSConnectionReachesTheInnerListenerNamedByItsClient() throws {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    defer { try? group.syncShutdownGracefully() }
    let secret = "s3cret"
    let inner = try ServerBootstrap(group: group)
        .childChannelInitializer { channel in channel.eventLoop.makeCompletedFuture { try channel.pipeline.syncOperations.addHandler(Inner(secret: secret)) } }
        .bind(host: "127.0.0.1", port: 0).wait()
    defer { try? inner.close().wait() }

    let own = try ServerIdentity.make(commonName: "Own", dnsNames: ["mac.local"], ipv4: ["127.0.0.1"])
    let ca = try ServerIdentity.make(commonName: "CA's", dnsNames: ["mac.example.ts.net"])
    let front = TLSFront()
    let port = try front.start(host: "127.0.0.1", port: 0, inner: inner.localAddress!.port!, secret: secret,
                               certificates: ServerCertificates(caNames: ["mac.example.ts.net"], ca: PEMPair(chain: ca.chain, key: ca.key),
                                                                own: PEMPair(chain: own.chain, key: own.key)))
    defer { front.stop() }

    // Each hello shown the certificate its name picks: checked as a paired client checks it, by its pins.
    func ask(_ serverName: String?, trusting identity: ServerIdentity) throws -> String {
        var configuration = TLSConfiguration.makeClientConfiguration()
        configuration.certificateVerification = .noHostnameVerification
        let verify: NIOSSLCustomVerificationCallback = { chain, promise in
            let shown = chain.first.flatMap { try? ServerIdentity.pins(ofCertificateDER: $0.toDERBytes()) }
            promise.succeed(shown == identity.pins ? .certificateVerified : .failed)
        }
        let context = try NIOSSLContext(configuration: configuration)
        let done = group.next().makePromise(of: String.self)
        _ = try ClientBootstrap(group: group)
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(try NIOSSLClientHandler(context: context, serverHostname: serverName, customVerificationCallback: verify))
                    try channel.pipeline.syncOperations.addHandler(Client(done: done))
                }
            }
            .connect(host: "127.0.0.1", port: port).wait()
        return try done.futureResult.wait()
    }
    #expect(try ask(nil, trusting: own) == "127.0.0.1 said ping")
    #expect(try ask("mac.example.ts.net", trusting: ca) == "127.0.0.1 said ping")
    #expect(throws: (any Error).self) { try ask("mac.example.ts.net", trusting: own) }
}
