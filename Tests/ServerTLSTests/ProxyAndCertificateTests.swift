import Foundation
import NIOConcurrencyHelpers
import NIOCore
import NIOEmbedded
import ServerIdentity
import Testing
@testable import ServerTLS

let caPair = PEMPair(chain: "ca chain", key: "ca key")
let ownPair = PEMPair(chain: "own chain", key: "own key")
let secret = "0123456789abcdefSECRET"

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

@Test func aSuffixIsAWholeLabels() {
    // Given without its dot, it still never matches a name that only ends in its letters.
    let certificates = ServerCertificates(caSuffixes: ["ts.net"], ca: caPair, own: ownPair)
    #expect(certificates.choice(for: "mac.example.ts.net") == .ca)
    #expect(certificates.choice(for: "evilts.net") == .own && certificates.choice(for: "ts.net") == .own)
}

func header(_ client: String = "192.168.1.9", _ port: Int = 50000) -> String {
    ProxyV1.preamble(secret) + ProxyV1.line(client: client, clientPort: port, server: "192.168.1.5", serverPort: 7445)
}

@Test func aHeaderIsWrittenAndRead() throws {
    let bytes = Array((header() + "GET /").utf8)
    let read = try #require(try ProxyV1.parse(bytes, secret: secret)?.get())
    #expect(read == ProxyV1.Header(client: "192.168.1.9", clientPort: 50000, server: "192.168.1.5", serverPort: 7445,
                                   length: bytes.count - 5))
    let six = Array((ProxyV1.preamble(secret) + ProxyV1.line(client: "fe80::1", clientPort: 0, server: "::1", serverPort: 2)).utf8)
    #expect((try ProxyV1.parse(six, secret: secret)?.get())?.client == "fe80::1")
}

@Test func aHeaderNotAllThereIsWaitedFor() {
    let whole = Array(header("10.0.0.1", 1).utf8)
    for count in [0, 3, 14, 20, whole.count - 1] { #expect(ProxyV1.parse(Array(whole.prefix(count)), secret: secret) == nil, "\(count)") }
}

@Test func whatIsntTheFrontsIsRefused() {
    let start = ProxyV1.preamble(secret)
    func refused(_ text: String, _ why: Comment) {
        if case .failure? = ProxyV1.parse(Array(text.utf8), secret: secret) {} else { Issue.record(why) }
    }
    refused("GET / HTTP/1.1\r\n", "no preamble")
    refused("SERVERKIT-TLS 0123456789abcdefOTHER!\r\nPROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n", "another's secret")
    refused(start + "PROXY UNKNOWN\r\n", "UNKNOWN")
    refused(start + "PROXY TCP4 fe80::1 5.6.7.8 1 2\r\n", "an address of the other family")
    refused(start + "PROXY TCP4 1.2.3.4 5.6.7.8 1 70000\r\n", "a port that isn't one")
    refused(start + "PROXY TCP4 1.2.3.4 5.6.7.8 +1 2\r\n", "a sign")
    refused(start + "PROXY TCP4 1.2.3.4 5.6.7.8 0080 2\r\n", "a leading zero")
    refused(start + "PROXY TCP4 1.2.3.4 5.6.7.8  1 2\r\n", "two spaces")
    refused(start + String(repeating: "x", count: 120), "too long, no line end")
    // A long buffer: refused from its first 107 bytes, not scanned whole.
    refused(start + String(repeating: "x", count: 5_000_000) + "\r\n", "a line end far beyond")
}

@Test func aSecretIsLongAndPlain() {
    #expect(ProxyV1.isValidSecret(secret))
    for bad in ["", "short", "0123456789abcdef with space", "0123456789abcdef\r\nPROXY", "0123456789abcdefé"] {
        #expect(!ProxyV1.isValidSecret(bad), "\(bad)")
    }
}

@Test func aReaderTakesBytesAsTheyCome() {
    var reader = ProxyV1.Reader(secret: secret)
    let bytes = Array((header() + "GET /").utf8)
    #expect(reader.feed(bytes.prefix(10)) == .more)
    #expect(reader.feed(bytes[10..<30]) == .more)
    guard case .done(let read, let rest) = reader.feed(bytes[30...]) else { Issue.record("not read"); return }
    #expect(read.client == "192.168.1.9" && rest == Array("GET /".utf8))
    // Bytes that never make a header: refused at the most a header takes.
    var endless = ProxyV1.Reader(secret: secret)
    #expect(endless.feed(Array(ProxyV1.preamble(secret).utf8)) == .more)
    guard case .refused = endless.feed([UInt8](repeating: 0x41, count: 200)) else { Issue.record("not refused"); return }
}

@Test func theInnerHandlerPassesTheRequestOnWithItsClient() throws {
    let channel = EmbeddedChannel()
    let events = Events()
    try channel.pipeline.syncOperations.addHandler(events)
    try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 1)).wait()
    channel.remoteAddress = try SocketAddress(ipAddress: "127.0.0.1", port: 50000)
    try channel.pipeline.syncOperations.addHandler(ProxyV1Handler(secret: secret), position: .first)
    var first = channel.allocator.buffer(capacity: 64)
    first.writeString(String(header().prefix(20)))
    try channel.writeInbound(first)
    var second = channel.allocator.buffer(capacity: 64)
    second.writeString(String(header().dropFirst(20)) + "GET /")
    try channel.writeInbound(second)
    #expect(events.headers.map(\.client) == ["192.168.1.9"])
    #expect(try channel.readInbound(as: ByteBuffer.self).map { String(buffer: $0) } == "GET /")
    // Out of the way after: what follows passes as it is.
    var third = channel.allocator.buffer(capacity: 8)
    third.writeString(" HTTP/1.1")
    try channel.writeInbound(third)
    #expect(try channel.readInbound(as: ByteBuffer.self).map { String(buffer: $0) } == " HTTP/1.1")
    _ = try? channel.finish()
}

@Test func theInnerHandlerTakesNothingFromElsewhereOrWithoutTheSecret() throws {
    // Not from loopback: closed at once.
    let away = EmbeddedChannel()
    try away.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 1)).wait()
    away.remoteAddress = try SocketAddress(ipAddress: "192.168.1.9", port: 1)
    try away.pipeline.syncOperations.addHandler(ProxyV1Handler(secret: secret))
    #expect(!away.isActive)
    // Another's header: closed.
    let wrong = EmbeddedChannel()
    try wrong.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 1)).wait()
    wrong.remoteAddress = try SocketAddress(ipAddress: "127.0.0.1", port: 2)
    try wrong.pipeline.syncOperations.addHandler(ProxyV1Handler(secret: secret))
    var bytes = wrong.allocator.buffer(capacity: 64)
    bytes.writeString("GET / HTTP/1.1\r\n\r\n")
    _ = try? wrong.writeInbound(bytes)
    #expect(!wrong.isActive)
    #expect(try wrong.readInbound(as: ByteBuffer.self) == nil, "nothing passed on")
}

final class Events: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    var headers: [ProxyV1.Header] = []
    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let header = event as? ProxyV1.Header { headers.append(header) }
        context.fireUserInboundEventTriggered(event)
    }
    func channelRead(context: ChannelHandlerContext, data: NIOAny) { context.fireChannelRead(data) }
}

@Test func aPairIsCheckedBeforeItServes() throws {
    let now = Date()
    let identity = try ServerIdentity.make(commonName: "Mac", dnsNames: ["mac.local"], now: now)
    let other = try ServerIdentity.make(commonName: "Other", dnsNames: ["other.local"], now: now)
    try PEMPair(chain: identity.chain, key: identity.key).check(now: now.addingTimeInterval(60))
    #expect(throws: PEMPair.Unusable.self) { try PEMPair(chain: identity.chain, key: other.key).check(now: now.addingTimeInterval(60)) }
    #expect(throws: PEMPair.Unusable.self) {
        try PEMPair(chain: identity.chain, key: identity.key).check(now: now.addingTimeInterval(400 * 365 * 86_400))
    }
}

#if !os(iOS) && !os(tvOS) && !os(watchOS) && !os(visionOS)
@Test func tailnetNamesAreTold() {
    #expect(TailscaleCertificate.isName("mac.example.ts.net"))
    for name in ["ts.net", ".ts.net", "mac.example.com", "mac;rm.ts.net", "-x.ts.net"] { #expect(!TailscaleCertificate.isName(name), "\(name)") }
    #expect(TailscaleCertificate(name: "mac.example.ts.net", folder: URL(fileURLWithPath: "/tmp"), tool: nil) == nil, "no Tailscale")
}

@Test func tailscalesAnswerIsReadAndKept() async throws {
    // A stand-in for Tailscale's command: prints a chain and its key, as `tailscale cert --cert-file=- --key-file=-` does.
    let place = NSTemporaryDirectory() + "server-tls-\(UUID().uuidString)"
    defer { try? FileManager.default.removeItem(atPath: place) }
    try FileManager.default.createDirectory(atPath: place + "/bin", withIntermediateDirectories: true)
    let tool = place + "/bin/tailscale"
    func standIn(_ script: String) throws {
        try script.write(toFile: tool, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: tool)
    }
    let identity = try ServerIdentity.make(commonName: "mac.example.ts.net", dnsNames: ["mac.example.ts.net"])
    try standIn("#!/bin/sh\ncat <<'EOF'\n\(identity.chain)\(identity.key)EOF\n")
    let certificate = try #require(TailscaleCertificate(name: "mac.example.ts.net", folder: URL(fileURLWithPath: place), tool: tool))
    let pair = try await certificate.refresh().get()
    #expect(pair.chain.contains("BEGIN CERTIFICATE") && pair.key.contains("PRIVATE KEY"))
    #expect(certificate.kept() == pair)
    let mode = try FileManager.default.attributesOfItem(atPath: certificate.file.path)[.posixPermissions] as? Int
    #expect(mode == 0o600)
    #expect(certificate.kept(now: Date().addingTimeInterval(400 * 365 * 86_400)) == nil, "past its end: not served")

    // A pair whose key isn't its certificate's: refused, the last one kept.
    let other = try ServerIdentity.make(commonName: "Other", dnsNames: ["other.local"])
    try standIn("#!/bin/sh\ncat <<'EOF'\n\(identity.chain)\(other.key)EOF\n")
    guard case .failure = await certificate.refresh() else { Issue.record("a mismatched pair kept"); return }
    #expect(certificate.kept() == pair)

    // A failure: said, with what it said.
    try standIn("#!/bin/sh\necho 'not logged in' >&2\nexit 3\n")
    guard case .failure(let failure) = await certificate.refresh() else { Issue.record("not refused"); return }
    #expect(failure.description.contains("exit 3") && failure.description.contains("not logged in"))

    // One that hangs past its time, ignoring TERM: stopped all the same.
    try standIn("#!/bin/sh\nexec perl -e '$SIG{TERM} = \"IGNORE\"; sleep 60'\n")
    let started = Date()
    guard case .failure = await certificate.refresh(timeout: .milliseconds(200)) else { Issue.record("not stopped"); return }
    #expect(Date().timeIntervalSince(started) < 20)
    // One whose child outlives it, holding its pipes: the answer doesn't wait for the child.
    try standIn("#!/bin/sh\ntrap '' TERM\nsleep 60\n")
    let again = Date()
    guard case .failure = await certificate.refresh(timeout: .milliseconds(200)) else { Issue.record("not stopped"); return }
    #expect(Date().timeIntervalSince(again) < 20)
}
#endif

@Test func anIPv6HostIsCountedByItsSlash64() {
    #expect(TLSFront.place(of: "2001:db8:1:2::5") == TLSFront.place(of: "2001:db8:1:2:abcd::9"))
    #expect(TLSFront.place(of: "2001:db8:1:2::5") != TLSFront.place(of: "2001:db8:1:3::5"))
    #expect(TLSFront.place(of: "192.168.1.9") == "192.168.1.9")
    // A tailnet's nodes share one /96: each counts alone, so one node can't use up the others' room.
    let a = "fd7a:115c:a1e0:ab12:4843:cd96:6201:1", b = "fd7a:115c:a1e0:ab12:4843:cd96:6201:2"
    #expect(TLSFront.place(of: a) != TLSFront.place(of: b) && TLSFront.place(of: a) == TLSFront.place(of: a))
}

@Test func refusalsAreSaidWithoutFlooding() {
    let said = NIOLockedValueBox<[String]>([])
    let log = RefusalLog(every: .seconds(10)) { line in said.withLockedValue { $0.append(line) } }
    let start = NIODeadline.now()
    for _ in 0..<1000 { log.say("cap", "refused", now: start) }
    log.say("handshake", "slow", now: start)
    log.say("cap", "refused", now: start + .seconds(11))
    #expect(said.withLockedValue { $0 } == ["refused", "slow", "refused (and 999 more like it since the last)"])
}

#if !os(iOS) && !os(tvOS) && !os(watchOS) && !os(visionOS)
@Test func aCommandGetsNothingOfTheServersButItsOutputs() async throws {
    // A descriptor this process holds open (a listener's, a client's socket): not open in the command it runs.
    // Numbered high, apart from those `ls` opens for itself.
    let opened = open("/dev/null", O_RDONLY)
    let held = fcntl(opened, F_DUPFD, 200)
    close(opened)
    defer { close(held) }
    #expect(held >= 200)
    let ran = try await TailscaleCertificate.run("/bin/sh", ["-c", "ls /proc/self/fd 2>/dev/null || ls /dev/fd"],
                                                 environment: [:], timeout: .seconds(10))
    let open = ran.output.split(separator: "\n").compactMap { Int($0) }
    #expect(ran.status == 0 && !open.contains(Int(held)), "open in the command: \(open)")
}
#endif
