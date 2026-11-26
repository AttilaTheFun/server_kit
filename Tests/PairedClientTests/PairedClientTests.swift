import Foundation
import NetworkCore
import PairingLink
import ServerIdentity
import Testing
@testable import PairedClient

@Test func aCertificatesPinsAreTheServersOwn() throws {
    let identity = try ServerIdentity.make(commonName: "Mac", dnsNames: ["mac.local"], ipv4: ["192.168.1.5"])
    let der = try #require(derOfLeaf(identity.chain))
    let shown = try #require(CertificatePins.of(der: der))
    #expect(Pin(.spki, sha256: shown.spki) == identity.spkiPin)
    #expect(PinSet([Pin(.spki, sha256: shown.spki)!, Pin(.certificate, sha256: shown.certificate)!]) == identity.pins)
    #expect(CertificatePins.match(identity.pins, der: der))
    let other = try ServerIdentity.make(commonName: "Other", dnsNames: ["other.local"])
    #expect(!CertificatePins.match(other.pins, der: der))
}

@Test func whatIsntACertificateHasNoPins() throws {
    let identity = try ServerIdentity.make(commonName: "Mac", dnsNames: ["mac.local"])
    let der = try #require(derOfLeaf(identity.chain))
    #expect(CertificatePins.of(der: []) == nil)
    #expect(CertificatePins.of(der: Array(der.dropLast())) == nil, "cut short")
    #expect(CertificatePins.of(der: der + [0]) == nil, "something after it")
    #expect(CertificatePins.of(der: [0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF]) == nil, "a length past its end")
    #expect(CertificatePins.of(der: [0x30, 0x81, 0x05, 1, 2, 3, 4, 5]) == nil, "the long form for a short length")
}

func derOfLeaf(_ pem: String) -> [UInt8]? {
    guard let begin = pem.range(of: "-----BEGIN CERTIFICATE-----"), let end = pem.range(of: "-----END CERTIFICATE-----") else { return nil }
    let body = pem[begin.upperBound..<end.lowerBound].filter { !$0.isWhitespace }
    return Data(base64Encoded: String(body)).map { [UInt8]($0) }
}

let home = NetworkInterfaces([("192.168.1.20", "255.255.255.0"), ("100.101.102.103", "255.255.255.255")])
let cafe = NetworkInterfaces([("10.9.8.7", "255.255.0.0")])

@Test func addressesAreRankedByWhereTheDeviceIs() {
    let addresses = ["https://mac.example.ts.net:7445", "https://mac.local:7445", "https://192.168.1.5:7445",
                     "https://100.64.0.9:7445", "http://127.0.0.1:7480", "https://example.com"]
    #expect(ServerPaths.ranked(addresses, network: home) == [
        "http://127.0.0.1:7480", "https://192.168.1.5:7445", "https://mac.example.ts.net:7445", "https://100.64.0.9:7445",
        "https://mac.local:7445", "https://example.com",
    ])
    // Away, off the tailnet: the LAN address and tailnet's last.
    #expect(ServerPaths.ranked(addresses, network: cafe) == [
        "http://127.0.0.1:7480", "https://mac.local:7445", "https://example.com",
        "https://mac.example.ts.net:7445", "https://192.168.1.5:7445", "https://100.64.0.9:7445",
    ])
    #expect(ServerPaths.fit(of: "user@studio:22", network: home) == .bonjour)
    #expect(ServerPaths.fit(of: "https://[::1]:7445", network: cafe) == .loopback)
    // The last good first among its equals.
    #expect(ServerPaths.ranked(["https://a.ts.net", "https://b.ts.net"], network: home, lastGood: "https://b.ts.net").first == "https://b.ts.net")
}

struct Refused: Error {}

@Test func theFirstToAnswerIsTakenAndTheSlowCostAMoment() async throws {
    let started = ContinuousClock.now
    let won = try await PathRace.first(["slow", "fast"], headStart: .milliseconds(50)) { path -> String in
        if path == "slow" { try await Task.sleep(for: .seconds(10)) }
        return path
    }
    #expect(won.path == "fast" && ContinuousClock.now - started < .seconds(5))
    // Each failing at once: the next at once, and every error said when none answer.
    await #expect(throws: PathRace.NoneAnswered.self) {
        _ = try await PathRace.first(["a", "b", "c"], headStart: .seconds(10)) { _ -> Int in throw Refused() }
    }
    let late = try await PathRace.first(["a", "b"], headStart: .seconds(10)) { path -> String in
        guard path == "b" else { throw Refused() }
        return path
    }
    #expect(late.path == "b")
}

let spkiPin = Pin(.spki, sha256: String(repeating: "ab", count: 32))!

@Test func aRecordIsMadeFromItsLinkAndKnowsItsServer() throws {
    let link = try #require(PairingLink(scheme: "example", servers: ["https://mac.example.ts.net", "https://192.168.1.5"],
                                        paths: ["http://127.0.0.1:8080", "http://192.168.1.5:8080", "ssh://mac.local"],
                                        pins: PinSet([spkiPin]), credential: .oneTimeCode("c"), serverID: "srv-1", name: "Mac"))
    let server = PairedServer(link: link)
    #expect(server.serverID == "srv-1" && server.pinSet == PinSet([spkiPin]))
    #expect(server.answers(as: "srv-1") && !server.answers(as: "srv-2") && server.answers(as: nil))
    // A credential: TLS, or this device's own loopback; never plain HTTP across a network.
    #expect(server.credentialAddresses == ["https://mac.example.ts.net", "https://192.168.1.5", "http://127.0.0.1:8080"])
    // With no pins, the pinned address is no place for it.
    var unpinned = server
    unpinned.pins = []
    #expect(unpinned.credentialAddresses == ["https://mac.example.ts.net", "http://127.0.0.1:8080"])
}

@Test func whatAServerSaysOfItselfIsTakenOnlyOverTLS() {
    let server = PairedServer(serverID: "srv-1", name: nil, servers: ["https://mac.example.ts.net", "https://192.168.1.5"],
                              pins: PinSet([spkiPin]), lastGood: "https://192.168.1.5")
    let next = Pin(.spki, sha256: String(repeating: "cd", count: 32))!
    let reach = ServerReach(addresses: ["https://mac.example.ts.net", "https://192.168.1.9", "http://192.168.1.9:8080"],
                            pins: PinSet([next, spkiPin]))
    #expect(server.merging(reach, answeredAt: "http://192.168.1.5:8080") == server, "plain HTTP: nothing taken")
    let merged = server.merging(reach, answeredAt: "https://mac.example.ts.net")
    // The moved LAN address gone, the new one in, never a plain one; the pins as the server says them now.
    #expect(merged.servers == ["https://mac.example.ts.net", "https://192.168.1.9"])
    #expect(merged.pinSet == PinSet([next, spkiPin]) && merged.lastGood == nil)
    // A server that says no pins keeps those it had.
    #expect(server.merging(ServerReach(addresses: [], pins: PinSet([])), answeredAt: "https://mac.example.ts.net").pinSet == server.pinSet)
}

@Test func eachServerHasItsOwnRecord() {
    var servers = PairedServers()
    let a = PairedServer(serverID: "a", name: "A", servers: ["https://a.example.ts.net"], pins: PinSet([]))
    let b = PairedServer(serverID: "b", name: "B", servers: ["https://a.example.ts.net"], pins: PinSet([]))
    servers.pair(a)
    servers.pair(b)
    var again = a
    again.name = "A again"
    servers.pair(again)
    #expect(servers.servers.map(\.name) == ["A again", "B"], "the same address, another id: another server")
    servers.forget(b)
    #expect(servers.servers.map(\.serverID) == ["a"])
}

@Test func networkChangesAreSaidOnceTheySettle() async throws {
    let watch = NetworkWatch()
    let told = Told()
    let token = watch.onChange { generation in told.add(generation) }
    defer { watch.stop(token) }
    watch.changed(settle: .milliseconds(20))
    watch.changed(settle: .milliseconds(20))
    try await Task.sleep(for: .milliseconds(300))
    #expect(told.values == [1], "two changes at once: one")
}

final class Told: @unchecked Sendable {
    private let lock = NSLock()
    private var seen: [Int] = []
    func add(_ value: Int) { lock.withLock { seen.append(value) } }
    var values: [Int] { lock.withLock { seen } }
}
