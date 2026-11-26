import NetworkCore
import PairingLink
import Testing
@testable import PairedCore

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
    #expect(server.answers(as: "srv-1") && !server.answers(as: "srv-2"))
    #expect(!server.answers(as: nil), "a stranger at a reused address can't pass by naming no one")
    #expect(throws: PairedServer.AnotherServer.self) { try server.check(answeredID: "srv-2") }
    #expect(PairedServer(serverID: nil, name: nil, servers: [], pins: PinSet([])).answers(as: "anyone"), "a record from before ids")
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


@Test func aCredentialNeverGoesInTheClearToAnotherMachine() throws {
    // Made: only https kept.
    let made = PairedServer(serverID: "s", name: nil, servers: ["http://example.com", "https://a.example.com", "http://10.0.0.2"],
                            pins: PinSet([spkiPin]))
    #expect(made.servers == ["https://a.example.com"])
    // Stored by something older, or by hand: refused all the same.
    var stored = made
    stored.servers = ["http://example.com", "http://10.0.0.2", "https://10.0.0.2", "HTTPS://b.example.com"]
    stored.paths = ["http://127.0.0.1:8080", "http://10.0.0.2:8080", "http://localhost.:80", "http://127.0.0.1.nip.io"]
    #expect(stored.credentialAddresses == ["https://10.0.0.2", "HTTPS://b.example.com", "http://127.0.0.1:8080"])
}

@Test func routesPutSSHFirstWhereTheDeviceTakesIt() {
    let server = PairedServer(serverID: "s", name: nil,
                              servers: ["https://mac.example.ts.net", "https://192.168.1.5", "https://example.com"],
                              paths: ["http://127.0.0.1:8080", "ssh://192.168.1.5", "user@mac.example.ts.net:22", "studio"],
                              pins: PinSet([spkiPin]), lastGood: nil)
    // Without SSH: no SSH route, by fit.
    let plain = server.routes(network: home)
    #expect(plain.map(\.address) == ["http://127.0.0.1:8080", "https://192.168.1.5", "https://mac.example.ts.net", "https://example.com"])
    #expect(plain.map(\.kind) == [.loopbackHTTP, .https, .https, .https])
    // With it: loopback, then SSH on the LAN and tailnet, then their TLS, then each further fit's SSH before the rest.
    let ssh = server.routes(network: home, policy: RoutePolicy(canSSH: true))
    #expect(ssh.map(\.address) == ["http://127.0.0.1:8080", "ssh://192.168.1.5", "user@mac.example.ts.net:22", "https://192.168.1.5",
                                    "https://mac.example.ts.net", "studio", "https://example.com"])
    // Timings: SSH has longer alone; this device's and its network's less time to answer.
    #expect(ssh[1].headStart == .milliseconds(1000) && ssh[3].headStart == .milliseconds(400))
    #expect(ssh[0].timeout == .seconds(2) && ssh[3].timeout == .seconds(2) && ssh[4].timeout == .seconds(5))
    // Not preferred: SSH in its fit like any other.
    let even = server.routes(network: home, policy: RoutePolicy(canSSH: true, preferSSH: false))
    #expect(even.map(\.address).prefix(3) == ["http://127.0.0.1:8080", "https://192.168.1.5", "ssh://192.168.1.5"])
}

@Test func homeNamesRankAsTheAppSays() {
    #expect(ServerPaths.fit(of: "https://mac.local", network: home) == .bonjour)
    #expect(ServerPaths.fit(of: "https://mac.local", network: home, ranking: .init(homeNames: .other)) == .other)
    #expect(ServerPaths.fit(of: "https://mac.local", network: NetworkInterfaces([(String, String)]())) == .unlikely)
}

@Test func aCancelledRaceStartsNothingMore() async throws {
    let started = Started()
    let race = Task {
        try await PathRace.first(["a", "b", "c", "d"], headStart: .seconds(10)) { path -> String in
            await started.add(path)
            try await Task.sleep(for: .seconds(30))
            return path
        }
    }
    try await Task.sleep(for: .milliseconds(100))
    race.cancel()
    await #expect(throws: CancellationError.self) { _ = try await race.value }
    try await Task.sleep(for: .milliseconds(100))
    #expect(await started.values == ["a"])
}

@Test func theWinnerIsntHeldByALoserThatIgnoresCancellation() async throws {
    let clock = ContinuousClock(), start = clock.now
    let won = try await PathRace.first(["stubborn", "quick"], headStart: .milliseconds(50)) { path -> String in
        if path == "stubborn" {
            // Ignores cancellation: sleeps its full time.
            let until = clock.now + .seconds(2)
            while clock.now < until { try? await Task.sleep(for: .milliseconds(50)) }
            return path
        }
        try await Task.sleep(for: .milliseconds(150))
        return path
    }
    #expect(won.path == "quick" && clock.now - start < .seconds(1))
}

@Test func aPathOutOfTimeMakesWayForTheNext() async throws {
    let clock = ContinuousClock(), start = clock.now
    let won = try await PathRace.first(["silent", "answers"], headStart: { _ in .seconds(30) },
                                       timeout: { $0 == "silent" ? .milliseconds(100) : nil }) { path -> String in
        if path == "silent" { try await Task.sleep(for: .seconds(30)) }
        return path
    }
    #expect(won.path == "answers" && clock.now - start < .seconds(2))
    await #expect(throws: PathRace.NoneAnswered.self) {
        _ = try await PathRace.first(["x"], headStart: { _ in .seconds(1) }, timeout: { _ in .milliseconds(50) }) { _ -> Int in
            try await Task.sleep(for: .seconds(30))
            return 1
        }
    }
}

actor Started {
    private(set) var values: [String] = []
    func add(_ value: String) { values.append(value) }
}
