import NetworkCore
import PairingLink

// What a device keeps of a server it paired with: one record a server (a device may pair with several), each its own,
// so what one server says never touches another's. Made from the pairing link, kept up to date by what the server says
// of where it's reached (ServerReach) over a connection already trusted.

public struct PairedServer: Codable, Hashable, Sendable {
    /// The server's own id, from the link; nil for a server that gave none. A connection answered by another id, or by
    /// none, is another server (an address reused on another network) and is refused (`answers(as:)`).
    public var serverID: String?
    /// What a person calls it.
    public var name: String?
    /// Its addresses over TLS (`https://…`), the one a CA vouches for first. Only `https` ones are made or used.
    public var servers: [String]
    /// Its other ways (plain loopback HTTP, SSH), as the link gave them.
    public var paths: [String]
    /// Its pins (`spki:<hex>`, or bare hex for a whole certificate's), current first.
    public var pins: [String]
    /// The address that answered last: first among its equals next time.
    public var lastGood: String?

    public init(serverID: String?, name: String?, servers: [String], paths: [String] = [], pins: PinSet, lastGood: String? = nil) {
        self.serverID = serverID
        self.name = name
        self.servers = servers.filter(Self.isHTTPS)
        self.paths = paths
        self.pins = pins.pins.map(\.description)
        self.lastGood = lastGood
    }

    /// The record a pairing link makes.
    public init(link: PairingLink) {
        self.init(serverID: link.serverID, name: link.name, servers: link.servers, paths: link.paths, pins: link.pins)
    }

    public var pinSet: PinSet { PinSet(pins.compactMap(Pin.init)) }

    /// Whether a server's answer (its `serverID`) is this one's: the same id. A record with no id (a server from
    /// before ids) takes any answer; one with an id refuses an answer naming none, as a stranger at a reused address
    /// would.
    public func answers(as answeredID: String?) -> Bool {
        guard let serverID else { return true }
        return answeredID == serverID
    }

    /// Another server answered where this one was looked for.
    public struct AnotherServer: Error, CustomStringConvertible {
        public var expected: String?
        public var answered: String?
        public var description: String { "another server answered (\(answered ?? "no id"), not \(expected ?? "?"))" }
    }

    /// Throws `AnotherServer` unless the answer is this server's (`answers(as:)`): for a race's attempt to call once
    /// the server has said its id, so a path that reached another server loses.
    public func check(answeredID: String?) throws {
        guard answers(as: answeredID) else { throw AnotherServer(expected: serverID, answered: answeredID) }
    }

    /// Where a credential (a session, a password) may be sent: its `https` addresses, a pinned one only with pins to
    /// check it by, and its plain `http` paths only on this device's own loopback. Never plain HTTP to another machine,
    /// whatever a stored record says.
    public var credentialAddresses: [String] {
        let pinned = !pinSet.isEmpty
        return servers.filter { address in
            guard Self.isHTTPS(address), let host = PairingLink.host(of: address) else { return false }
            return !PinTrust.isPinned(host: host) || pinned
        } + paths.filter(Self.isLoopbackHTTP)
    }

    /// Its SSH paths (`ssh://…`, or a bare `[user@]host[:port]`), as the link gave them.
    public var sshPaths: [String] { paths.filter(Self.isSSH) }

    static func isHTTPS(_ address: String) -> Bool { address.lowercased().hasPrefix("https://") }

    static func isSSH(_ path: String) -> Bool {
        let lower = path.lowercased()
        if lower.hasPrefix("ssh://") { return true }
        return !lower.contains("://") && PairingLink.pathHost(of: path) != nil
    }

    /// Its addresses a credential may go to, best first for where the device is now.
    public func ranked(network: NetworkInterfaces?) -> [String] {
        ServerPaths.ranked(credentialAddresses, network: network, lastGood: lastGood)
    }

    static func isLoopbackHTTP(_ address: String) -> Bool {
        let lower = address.lowercased()
        guard lower.hasPrefix("http://"), let host = PairingLink.host(of: lower) else { return false }
        return host == "localhost" || host == "[::1]" || IPv4.parse(host).map(IPv4.isLoopback) == true
    }

    /// The record with what its server said of itself (`reach`) over a connection already trusted (at `answeredAt`,
    /// an `https` address): its addresses added and its pins taken. Never from plain HTTP, where anyone on the way could
    /// name another address and certificate. Pinned addresses it learned before and the server no longer names (a DHCP
    /// lease moved on) go; what it was given otherwise (a CA's name) stays. A server that says no pins keeps those it had.
    public func merging(_ reach: ServerReach, answeredAt: String) -> PairedServer {
        guard answeredAt.lowercased().hasPrefix("https://") else { return self }
        let offered = reach.addresses.filter { $0.lowercased().hasPrefix("https://") && PairingLink.host(of: $0) != nil }
        let said = reach.pinSet
        let pins = said.isEmpty ? pinSet : said
        func key(_ address: String) -> String {
            var lower = address.lowercased()
            while lower.hasSuffix("/") { lower.removeLast() }
            return lower
        }
        let offeredKeys = Set(offered.map(key))
        func isPinned(_ address: String) -> Bool { PairingLink.host(of: address).map(PinTrust.isPinned(host:)) ?? false }
        var servers = self.servers.filter { !isPinned($0) || offeredKeys.contains(key($0)) }
        for address in offered where !servers.contains(where: { key($0) == key(address) }) {
            // A pinned address is of use only with pins.
            if isPinned(address), pins.isEmpty { continue }
            servers.append(address)
        }
        var merged = self
        merged.servers = servers
        merged.pins = pins.pins.map(\.description)
        if let lastGood, !servers.contains(lastGood), !paths.contains(lastGood) { merged.lastGood = nil }
        return merged
    }
}

/// Every server a device paired with, by id (or, with none, by its first address).
public struct PairedServers: Codable, Hashable, Sendable {
    public var servers: [PairedServer]

    public init(_ servers: [PairedServer] = []) { self.servers = servers }

    /// A server paired again (a new code, new addresses) replaces its record; another is added.
    public mutating func pair(_ server: PairedServer) {
        if let index = servers.firstIndex(where: { Self.same($0, server) }) {
            servers[index] = server
        } else {
            servers.append(server)
        }
    }

    public mutating func forget(_ server: PairedServer) {
        servers.removeAll { Self.same($0, server) }
    }

    static func same(_ a: PairedServer, _ b: PairedServer) -> Bool {
        if let one = a.serverID, let other = b.serverID { return one == other }
        return a.serverID == nil && b.serverID == nil && a.servers.first == b.servers.first
    }
}
