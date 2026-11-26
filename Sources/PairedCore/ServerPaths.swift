import NetworkCore
import PairingLink

// Reaching a paired server by every way it has, nearest first: its addresses ranked by how they fit where the device
// is now (ServerPaths), its routes (TLS, loopback HTTP, SSH) put in the order to try (`PairedServer.routes`), tried a
// moment apart with the first to answer taken (PathRace), and ranked again when the device's networks change.

public enum ServerPaths {
    /// How an address fits where the device is now, best first.
    public enum Fit: Int, Comparable, Sendable, CaseIterable {
        /// This device's own loopback: a server on the same machine.
        case loopback
        /// An address on one of the device's networks (the LAN at home).
        case local
        /// The tailnet (its 100.64/10 addresses, its `*.ts.net` names), while the device is on it.
        case overlay
        /// A `.local` name (or another a home network gives), while the device is on a private network: after the
        /// tailnet, as it may be another network (a café's) whose names don't answer until mDNS gives up.
        case bonjour
        /// Anything else: a public name, a public address, an IPv6 address.
        case other
        /// A tailnet address off the tailnet, a private address on no network of the device's.
        case unlikely

        public static func < (a: Fit, b: Fit) -> Bool { a.rawValue < b.rawValue }
    }

    /// How an app ranks what the kit can't know for it.
    public struct Ranking: Sendable, Equatable {
        /// Where a home network's name (`.local`, `.lan`, `.home.arpa`, `.home`, a bare host) goes while the device
        /// is on a private network: `.bonjour` by default, `.other` to rank it with public names.
        public var homeNames: Fit

        public init(homeNames: Fit = .bonjour) { self.homeNames = homeNames }
    }

    /// How `address` (a URL's text, or a bare host) fits.
    public static func fit(of address: String, network: NetworkInterfaces, ranking: Ranking = Ranking()) -> Fit {
        guard let raw = PairingHost.host(of: address) else { return .unlikely }
        var host = raw.lowercased()
        if host.hasPrefix("["), host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
        if host.hasSuffix(".") { host = String(host.dropLast()) }
        if host == "localhost" || host == "::1" { return .loopback }
        if let value = IPv4.parse(host) {
            if IPv4.isLoopback(value) { return .loopback }
            // The tailnet's addresses are the tailnet's, whatever mask its interface has.
            if IPv4.isTailnet(value) { return network.hasTailnet ? .overlay : .unlikely }
            if network.isOnLocalNetwork(host) { return .local }
            return IPv4.isPrivate(value) ? .unlikely : .other
        }
        if host.contains(":") { return .other }
        if host.hasSuffix(".ts.net") { return network.hasTailnet ? .overlay : .unlikely }
        if host.hasSuffix(".local") || host.hasSuffix(".lan") || host.hasSuffix(".home.arpa") || host.hasSuffix(".home")
            || !host.contains(".") {
            return network.hasLAN ? ranking.homeNames : .unlikely
        }
        return .other
    }

    /// `addresses` best first: by fit, the one that answered last (`lastGood`) first among its equals, the rest in
    /// their order; each once.
    public static func ranked(_ addresses: [String], network: NetworkInterfaces, lastGood: String? = nil,
                              ranking: Ranking = Ranking()) -> [String] {
        var unique: [String] = []
        for address in addresses where !unique.contains(address) { unique.append(address) }
        return unique.enumerated().sorted { a, b in
            let fa = fit(of: a.element, network: network, ranking: ranking), fb = fit(of: b.element, network: network, ranking: ranking)
            if fa != fb { return fa < fb }
            let la = a.element == lastGood, lb = b.element == lastGood
            if la != lb { return la }
            return a.offset < b.offset
        }.map(\.element)
    }
}

/// One way to a server: an address and how it's taken, and how long it has in a race.
public struct ServerRoute: Hashable, Sendable {
    public enum Kind: Hashable, Sendable {
        /// `https://…`: the server's TLS, its certificate a CA's or pinned.
        case https
        /// `http://` on this device's own loopback.
        case loopbackHTTP
        /// SSH (`ssh://…`, or a bare `[user@]host[:port]`): the app takes it (a tunnel, a command), not the kit.
        case ssh
    }

    public var address: String
    public var kind: Kind
    public var fit: ServerPaths.Fit
    /// How long it goes alone before the next starts beside it.
    public var headStart: Duration
    /// How long it has to answer before it's given up.
    public var timeout: Duration
}

/// How an app takes a server's routes: whether it can take SSH and would rather, and the timings.
public struct RoutePolicy: Sendable, Equatable {
    /// The device can take SSH routes (a browser can't).
    public var canSSH: Bool
    /// Where the server has SSH routes and the device can take them, SSH is the way in: its routes that fit (the
    /// LAN's, the tailnet's) before any other of theirs, the rest only when SSH doesn't answer.
    public var preferSSH: Bool
    public var ranking: ServerPaths.Ranking
    public var headStart: Duration
    /// SSH's handshake takes longer.
    public var sshHeadStart: Duration
    public var timeout: Duration
    /// A route on this device or its network has less.
    public var localTimeout: Duration

    public init(canSSH: Bool = false, preferSSH: Bool = true, ranking: ServerPaths.Ranking = ServerPaths.Ranking(),
                headStart: Duration = .milliseconds(400), sshHeadStart: Duration = .milliseconds(1000),
                timeout: Duration = .seconds(5), localTimeout: Duration = .seconds(2)) {
        self.canSSH = canSSH
        self.preferSSH = preferSSH
        self.ranking = ranking
        self.headStart = headStart
        self.sshHeadStart = sshHeadStart
        self.timeout = timeout
        self.localTimeout = localTimeout
    }
}

extension PairedServer {
    /// Its routes in the order to try for where the device is now, each with its timings: the ones a credential may
    /// take (`credentialAddresses`) and, where the device can, its SSH paths. By fit, then, preferring SSH, SSH before
    /// the rest of its fit for the device's own networks and the tailnet (loopback always first, SSH or not), and the
    /// one that answered last first among its equals.
    public func routes(network: NetworkInterfaces, policy: RoutePolicy = RoutePolicy()) -> [ServerRoute] {
        var all: [ServerRoute] = []
        func add(_ address: String, _ kind: ServerRoute.Kind) {
            guard !all.contains(where: { $0.address == address }) else { return }
            let fit = ServerPaths.fit(of: address, network: network, ranking: policy.ranking)
            let near = fit == .loopback || fit == .local
            all.append(ServerRoute(address: address, kind: kind, fit: fit,
                                   headStart: kind == .ssh ? policy.sshHeadStart : policy.headStart,
                                   timeout: near ? policy.localTimeout : policy.timeout))
        }
        for address in credentialAddresses { add(address, Self.isLoopbackHTTP(address) ? .loopbackHTTP : .https) }
        if policy.canSSH { for path in sshPaths { add(path, .ssh) } }
        let preferSSH = policy.canSSH && policy.preferSSH && all.contains { $0.kind == .ssh }
        func tier(_ route: ServerRoute) -> Int {
            guard preferSSH else { return route.fit.rawValue }
            let ssh = route.kind == .ssh
            switch route.fit {
            case .loopback: return 0
            // SSH on the device's networks and the tailnet first, then the rest of those.
            case .local: return ssh ? 1 : 3
            case .overlay: return ssh ? 2 : 4
            // Further out, each fit's SSH before its others.
            case .bonjour: return ssh ? 5 : 6
            case .other: return ssh ? 7 : 8
            case .unlikely: return ssh ? 9 : 10
            }
        }
        return all.enumerated().sorted { a, b in
            let ta = tier(a.element), tb = tier(b.element)
            if ta != tb { return ta < tb }
            let la = a.element.address == lastGood, lb = b.element.address == lastGood
            if la != lb { return la }
            return a.offset < b.offset
        }.map(\.element)
    }
}

/// A host read out of an address: a URL's (`https://host:port/…`) or a bare one's (`user@host:22`).
enum PairingHost {
    static func host(of address: String) -> String? {
        PairingLink.host(of: address) ?? PairingLink.pathHost(of: address)
    }
}
