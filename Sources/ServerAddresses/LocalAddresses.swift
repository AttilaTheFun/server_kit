import Foundation
@_exported import NetworkCore

/// Where this server is reached, from its own interfaces: its LAN addresses, its tailnet's, and its `.local` name.
public struct LocalAddresses: Sendable, Equatable {
    /// Private IPv4 addresses (10/8, 172.16/12, 192.168/16, 169.254/16), dotted, in the system's order.
    public var lan: [String]
    /// Tailnet addresses (100.64/10), dotted.
    public var tailnet: [String]
    /// The machine's `.local` name (`mac.local`), if it has a host name.
    public var bonjour: String?

    public init(lan: [String], tailnet: [String], bonjour: String?) {
        self.lan = lan
        self.tailnet = tailnet
        self.bonjour = bonjour
    }

    /// From `network`, leaving out the interfaces `excluding` names (a VM's bridge, a container network's: addresses a
    /// device elsewhere can't reach), and the host name `host`.
    public init(network: NetworkInterfaces, host: String?, excluding: (NetworkInterfaces.Interface) -> Bool = { _ in false }) {
        let kept = network.ipv4.filter { !excluding($0) }
        lan = kept.filter { IPv4.isPrivate($0.address) }.map { IPv4.format($0.address) }
        tailnet = kept.filter { IPv4.isTailnet($0.address) }.map { IPv4.format($0.address) }
        bonjour = host.flatMap(Self.bonjourName)
    }

    /// This machine's now, a bridge's addresses (`bridge*`, `vmnet*`, `docker*`, `virbr*`) left out.
    public static func current(reader: any NetworkReader = SystemNetwork(), host: String? = ProcessInfo.processInfo.hostName) -> LocalAddresses {
        LocalAddresses(network: reader.read(), host: host, excluding: isBridge)
    }

    /// Whether an interface is a bridge to machines on this one, not a network others reach it by.
    public static func isBridge(_ interface: NetworkInterfaces.Interface) -> Bool {
        guard let name = interface.name else { return false }
        return ["bridge", "vmnet", "docker", "virbr", "veth", "br-"].contains { name.hasPrefix($0) }
    }

    /// `mac` or `mac.local` as `mac.local`; nil for an address or an empty name.
    public static func bonjourName(_ host: String) -> String? {
        let name = host.hasSuffix(".") ? String(host.dropLast()) : host
        guard !name.isEmpty, IPv4.parse(name) == nil, !name.contains(":") else { return nil }
        if name.lowercased().hasSuffix(".local") { return name }
        // A host name with a domain of its own (`mac.example.com`): its first label is the `.local` name.
        let first = name.split(separator: ".").first.map(String.init) ?? name
        return first + ".local"
    }

    /// Each as `https://<address>:<port>`: the LAN's, then the `.local` name's (the tailnet's are a name's: its
    /// certificate is a CA's, by its `*.ts.net` name, which the server knows from its configuration).
    public func httpsURLs(port: Int) -> [String] {
        lan.map { "https://\($0):\(port)" } + [bonjour].compactMap { $0.map { "https://\($0):\(port)" } }
    }
}
