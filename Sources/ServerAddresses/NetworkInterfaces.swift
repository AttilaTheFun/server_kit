#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif
import Foundation

// Where this machine is reached, read from its own interfaces (getifaddrs): no CLI (a sandboxed app runs none), no
// network asked. A server lists them in its pairing link and in what it says of itself; a client ranks a server's
// addresses by them.

/// The machine's IPv4 networks now: each interface's address and mask, loopback left out.
public struct NetworkInterfaces: Sendable, Equatable {
    public struct Interface: Sendable, Equatable {
        public var address: UInt32
        public var mask: UInt32
        /// Its name (`en0`, `utun3`, `bridge100`), where it was read from the system.
        public var name: String?

        public init(address: UInt32, mask: UInt32, name: String? = nil) {
            self.address = address
            self.mask = mask
            self.name = name
        }
    }

    public var ipv4: [Interface]

    public init(_ ipv4: [Interface]) { self.ipv4 = ipv4 }

    /// From dotted addresses and masks (tests, and a network another layer read: Android's, a browser's).
    public init(_ pairs: [(String, String)]) {
        ipv4 = pairs.compactMap { pair in
            guard let address = IPv4Text.parse(pair.0), let mask = IPv4Text.parse(pair.1) else { return nil }
            return Interface(address: address, mask: mask)
        }
    }

    /// Whether `host`, an IPv4 address, is on one of these networks.
    public func isOnLocalNetwork(_ host: String) -> Bool {
        guard let target = IPv4Text.parse(host) else { return false }
        return ipv4.contains { $0.mask != 0 && ($0.address & $0.mask) == (target & $0.mask) }
    }

    /// Whether the machine is on a tailnet (has a 100.64.0.0/10 address): Tailscale is up.
    public var hasTailnet: Bool { ipv4.contains { IPv4Text.isTailnet($0.address) } }

    /// Whether the machine is on a private network, where a `.local` name may answer.
    public var hasLAN: Bool { ipv4.contains { IPv4Text.isPrivate($0.address) } }

    /// The machine's, now.
    public static func current() -> NetworkInterfaces { SystemNetwork().read() }
}

/// Where a machine's networks come from: the system's interfaces by default; another layer's where Swift can't read
/// them itself (Android, a browser), or a test's.
public protocol NetworkReader: Sendable {
    func read() -> NetworkInterfaces
}

/// The system's own interfaces (getifaddrs), IPv4 alone, loopback left out.
public struct SystemNetwork: NetworkReader {
    public init() {}

    public func read() -> NetworkInterfaces {
        #if os(Windows) || os(WASI)
        return NetworkInterfaces([NetworkInterfaces.Interface]())
        #else
        var result: [NetworkInterfaces.Interface] = []
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return NetworkInterfaces(result) }
        defer { freeifaddrs(list) }
        for pointer in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let entry = pointer.pointee
            guard let address = entry.ifa_addr, address.pointee.sa_family == sa_family_t(AF_INET), let netmask = entry.ifa_netmask else { continue }
            let value = address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
            let mask = netmask.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
            if IPv4Text.isLoopback(value) { continue }
            result.append(.init(address: value, mask: mask, name: entry.ifa_name.map { String(cString: $0) }))
        }
        return NetworkInterfaces(result)
        #endif
    }
}

/// IPv4 as numbers (ServerAddresses' own: it depends on nothing of the kit's, as PairingLink's IPv4 doesn't on it).
public enum IPv4Text {
    public static func parse<S: StringProtocol>(_ text: S) -> UInt32? {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var value: UInt32 = 0
        for part in parts {
            guard !part.isEmpty, part.count <= 3, part.allSatisfy({ $0.isASCII && $0.isNumber }), let octet = UInt32(part), octet < 256 else { return nil }
            value = value << 8 | octet
        }
        return value
    }

    public static func format(_ value: UInt32) -> String {
        "\(value >> 24).\(value >> 16 & 0xFF).\(value >> 8 & 0xFF).\(value & 0xFF)"
    }

    public static func isTailnet(_ value: UInt32) -> Bool { value & 0xFFC0_0000 == 0x6440_0000 }

    public static func isPrivate(_ value: UInt32) -> Bool {
        value >> 24 == 10 || value & 0xFFF0_0000 == 0xAC10_0000 || value & 0xFFFF_0000 == 0xC0A8_0000 || value & 0xFFFF_0000 == 0xA9FE_0000
    }

    public static func isLoopback(_ value: UInt32) -> Bool { value >> 24 == 127 }
}
