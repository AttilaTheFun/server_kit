#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(Android)
import Android
#endif

// A machine's networks, read from its own interfaces (getifaddrs): no CLI (a sandboxed app runs none), no network
// asked, and no Foundation, so a client in WebAssembly links it too (with a reader of its host's). A server lists its
// addresses from them; a client ranks a server's addresses by them.

/// The machine's IPv4 networks now: each interface's address and mask, loopback left out.
public struct NetworkInterfaces: Sendable, Equatable {
    public struct Interface: Sendable, Equatable {
        public var address: UInt32
        public var mask: UInt32
        /// Its name (`en0`, `utun3`, `bridge100`), where the system said it.
        public var name: String?

        public init(address: UInt32, mask: UInt32, name: String? = nil) {
            self.address = address
            self.mask = mask
            self.name = name
        }
    }

    public var ipv4: [Interface]

    public init(_ ipv4: [Interface]) { self.ipv4 = ipv4 }

    /// From dotted addresses and masks (a test's, or a network another layer read: Android's, a browser's).
    public init(_ pairs: [(String, String)]) {
        ipv4 = pairs.compactMap { pair in
            guard let address = IPv4.parse(pair.0), let mask = IPv4.parse(pair.1) else { return nil }
            return Interface(address: address, mask: mask)
        }
    }

    /// From `address/mask` lines (`192.168.1.5/255.255.255.0`), as a bridge from another language hands them over.
    public init(lines: [String]) {
        self.init(lines.compactMap { line -> (String, String)? in
            let parts = line.split(separator: "/", maxSplits: 1)
            return parts.count == 2 ? (String(parts[0]), String(parts[1])) : nil
        })
    }

    /// Whether `host`, an IPv4 address, is on one of these networks.
    public func isOnLocalNetwork(_ host: String) -> Bool {
        guard let target = IPv4.parse(host) else { return false }
        return ipv4.contains { $0.mask != 0 && ($0.address & $0.mask) == (target & $0.mask) }
    }

    /// Whether the machine is on a tailnet (has a 100.64.0.0/10 address): Tailscale is up.
    public var hasTailnet: Bool { ipv4.contains { IPv4.isTailnet($0.address) } }

    /// Whether the machine is on a private network, where a `.local` name may answer.
    public var hasLAN: Bool { ipv4.contains { IPv4.isPrivate($0.address) } }
}

/// Where a machine's networks come from: the system's interfaces (SystemNetwork), or another layer's where Swift can't
/// read them itself (Android, a browser), or a test's.
public protocol NetworkReader: Sendable {
    func read() -> NetworkInterfaces
}

/// The system's own interfaces (getifaddrs), IPv4 alone, loopback left out; none where there's no getifaddrs.
public struct SystemNetwork: NetworkReader {
    public init() {}

    public func read() -> NetworkInterfaces {
        #if canImport(Darwin) || canImport(Glibc) || canImport(Musl) || canImport(Android)
        var result: [NetworkInterfaces.Interface] = []
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return NetworkInterfaces(result) }
        defer { freeifaddrs(list) }
        for pointer in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let entry = pointer.pointee
            guard let address = entry.ifa_addr, address.pointee.sa_family == sa_family_t(AF_INET), let netmask = entry.ifa_netmask else { continue }
            let value = address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
            let mask = netmask.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
            if IPv4.isLoopback(value) { continue }
            let name: String? = entry.ifa_name.map { String(cString: $0) }
            result.append(.init(address: value, mask: mask, name: name))
        }
        return NetworkInterfaces(result)
        #else
        return NetworkInterfaces([NetworkInterfaces.Interface]())
        #endif
    }
}

/// IPv4 addresses as numbers.
public enum IPv4 {
    /// `a.b.c.d` as a number; nil for anything else.
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

    /// A number as `a.b.c.d`.
    public static func format(_ value: UInt32) -> String {
        "\(value >> 24).\(value >> 16 & 0xFF).\(value >> 8 & 0xFF).\(value & 0xFF)"
    }

    /// A tailnet's (Tailscale's 100.64.0.0/10).
    public static func isTailnet(_ value: UInt32) -> Bool { value & 0xFFC0_0000 == 0x6440_0000 }

    /// Private (10/8, 172.16/12, 192.168/16) or link-local (169.254/16): a LAN's.
    public static func isPrivate(_ value: UInt32) -> Bool {
        value >> 24 == 10 || value & 0xFFF0_0000 == 0xAC10_0000 || value & 0xFFFF_0000 == 0xC0A8_0000 || value & 0xFFFF_0000 == 0xA9FE_0000
    }

    /// Loopback (127/8).
    public static func isLoopback(_ value: UInt32) -> Bool { value >> 24 == 127 }
}

/// IPv6 addresses as their 16 bytes.
public enum IPv6 {
    /// `fe80::1`, `[2001:db8::1]`, `::ffff:192.0.2.1` (a zone, `%en0`, ignored) as 16 bytes; nil for anything else.
    public static func parse<S: StringProtocol>(_ text: S) -> [UInt8]? {
        var body = Substring(text)
        if body.hasPrefix("["), body.hasSuffix("]") { body = body.dropFirst().dropLast() }
        if let zone = body.firstIndex(of: "%") { body = body[..<zone] }
        guard body.contains(":") else { return nil }
        // An IPv4 tail (`::ffff:192.0.2.1`): its four bytes as the last two groups.
        var tail: [UInt8] = []
        if let lastColon = body.lastIndex(of: ":"), body[body.index(after: lastColon)...].contains("."), let v4 = IPv4.parse(body[body.index(after: lastColon)...]) {
            tail = [UInt8(v4 >> 24), UInt8(v4 >> 16 & 0xFF), UInt8(v4 >> 8 & 0xFF), UInt8(v4 & 0xFF)]
            body = body[...lastColon]
            if body.hasSuffix(":"), !body.hasSuffix("::") { body = body.dropLast() }
        }
        let halves = splitAtDoubleColon(body)
        guard halves.count <= 2 else { return nil }
        func groups(_ part: Substring) -> [UInt16]? {
            if part.isEmpty { return [] }
            var out: [UInt16] = []
            for group in part.split(separator: ":", omittingEmptySubsequences: false) {
                guard !group.isEmpty, group.count <= 4, let value = UInt16(group, radix: 16) else { return nil }
                out.append(value)
            }
            return out
        }
        guard let head = groups(halves[0]) else { return nil }
        let tailGroups = tail.count / 2
        var all: [UInt16]
        if halves.count == 2 {
            guard let rest = groups(halves[1]) else { return nil }
            let missing = 8 - tailGroups - head.count - rest.count
            guard missing >= 1 else { return nil }
            all = head + Array(repeating: 0, count: missing) + rest
        } else {
            all = head
            guard all.count + tailGroups == 8 else { return nil }
        }
        var bytes: [UInt8] = []
        for group in all { bytes += [UInt8(group >> 8), UInt8(group & 0xFF)] }
        return bytes + tail
    }

    /// Whether `text` is a tailnet's IPv6 address (Tailscale's `fd7a:115c:a1e0::/48`). A tailnet's nodes all share one
    /// /96 of it, each its own address, assigned by the tailnet and not the node's to change: so a tailnet client is
    /// one address, never its /64 (which would put every node of the tailnet in one place).
    public static func isTailnet<S: StringProtocol>(_ text: S) -> Bool {
        guard let bytes = parse(text) else { return false }
        return bytes[0] == 0xFD && bytes[1] == 0x7A && bytes[2] == 0x11 && bytes[3] == 0x5C && bytes[4] == 0xA1 && bytes[5] == 0xE0
    }

    /// Where a client's IPv6 address counts from, for a throttle or a cap: its /64 (one host's many addresses), but
    /// a tailnet's address alone (`isTailnet`); as lowercase hex, the /64 ending `/64`. Nil for what isn't IPv6.
    public static func clientKey<S: StringProtocol>(_ text: S) -> String? {
        guard let bytes = parse(text) else { return nil }
        let digits = Array("0123456789abcdef")
        let hex = { (part: ArraySlice<UInt8>) in part.map { String(digits[Int($0 >> 4)]) + String(digits[Int($0 & 0xF)]) }.joined() }
        return isTailnet(text) ? hex(bytes[...]) : hex(bytes.prefix(8)) + "/64"
    }

    /// Its first 64 bits, as lowercase hex: the network a host is on (`/64`), what one host's many addresses share.
    public static func prefix64<S: StringProtocol>(_ text: S) -> String? {
        guard let bytes = parse(text) else { return nil }
        let digits = Array("0123456789abcdef")
        return bytes.prefix(8).map { String(digits[Int($0 >> 4)]) + String(digits[Int($0 & 0xF)]) }.joined()
    }
}

/// An address split at its `::`, if it has one: the parts before and after. Two `::`s make three parts (refused).
private func splitAtDoubleColon(_ text: Substring) -> [Substring] {
    guard let range = text.firstRange(of: "::") else { return [text] }
    let after = text[range.upperBound...]
    if after.firstRange(of: "::") != nil { return [text, after, after] }
    return [text[..<range.lowerBound], after]
}
