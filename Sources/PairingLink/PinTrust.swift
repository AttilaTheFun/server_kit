// Which certificate a client trusts at an address. A server is reached by names a CA can vouch for (a tailnet's
// `*.ts.net`, a public domain) and by names none can (an IP address, a `.local` name): the latter present the server's
// own self-signed certificate, trusted by its pins alone; the former keep the system's trust.

public enum PinTrust {
    public enum Decision: Equatable, Sendable {
        /// The system's own evaluation: a certificate a CA vouches for.
        case system
        /// A pinned certificate that matches: trusted.
        case accept
        /// Not matched, or no pin to match: refused.
        case refuse
    }

    /// Whether `host` presents the server's own certificate: an IP address (v4 or v6) or a `.local` name.
    public static func isPinned(host: String) -> Bool {
        var bare = host.lowercased()
        if bare.hasPrefix("["), bare.hasSuffix("]") { bare = String(bare.dropFirst().dropLast()) }
        if bare.hasSuffix(".") { bare = String(bare.dropLast()) }
        return bare.hasSuffix(".local") || IPv4.parse(bare) != nil || bare.contains(":")
    }

    /// What a client does with the certificate it's shown at `host`: the system's to judge, or trusted only if `pins`
    /// match it (its SHA-256s: of its SubjectPublicKeyInfo and of the whole certificate).
    public static func decide(host: String, pins: PinSet, spki: String?, certificate: String?) -> Decision {
        guard isPinned(host: host) else { return .system }
        guard !pins.isEmpty else { return .refuse }
        return pins.matches(spki: spki, certificate: certificate) ? .accept : .refuse
    }
}

/// IPv4 addresses as numbers, with no Foundation: the link, the pins and the ranking run in WebAssembly too.
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

    /// Whether it's a tailnet's (Tailscale's 100.64.0.0/10).
    public static func isTailnet(_ value: UInt32) -> Bool { value & 0xFFC0_0000 == 0x6440_0000 }

    /// Whether it's private (10/8, 172.16/12, 192.168/16) or link-local (169.254/16): a LAN's.
    public static func isPrivate(_ value: UInt32) -> Bool {
        value >> 24 == 10 || value & 0xFFF0_0000 == 0xAC10_0000 || value & 0xFFFF_0000 == 0xC0A8_0000 || value & 0xFFFF_0000 == 0xA9FE_0000
    }

    /// Whether it's loopback (127/8).
    public static func isLoopback(_ value: UInt32) -> Bool { value >> 24 == 127 }
}
