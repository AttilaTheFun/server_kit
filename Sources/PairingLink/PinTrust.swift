import NetworkCore

// Which certificate a client trusts at an address. A server is reached by names a CA can vouch for (a tailnet's
// `*.ts.net`, a public domain) and by names none can: an IP address, a `.local` name, a bare host name (`studio`), a
// home network's (`.lan`, `.home.arpa`, `.internal`). The latter present the server's own self-signed certificate,
// trusted by its pins alone; the former keep the system's trust.

public enum PinTrust {
    public enum Decision: Equatable, Sendable {
        /// The system's own evaluation: a certificate a CA vouches for.
        case system
        /// A pinned certificate that matches: trusted.
        case accept
        /// Not matched, or no pin to match: refused.
        case refuse
    }

    /// The suffixes of names no CA vouches for: mDNS's and the home networks' (RFC 8375, ICANN's `.internal`).
    public static let privateSuffixes = [".local", ".lan", ".home.arpa", ".internal"]

    /// Whether `host` presents the server's own certificate: an IP address (v4 or v6), a single-label name, or a name
    /// under one of `privateSuffixes`.
    public static func isPinned(host: String) -> Bool {
        var bare = host.lowercased()
        if bare.hasPrefix("["), bare.hasSuffix("]") { bare = String(bare.dropFirst().dropLast()) }
        if bare.hasSuffix(".") { bare = String(bare.dropLast()) }
        if bare.isEmpty { return false }
        if IPv4.parse(bare) != nil || bare.contains(":") { return true }
        if !bare.contains(".") { return true }
        return privateSuffixes.contains { bare.hasSuffix($0) }
    }

    /// What a client does with the certificate it's shown at `host`: the system's to judge, or trusted only if `pins`
    /// match it (its SHA-256s: of its SubjectPublicKeyInfo and of the whole certificate). `isPinned` says which hosts
    /// present the server's own certificate (by default `isPinned(host:)`; an app with names of its own passes its).
    public static func decide(host: String, pins: PinSet, spki: String?, certificate: String?,
                              isPinned: (String) -> Bool = PinTrust.isPinned(host:)) -> Decision {
        guard isPinned(host) else { return .system }
        guard !pins.isEmpty else { return .refuse }
        return pins.matches(spki: spki, certificate: certificate) ? .accept : .refuse
    }
}
