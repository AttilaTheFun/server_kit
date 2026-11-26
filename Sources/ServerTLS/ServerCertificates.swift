// What a server's TLS answers with: a certificate a CA vouches for, for its names that have one (a tailnet's
// `<host>.<tailnet>.ts.net`, a public domain), and its own (ServerIdentity), pinned by its devices, for every other
// name it's reached by (an IP address, which a client sends no SNI for; a `.local` name; a bare host name). Chosen by
// the name a TLS hello asks for (SNI).

/// A certificate chain and its key, PEM.
public struct PEMPair: Sendable, Equatable {
    public var chain: String
    public var key: String

    public init(chain: String, key: String) {
        self.chain = chain
        self.key = key
    }
}

/// The pairs a server answers with, and which a hello gets.
public struct ServerCertificates: Sendable, Equatable {
    /// The names a CA's pair is for, exactly (`mac.example.ts.net`).
    public var caNames: Set<String>
    /// The suffixes a CA's pair is for too (`.ts.net`: a tailnet's certificate answers for any of its names).
    public var caSuffixes: [String]
    /// The CA's pair, if there is one now.
    public var ca: PEMPair?
    /// The server's own pair (ServerIdentity's), if it serves one.
    public var own: PEMPair?

    public init(caNames: Set<String> = [], caSuffixes: [String] = [], ca: PEMPair?, own: PEMPair?) {
        self.caNames = Set(caNames.map(Self.normalized))
        self.caSuffixes = caSuffixes.map { $0.lowercased() }
        self.ca = ca
        self.own = own
    }

    public enum Choice: Sendable, Equatable { case ca, own }

    /// Which pair a hello naming `serverName` is answered with: the CA's for one of its names (or under one of its
    /// suffixes), the server's own for anything else, no name included.
    public func choice(for serverName: String?) -> Choice {
        guard let name = serverName.map(Self.normalized), !name.isEmpty else { return .own }
        if caNames.contains(name) || caSuffixes.contains(where: { name.hasSuffix($0) }) { return .ca }
        return .own
    }

    /// The pair for a hello naming `serverName`: its choice's, else the other where it's missing.
    public func pair(for serverName: String?) -> PEMPair? {
        switch choice(for: serverName) {
        case .ca: return ca ?? own
        case .own: return own ?? ca
        }
    }

    static func normalized(_ name: String) -> String {
        var lower = name.lowercased()
        while lower.hasSuffix(".") { lower.removeLast() }
        return lower
    }
}
