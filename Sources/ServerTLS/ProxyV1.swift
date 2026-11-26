#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(Android)
import Android
#endif

// How the TLS front hands a connection to the app's own listener on loopback: first a line with a secret the front is
// given at its start (any process on the machine could reach loopback; without the secret, its PROXY line is no one's
// word), then HAProxy's PROXY protocol, version 1, naming the client. The app's listener reads both before the request
// (`ProxyV1.Reader` for any listener, `ProxyV1Handler` for a SwiftNIO one), so it knows the request came over TLS, and
// from whom.

public enum ProxyV1 {
    /// The secret's line: `SERVERKIT-TLS <secret>\r\n`.
    public static func preamble(_ secret: String) -> String { "SERVERKIT-TLS \(secret)\r\n" }

    /// Whether `secret` may be one: at least 16 characters, printable ASCII without spaces.
    public static func isValidSecret(_ secret: String) -> Bool {
        secret.utf8.count >= 16 && secret.utf8.allSatisfy { $0 > 0x20 && $0 < 0x7F }
    }

    /// The PROXY v1 line naming the client and where it connected.
    public static func line(client: String, clientPort: Int, server: String, serverPort: Int) -> String {
        let family = client.contains(":") ? "TCP6" : "TCP4"
        return "PROXY \(family) \(client) \(server) \(clientPort) \(serverPort)\r\n"
    }

    /// The PROXY v1 line's longest, by its spec.
    static let longest = 107
    static let publicPart = Array("SERVERKIT-TLS ".utf8)

    /// What the front said of a connection.
    public struct Header: Sendable, Equatable {
        /// The client's address (IPv4-mapped IPv6 as IPv4) and port.
        public var client: String
        public var clientPort: Int
        /// Where it connected.
        public var server: String
        public var serverPort: Int
        /// The bytes the preamble and the line took; the request's begin after them.
        public var length: Int
    }

    public struct Refused: Error, Equatable, CustomStringConvertible {
        public var description: String
    }

    /// The header `bytes` begin with (the preamble with `secret`, then a PROXY v1 line); nil while they aren't all
    /// there; `.failure` for anything else: no preamble or another's secret (compared in constant time), a malformed
    /// line, an address that isn't one of its family, a port that isn't one, UNKNOWN (the front never sends it).
    public static func parse(_ bytes: [UInt8], secret: String) -> Result<Header, Refused>? {
        parse(bytes[...], secret: secret)
    }

    public static func parse(_ bytes: ArraySlice<UInt8>, secret: String) -> Result<Header, Refused>? {
        let expected = Array(preamble(secret).utf8)
        guard !bytes.isEmpty else { return nil }
        // Not all there yet: its public part checked so far, the secret only once it's whole.
        guard bytes.count >= expected.count else {
            let head = min(bytes.count, publicPart.count)
            return Array(bytes.prefix(head)) == Array(publicPart.prefix(head)) ? nil : .failure(Refused(description: "no preamble"))
        }
        let given = bytes.prefix(expected.count)
        guard zip(given, expected).reduce(UInt8(0), { $0 | ($1.0 ^ $1.1) }) == 0 else {
            return .failure(Refused(description: "no preamble, or another's secret"))
        }
        let rest = bytes.dropFirst(expected.count)
        guard let crlf = Self.crlf(in: rest.prefix(longest)) else {
            return rest.count >= longest ? .failure(Refused(description: "a PROXY line too long")) : nil
        }
        let words = String(decoding: rest[rest.startIndex..<crlf], as: UTF8.self).split(separator: " ", omittingEmptySubsequences: false)
        guard words.count == 6, words[0] == "PROXY", words[1] == "TCP4" || words[1] == "TCP6",
              valid(String(words[2]), v6: words[1] == "TCP6"), valid(String(words[3]), v6: words[1] == "TCP6"),
              let clientPort = port(words[4]), let serverPort = port(words[5]) else {
            return .failure(Refused(description: "a bad PROXY line"))
        }
        return .success(Header(client: String(words[2]), clientPort: clientPort, server: String(words[3]), serverPort: serverPort,
                               length: crlf + 2 - bytes.startIndex))
    }

    /// A port as the line writes it: 0–65535 in decimal digits, no sign, no leading zero.
    static func port(_ word: Substring) -> Int? {
        guard !word.isEmpty, word.count <= 5, word.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
              word == "0" || !word.hasPrefix("0"), let value = Int(word), value <= 65535 else { return nil }
        return value
    }

    static func crlf(in bytes: ArraySlice<UInt8>) -> Int? {
        var index = bytes.startIndex
        while index + 1 < bytes.endIndex {
            if bytes[index] == 13 && bytes[index + 1] == 10 { return index }
            index += 1
        }
        return nil
    }

    /// Whether `address` is an IP address of its family (inet_pton's word).
    static func valid(_ address: String, v6: Bool) -> Bool {
        var storage = [UInt8](repeating: 0, count: 16)
        return address.withCString { inet_pton(v6 ? AF_INET6 : AF_INET, $0, &storage) } == 1
    }

    /// A connection's first bytes, fed as they come, until its header is read: for a listener of any kind (Network,
    /// sockets). The listener checks itself that the connection came from loopback, and closes one that says nothing
    /// for a few seconds.
    public struct Reader: Sendable {
        public let secret: String
        private var bytes: [UInt8] = []

        public init(secret: String) { self.secret = secret }

        public enum Step: Sendable, Equatable {
            /// More bytes needed.
            case more
            /// The header, and the bytes after it (the request's first).
            case done(Header, rest: [UInt8])
            /// Not the front's: close the connection.
            case refused(Refused)
        }

        /// The most a header takes: more than this unread and it's refused.
        public var limit: Int { preamble(secret).utf8.count + longest }

        public mutating func feed(_ more: some Sequence<UInt8>) -> Step {
            bytes.append(contentsOf: more)
            switch parse(bytes, secret: secret) {
            case nil:
                return bytes.count >= limit ? .refused(Refused(description: "no header in \(limit) bytes")) : .more
            case .failure(let refused)?:
                return .refused(refused)
            case .success(let header)?:
                let rest = Array(bytes[header.length...])
                bytes = []
                return .done(header, rest: rest)
            }
        }
    }
}
