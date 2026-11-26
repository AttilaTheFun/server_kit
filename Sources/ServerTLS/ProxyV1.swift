#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(Android)
import Android
#endif

// How the TLS listener hands a connection to the app's own listener on loopback: first a line with a secret the
// listener makes at each start (any process on the machine could reach loopback; without the secret, its PROXY line
// is no one's word), then HAProxy's PROXY protocol, version 1, naming the client. The app's listener reads both
// (`parse`) before the request, so it knows the request came over TLS, and from whom.

public enum ProxyV1 {
    /// The secret's line: `SERVERKIT-TLS <secret>\r\n`.
    public static func preamble(_ secret: String) -> String { "SERVERKIT-TLS \(secret)\r\n" }

    /// The PROXY v1 line naming the client and where it connected.
    public static func line(client: String, clientPort: Int, server: String, serverPort: Int) -> String {
        let family = client.contains(":") ? "TCP6" : "TCP4"
        return "PROXY \(family) \(client) \(server) \(clientPort) \(serverPort)\r\n"
    }

    /// The PROXY v1 line's longest, by its spec.
    static let longest = 107
    static let publicPart = Array("SERVERKIT-TLS ".utf8)

    public struct Refused: Error, Equatable, CustomStringConvertible {
        public var description: String
    }

    /// The client named by `bytes`, which begin with the preamble (its secret `secret`) and a PROXY v1 line, and how
    /// many bytes those took; nil while they aren't all there; `.failure` for anything else: no preamble or another's
    /// secret (compared in constant time), a malformed line, an address that isn't one of its family, a port that
    /// isn't one, UNKNOWN (the listener never sends it).
    public static func parse(_ bytes: [UInt8], secret: String) -> Result<(client: String, length: Int), Refused>? {
        let expected = Array(preamble(secret).utf8)
        guard !bytes.isEmpty else { return nil }
        // Not all there yet: its public part checked so far, the secret only once it's whole.
        guard bytes.count >= expected.count else {
            let head = min(bytes.count, publicPart.count)
            return Array(bytes.prefix(head)) == Array(publicPart.prefix(head)) ? nil : .failure(Refused(description: "no preamble"))
        }
        let given = bytes[0..<expected.count]
        guard zip(given, expected).reduce(UInt8(0), { $0 | ($1.0 ^ $1.1) }) == 0 else {
            return .failure(Refused(description: "no preamble, or another's secret"))
        }
        let rest = bytes[expected.count...]
        guard let crlf = Self.crlf(in: rest) else {
            return rest.count >= longest ? .failure(Refused(description: "a PROXY line too long")) : nil
        }
        guard crlf - rest.startIndex + 2 <= longest else { return .failure(Refused(description: "a PROXY line too long")) }
        let words = String(decoding: bytes[rest.startIndex..<crlf], as: UTF8.self).split(separator: " ", omittingEmptySubsequences: false)
        guard words.count == 6, words[0] == "PROXY", words[1] == "TCP4" || words[1] == "TCP6",
              valid(String(words[2]), v6: words[1] == "TCP6"), valid(String(words[3]), v6: words[1] == "TCP6"),
              words[4].allSatisfy({ $0.isASCII && $0.isNumber }), words[5].allSatisfy({ $0.isASCII && $0.isNumber }),
              let clientPort = Int(words[4]), let serverPort = Int(words[5]),
              (0...65535).contains(clientPort), (0...65535).contains(serverPort) else {
            return .failure(Refused(description: "a bad PROXY line"))
        }
        return .success((String(words[2]), crlf + 2))
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
}
