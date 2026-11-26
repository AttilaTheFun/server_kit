// The link a server shows as a QR (or a person copies and pastes) for a device to pair with it:
//
//     <scheme>://pair?v=1&server=<https URL>&code=<one-time code>&address=<https URL>…&pin=<pin>…&id=<server id>&name=<name>
//
// - `server`: the address a device pairs at first (one a CA vouches for, like a tailnet's `*.ts.net` name, where one
//   exists); `address`: every other one (each LAN address, its `.local` name), repeated.
// - `pin`: the server's own certificate's pins (Pin), repeated: its current and, while it rotates, its next. An address
//   that presents the server's own certificate (PinTrust.isPinned) is kept only with a pin, so a link can't send a
//   device to a certificate it has no way to check.
// - `code`: good once, for minutes (ServerPairing's offers); `id` and `name`: the server's, so a device knows a server
//   it has paired with already, and what to call it.
//
// Written and read with no Foundation, so it runs wherever Swift does, WebAssembly included. Links in a format of an
// app's own from before this (`PairingLinkFormat`) are read through the same entry point, so a client reads both.

public struct PairingLink: Hashable, Sendable {
    /// The format's version: what `v=` says. A link with no `v` is a version 1 link (the first that servers wrote).
    public static let currentVersion = 1

    public var scheme: String
    public var code: String
    /// The address to pair at first, then every other, each `https://…` and each once.
    public var servers: [String]
    public var pins: PinSet
    /// The server's own stable id, if it says one.
    public var serverID: String?
    /// What the server is called, for a person.
    public var name: String?
    public var version: Int

    public init(scheme: String, code: String, servers: [String], pins: PinSet = PinSet([]), serverID: String? = nil,
                name: String? = nil, version: Int = PairingLink.currentVersion) {
        self.scheme = scheme
        self.code = code
        self.servers = Self.unique(servers)
        self.pins = pins
        self.serverID = serverID
        self.name = name
        self.version = version
    }

    /// The address to pair at first.
    public var server: String? { servers.first }

    /// The link, as a QR shows it.
    public var text: String {
        var items: [(String, String)] = [("v", String(version))]
        if let first = servers.first { items.append(("server", first)) }
        items.append(("code", code))
        // The others and the pins together: a pinned address is no use without them.
        if !pins.isEmpty {
            items += servers.dropFirst().map { ("address", $0) }
            items += pins.pins.map { ("pin", $0.description) }
        } else {
            items += servers.dropFirst().filter { !PinTrust.isPinned(host: Self.host(of: $0) ?? "") }.map { ("address", $0) }
        }
        if let serverID { items.append(("id", serverID)) }
        if let name { items.append(("name", name)) }
        return "\(scheme)://pair?" + items.map { "\(Query.encode($0.0))=\(Query.encode($0.1))" }.joined(separator: "&")
    }

    /// A link read, if `text` is one in any of `schemes` (the app's own: `nimbus`, `visor`…), or in one of `formats`.
    /// Whitespace around it is ignored, and so is anything around it when it's pasted inside a sentence.
    public static func parse(_ text: String, schemes: Set<String>, formats: [any PairingLinkFormat] = []) -> PairingLink? {
        let candidate = Self.extract(from: text, schemes: schemes) ?? text.trimmingWhitespace()
        if let link = Self.parseOwn(candidate, schemes: schemes) { return link }
        for format in formats {
            if let link = format.parse(candidate) { return link }
        }
        return nil
    }

    static func parseOwn(_ text: String, schemes: Set<String>) -> PairingLink? {
        guard let separator = text.firstRange(of: "://") else { return nil }
        let scheme = String(text[..<separator.lowerBound]).lowercased()
        guard schemes.contains(scheme) else { return nil }
        let rest = text[separator.upperBound...]
        guard let question = rest.firstIndex(of: "?"), rest[..<question].lowercased() == "pair" else { return nil }
        let items = Query.parse(rest[rest.index(after: question)...])
        func first(_ name: String) -> String? { items.first { $0.0 == name }?.1 }
        func all(_ name: String) -> [String] { items.filter { $0.0 == name }.map(\.1) }
        guard let code = first("code"), !code.isEmpty,
              let server = first("server"), Self.isHTTPS(server) else { return nil }
        let version = first("v").flatMap(Int.init) ?? 1
        // A version this reader doesn't know may mean what it doesn't: not read.
        guard version >= 1, version <= Self.currentVersion else { return nil }
        let pins = PinSet(all("pin").compactMap(Pin.init))
        var servers = [server]
        for address in all("address") where Self.isHTTPS(address) {
            // An address with the server's own certificate, only with a pin to check it by.
            if PinTrust.isPinned(host: Self.host(of: address) ?? ""), pins.isEmpty { continue }
            servers.append(address)
        }
        return PairingLink(scheme: scheme, code: code, servers: servers, pins: pins,
                           serverID: first("id").flatMap { $0.isEmpty ? nil : $0 },
                           name: first("name").flatMap { $0.isEmpty ? nil : $0 }, version: version)
    }

    /// The first `<scheme>://` link inside `text`, to its first whitespace: one pasted with words around it.
    static func extract(from text: String, schemes: Set<String>) -> String? {
        // Schemes are lowercase, as links write them: found as they are (an index into a lowercased copy wouldn't be
        // the text's).
        for scheme in schemes.sorted() {
            guard let start = text.firstRange(of: scheme + "://") else { continue }
            let tail = text[start.lowerBound...]
            let end = tail.firstIndex { $0.isWhitespace } ?? tail.endIndex
            return String(tail[..<end])
        }
        return nil
    }

    static func isHTTPS(_ address: String) -> Bool {
        address.lowercased().hasPrefix("https://") && host(of: address) != nil
    }

    /// `https://<host>[:port][/…]`'s host, brackets and all for IPv6.
    public static func host(of address: String) -> String? {
        guard let separator = address.firstRange(of: "://") else { return nil }
        var rest = address[separator.upperBound...]
        if let slash = rest.firstIndex(of: "/") { rest = rest[..<slash] }
        if let at = rest.lastIndex(of: "@") { rest = rest[rest.index(after: at)...] }
        if rest.hasPrefix("[") {
            guard let close = rest.firstIndex(of: "]") else { return nil }
            return String(rest[...close])
        }
        if let colon = rest.lastIndex(of: ":") { rest = rest[..<colon] }
        return rest.isEmpty ? nil : String(rest)
    }

    static func unique(_ addresses: [String]) -> [String] {
        var seen: [String] = []
        for address in addresses where !seen.contains(where: { $0.lowercased() == address.lowercased() }) { seen.append(address) }
        return seen
    }
}

/// A link format of an app's own, from before this one: read into a PairingLink, so a client reads both while the
/// devices that show the old one are still about. The app keeps its own parser and passes it to `PairingLink.parse`.
public protocol PairingLinkFormat: Sendable {
    func parse(_ text: String) -> PairingLink?
}

/// A query's `name=value` pairs, percent-coded (RFC 3986), with no Foundation.
enum Query {
    static func parse<S: StringProtocol>(_ query: S) -> [(String, String)] {
        query.split(separator: "&").compactMap { pair in
            let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard let name = decode(parts[0]) else { return nil }
            return (name, parts.count > 1 ? decode(parts[1]) ?? "" : "")
        }
    }

    static func decode<S: StringProtocol>(_ text: S) -> String? {
        var bytes: [UInt8] = []
        var iterator = Array(text.utf8).makeIterator()
        while let byte = iterator.next() {
            switch byte {
            case UInt8(ascii: "+"): bytes.append(UInt8(ascii: " "))
            case UInt8(ascii: "%"):
                guard let high = iterator.next().flatMap(hexValue), let low = iterator.next().flatMap(hexValue) else { return nil }
                bytes.append(high << 4 | low)
            default: bytes.append(byte)
            }
        }
        return String(validating: bytes, as: UTF8.self)
    }

    static func encode(_ text: String) -> String {
        var out = ""
        for byte in text.utf8 {
            let unreserved = (byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A) || (byte >= 0x30 && byte <= 0x39)
                || byte == UInt8(ascii: "-") || byte == UInt8(ascii: ".") || byte == UInt8(ascii: "_") || byte == UInt8(ascii: "~")
            if unreserved {
                out.unicodeScalars.append(Unicode.Scalar(byte))
            } else {
                let digits = Array("0123456789ABCDEF")
                out += "%" + String(digits[Int(byte >> 4)]) + String(digits[Int(byte & 0xF)])
            }
        }
        return out
    }

    static func hexValue(_ byte: UInt8) -> UInt8? {
        switch byte {
        case 0x30...0x39: return byte - 0x30
        case 0x41...0x46: return byte - 0x37
        case 0x61...0x66: return byte - 0x57
        default: return nil
        }
    }
}
