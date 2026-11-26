import NetworkCore

// The link a server shows as a QR (or a person copies and pastes) for a device to pair with it:
//
//     <scheme>://pair?v=1&server=<https URL>&address=<https URL>…&pin=<pin>…&code=<one-time code>&id=<server id>&name=<name>
//
// - `server`, then `address` (repeated): the server's TLS addresses, the one to pair at first leading (one a CA vouches
//   for, like a tailnet's `*.ts.net`, where there's one). `pin` (repeated): its own certificate's pins (Pin), current
//   first. An address that presents the server's own certificate (PinTrust.isPinned) is kept only with a pin, so a
//   link never sends a device to a certificate it has no way to check; a link without pins has only CA-vouched ones.
// - `path` (repeated): the server's other ways in, which an app handles itself, the kit saying nothing of their trust:
//   a URL of any scheme (`http://…` on loopback, `ssh://…`), or a bare host (`studio`, `user@studio:22`).
// - The credential, one of: `code` (good once, for minutes: ServerPairing's offers), `password` (a long-lived one, for a
//   server that has one), or none (a server that asks nothing, or a way of the app's own: an `x-` field). A link with
//   both a code and a password isn't read: which is meant can't be told.
// - `id`, `name`: the server's stable id and what to call it, so a device knows a server it has paired with already.
// - `x-<name>` (any): an app's own fields, kept and written back as they are.
//
// Written and read with no Foundation, so it runs wherever Swift does, WebAssembly included. A link in a format of an
// app's own from before (`PairingLinkFormat`) is read through the same entry point, so a client reads both.

public struct PairingLink: Hashable, Sendable {
    /// The format's version: what `v=` says. A link with no `v` is a version 1 link (the first servers wrote).
    public static let currentVersion = 1

    /// How a device proves itself when it pairs.
    public enum Credential: Hashable, Sendable {
        /// A one-time code, good for minutes: claimed for a session of the device's own.
        case oneTimeCode(String)
        /// A long-lived password the server keeps.
        case password(String)
        /// Nothing in the link.
        case none
    }

    public let scheme: String
    /// The TLS addresses (`https://…`), the one to pair at first leading, each once.
    public let servers: [String]
    /// The other ways in, any scheme, each once.
    public let paths: [String]
    public let pins: PinSet
    public var credential: Credential
    /// The server's own stable id, if it says one.
    public var serverID: String?
    /// What the server is called, for a person.
    public var name: String?
    /// An app's own fields (`x-<name>` in the link, the name here without `x-`).
    public var extensions: [String: String]
    public let version: Int

    /// A link, if it can be written as it is: a lowercase scheme, every server `https://` with a host, an address that
    /// presents the server's own certificate only with pins, every path with a host, at least one server or path, and a
    /// version this writes.
    public init?(scheme: String, servers: [String], paths: [String] = [], pins: PinSet = PinSet([]), credential: Credential,
                 serverID: String? = nil, name: String? = nil, extensions: [String: String] = [:],
                 version: Int = PairingLink.currentVersion) {
        let schemeCharacters = scheme.unicodeScalars.allSatisfy { ("a"..."z").contains($0) || ("0"..."9").contains($0) || "+-.".unicodeScalars.contains($0) }
        guard !scheme.isEmpty, schemeCharacters, version >= 1, version <= Self.currentVersion,
              servers.allSatisfy(Self.isHTTPS),
              !pins.isEmpty || !servers.contains(where: Self.presentsOwnCertificate),
              paths.allSatisfy({ Self.pathHost(of: $0) != nil }),
              !(servers.isEmpty && paths.isEmpty),
              extensions.keys.allSatisfy({ !$0.isEmpty }) else { return nil }
        self.scheme = scheme
        self.servers = Self.unique(servers)
        self.paths = Self.unique(paths)
        self.pins = pins
        self.credential = credential
        self.serverID = serverID
        self.name = name
        self.extensions = extensions
        self.version = version
    }

    /// The address to pair at first.
    public var server: String? { servers.first }

    /// The one-time code, if that's its credential.
    public var code: String? {
        if case .oneTimeCode(let code) = credential { return code }
        return nil
    }

    /// The link, as a QR shows it.
    public var text: String {
        var items: [(String, String)] = [("v", String(version))]
        if let first = servers.first { items.append(("server", first)) }
        items += servers.dropFirst().map { ("address", $0) }
        items += pins.pins.map { ("pin", $0.description) }
        items += paths.map { ("path", $0) }
        switch credential {
        case .oneTimeCode(let code): items.append(("code", code))
        case .password(let password): items.append(("password", password))
        case .none: break
        }
        if let serverID { items.append(("id", serverID)) }
        if let name { items.append(("name", name)) }
        items += extensions.keys.sorted().map { ("x-" + $0, extensions[$0] ?? "") }
        return "\(scheme)://pair?" + items.map { "\(Query.encode($0.0))=\(Query.encode($0.1, trailingDot: true))" }.joined(separator: "&")
    }

    /// A link read, if `text` is one in any of `schemes` (the app's own: `nimbus`, `visor`…), or in one of `formats`.
    /// Pasted text is read too: the earliest link in it (its scheme in any case, as a keyboard capitalises the start of
    /// a sentence), to its first whitespace, the punctuation a sentence puts after it left out.
    public static func parse(_ text: String, schemes: Set<String>, formats: [any PairingLinkFormat] = []) -> PairingLink? {
        // A bare trailing `.` (or `,` `)` …) is a sentence's: links this writes percent-code a value's last `.`, so they
        // never end with one.
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
        guard let question = rest.firstIndex(of: "?"), rest[..<question].lowercased() == "pair",
              let items = Query.parse(rest[rest.index(after: question)...]) else { return nil }
        func first(_ name: String) -> String? { items.first { $0.0 == name }?.1 }
        func all(_ name: String) -> [String] { items.filter { $0.0 == name }.map(\.1) }
        let version = first("v").flatMap { Int($0) } ?? 1
        // A version this reader doesn't know may mean what it doesn't: not read.
        guard version >= 1, version <= Self.currentVersion else { return nil }
        let pins = PinSet(all("pin").compactMap { Pin($0) })
        // `server`, then each `address`: https, and one with the server's own certificate only with pins.
        let servers = ([first("server")].compactMap { $0 } + all("address")).filter { address in
            Self.isHTTPS(address) && !(pins.isEmpty && Self.presentsOwnCertificate(address))
        }
        let credential: Credential
        switch (first("code").flatMap { $0.isEmpty ? nil : $0 }, first("password").flatMap { $0.isEmpty ? nil : $0 }) {
        case (.some, .some): return nil
        case (let code?, nil): credential = .oneTimeCode(code)
        case (nil, let password?): credential = .password(password)
        case (nil, nil): credential = .none
        }
        var extensions: [String: String] = [:]
        for (name, value) in items where name.hasPrefix("x-") && name.count > 2 { extensions[String(name.dropFirst(2))] = value }
        return PairingLink(scheme: scheme, servers: servers, paths: all("path").filter { Self.pathHost(of: $0) != nil }, pins: pins,
                           credential: credential, serverID: first("id").flatMap { $0.isEmpty ? nil : $0 },
                           name: first("name").flatMap { $0.isEmpty ? nil : $0 }, extensions: extensions, version: version)
    }

    /// The earliest `<scheme>://` link inside `text` (its scheme in any case), to its first whitespace, with the
    /// punctuation a sentence puts after it left out.
    static func extract(from text: String, schemes: Set<String>) -> String? {
        let bytes = Array(text.utf8)
        var earliest: Int?
        for scheme in schemes {
            let needle = Array((scheme + "://").utf8)
            guard needle.count <= bytes.count else { continue }
            for start in 0...(bytes.count - needle.count) {
                if let found = earliest, start >= found { break }
                // ASCII schemes, compared without case.
                if zip(bytes[start..<(start + needle.count)], needle).allSatisfy({ Self.lower($0.0) == Self.lower($0.1) }) {
                    earliest = start
                    break
                }
            }
        }
        guard let start = earliest else { return nil }
        var end = start
        while end < bytes.count, !Self.isSpace(bytes[end]) { end += 1 }
        let trailing = Array(".,;:!?)]}>\"'".utf8)
        while end > start, trailing.contains(bytes[end - 1]) { end -= 1 }
        return String(decoding: bytes[start..<end], as: UTF8.self)
    }

    static func lower(_ byte: UInt8) -> UInt8 { byte >= 0x41 && byte <= 0x5A ? byte + 0x20 : byte }
    static func isSpace(_ byte: UInt8) -> Bool { byte == 0x20 || (byte >= 0x09 && byte <= 0x0D) }

    static func isHTTPS(_ address: String) -> Bool {
        address.lowercased().hasPrefix("https://") && host(of: address) != nil
    }

    static func presentsOwnCertificate(_ address: String) -> Bool {
        PinTrust.isPinned(host: host(of: address) ?? "")
    }

    /// `<scheme>://<host>[:port][/…]`'s host (brackets kept for IPv6); nil when there's none.
    public static func host(of address: String) -> String? {
        guard let separator = address.firstRange(of: "://") else { return nil }
        var rest = address[separator.upperBound...]
        if let slash = rest.firstIndex(where: { $0 == "/" || $0 == "?" || $0 == "#" }) { rest = rest[..<slash] }
        if let at = rest.lastIndex(of: "@") { rest = rest[rest.index(after: at)...] }
        if rest.hasPrefix("[") {
            guard let close = rest.firstIndex(of: "]") else { return nil }
            return String(rest[...close])
        }
        if let colon = rest.lastIndex(of: ":") { rest = rest[..<colon] }
        return rest.isEmpty ? nil : String(rest)
    }

    /// A path's host: a URL's (`host(of:)`), or a bare one's (`studio`, `user@studio:22`, `[fe80::1]:22`); nil for an
    /// empty one, or one with whitespace.
    public static func pathHost(of path: String) -> String? {
        if path.firstRange(of: "://") != nil { return host(of: path) }
        guard !path.isEmpty, !path.contains(where: { $0.isWhitespace }) else { return nil }
        return host(of: "x://" + path)
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
    /// Every pair; nil when one can't be decoded (bad percent-coding, or bytes that aren't UTF-8).
    static func parse<S: StringProtocol>(_ query: S) -> [(String, String)]? {
        var pairs: [(String, String)] = []
        for pair in query.split(separator: "&") {
            let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard let name = decode(parts[0]) else { return nil }
            guard let value = parts.count > 1 ? decode(parts[1]) : "" else { return nil }
            pairs.append((name, value))
        }
        return pairs
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
        // UTF-8 or nothing: decoded with repairs, then the same bytes back (not `String(validating:)`, which needs macOS
        // 15 and iOS 18).
        let string = String(decoding: bytes, as: UTF8.self)
        return Array(string.utf8) == bytes ? string : nil
    }

    /// `trailingDot`: a value's last `.` percent-coded too, so a link pasted into a sentence, whose trailing punctuation a
    /// reader leaves out, keeps it.
    static func encode(_ text: String, trailingDot: Bool = false) -> String {
        var out = ""
        let digits = Array("0123456789ABCDEF")
        let bytes = Array(text.utf8)
        for (index, byte) in bytes.enumerated() {
            let last = trailingDot && index == bytes.count - 1 && byte == UInt8(ascii: ".")
            let unreserved = !last && ((byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A) || (byte >= 0x30 && byte <= 0x39)
                || byte == UInt8(ascii: "-") || byte == UInt8(ascii: ".") || byte == UInt8(ascii: "_") || byte == UInt8(ascii: "~"))
            if unreserved {
                out.unicodeScalars.append(Unicode.Scalar(byte))
            } else {
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
