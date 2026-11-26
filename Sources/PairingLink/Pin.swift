// A server's own TLS certificate is self-signed: no CA vouches for it, so a client trusts it by a pin it was given when
// it paired (the pairing link, and what the server says of itself over a connection already trusted).
//
// A pin is a SHA-256, written as 64 lowercase hex digits, of one of two things:
//
// - `spki`: the certificate's SubjectPublicKeyInfo (its public key and algorithm, DER). A certificate made again for
//   the same key (new dates, new names) keeps the pin, so a server can re-issue it without unpairing anyone.
// - `certificate`: the whole certificate (its DER). What servers pinned before SPKI pins; read, and matched, still.
//
// A pin set is every pin a server stands behind at once: its current key and, while it rotates, its next. A client
// trusts a certificate that any of them matches.

/// One pin: what it's a SHA-256 of, and the SHA-256.
public struct Pin: Hashable, Sendable, CustomStringConvertible {
    public enum Kind: String, Sendable, Hashable, CaseIterable {
        /// The SHA-256 of the certificate's SubjectPublicKeyInfo (DER).
        case spki
        /// The SHA-256 of the whole certificate (DER).
        case certificate
    }

    public var kind: Kind
    /// 64 lowercase hex digits.
    public var sha256: String

    /// A pin, if `sha256` is 64 hex digits (any case; kept lowercase).
    public init?(_ kind: Kind, sha256: String) {
        guard let hex = Self.hex64(sha256) else { return nil }
        self.kind = kind
        self.sha256 = hex
    }

    /// A pin as a link or an answer writes it: `spki:<hex>` or `certificate:<hex>`; bare 64 hex digits are a
    /// `certificate` pin, as servers wrote them before kinds.
    public init?(_ text: String) {
        let trimmed = text.trimmingWhitespace()
        if let colon = trimmed.firstIndex(of: ":") {
            guard let kind = Kind(rawValue: String(trimmed[..<colon]).lowercased()) else { return nil }
            self.init(kind, sha256: String(trimmed[trimmed.index(after: colon)...]))
        } else {
            self.init(.certificate, sha256: trimmed)
        }
    }

    /// `spki:<hex>`, or bare hex for a `certificate` pin (what clients before kinds read).
    public var description: String {
        kind == .certificate ? sha256 : "\(kind.rawValue):\(sha256)"
    }

    static func hex64(_ text: String) -> String? {
        let lower = text.trimmingWhitespace().lowercased()
        guard lower.utf8.count == 64, lower.utf8.allSatisfy({ ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102) }) else { return nil }
        return lower
    }
}

/// The pins a server stands behind at once, in the order it gave them (its current first).
public struct PinSet: Hashable, Sendable {
    public var pins: [Pin]

    public init(_ pins: [Pin]) {
        var unique: [Pin] = []
        for pin in pins where !unique.contains(pin) { unique.append(pin) }
        self.pins = unique
    }

    public var isEmpty: Bool { pins.isEmpty }

    /// Whether a certificate, by its SHA-256s (each lowercase hex: of its SubjectPublicKeyInfo, and of the whole
    /// certificate; either may be unknown), is one of these. Every pin compared in constant time, and each one
    /// compared whatever came before, so nothing of the pins is told by how long the answer takes.
    public func matches(spki: String?, certificate: String?) -> Bool {
        var matched = false
        for pin in pins {
            let given = pin.kind == .spki ? spki : certificate
            if let given, Self.constantTimeEqual(given.lowercased(), pin.sha256) { matched = true }
        }
        return matched
    }

    static func constantTimeEqual(_ a: String, _ b: String) -> Bool {
        let a = Array(a.utf8), b = Array(b.utf8)
        guard a.count == b.count else { return false }
        return zip(a, b).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
    }
}

extension StringProtocol {
    func trimmingWhitespace() -> String {
        var scalars = Substring(self).unicodeScalars[...]
        while let first = scalars.first, first.properties.isWhitespace { scalars = scalars.dropFirst() }
        while let last = scalars.last, last.properties.isWhitespace { scalars = scalars.dropLast() }
        return String(String.UnicodeScalarView(scalars))
    }
}
