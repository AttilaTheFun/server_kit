import Crypto
import Foundation

// Pairing a device with a server: the server's owner asks for a pairing (on the server's own screen, or from a device
// already paired), the server offers a one-time code, shown as a QR (PairingLink) beside its addresses and pins; the
// device claims the code once, within minutes, over TLS, and is given a session of its own (DeviceSessions) as the one
// the code was offered for. Codes are kept as their SHA-256 alone, in memory (a restart forgets them).

/// The codes offered and not yet claimed, each for an `Owner` (whom a session made from it is for).
public final class PairingOffers<Owner: Sendable>: @unchecked Sendable {
    public struct Offer: Sendable {
        public var code: String
        public var expires: Date
    }

    /// How long a code is good for.
    public let lifetime: TimeInterval
    /// Codes waiting at once: one is for a device in front of the server, not a stack of them.
    public let most: Int

    private let lock = NSLock()
    private var waiting: [String: (owner: Owner, expires: Date)] = [:]

    public init(lifetime: TimeInterval = 5 * 60, most: Int = 8) {
        self.lifetime = lifetime
        self.most = most
    }

    /// A code for `owner`, good once until it runs out; nil while `most` are waiting.
    public func offer(for owner: Owner, now: Date = Date()) -> Offer? {
        let code = Token.random(bytes: 16)
        return lock.withLock {
            waiting = waiting.filter { $0.value.expires > now }
            guard waiting.count < most else { return nil }
            let expires = now.addingTimeInterval(lifetime)
            waiting[Token.digest(code)] = (owner, expires)
            return Offer(code: code, expires: expires)
        }
    }

    /// Whom a code was offered for, once: nil if it wasn't offered here, was claimed already, or ran out.
    public func claim(_ code: String, now: Date = Date()) -> Owner? {
        lock.withLock {
            guard let offer = waiting.removeValue(forKey: Token.digest(code)), offer.expires > now else { return nil }
            return offer.owner
        }
    }

    /// Codes waiting now.
    public func count(now: Date = Date()) -> Int {
        lock.withLock { waiting.values.filter { $0.expires > now }.count }
    }
}

/// Wrong claims counted by where they come from: `limit` wrong, used or run-out codes within `window` from one
/// address, and that address is refused for `lockout`; another's never block it. A server on a LAN is reachable by
/// strangers (a café's, a hotel's), so a short code isn't guessed at leisure. In memory, at most `most` addresses kept,
/// those done with first, then the oldest.
public final class ClaimThrottle: @unchecked Sendable {
    public let limit: Int
    public let window: TimeInterval
    public let lockout: TimeInterval
    public let most: Int

    private struct Entry {
        var failures: [Date] = []
        var lockedUntil: Date?
        var touched: Date
    }

    private let lock = NSLock()
    private var entries: [String: Entry] = [:]

    public init(limit: Int = 5, window: TimeInterval = 60, lockout: TimeInterval = 5 * 60, most: Int = 1024) {
        self.limit = limit
        self.window = window
        self.lockout = lockout
        self.most = most
    }

    /// When `address` may claim again, if it's locked out now.
    public func lockedUntil(_ address: String, now: Date = Date()) -> Date? {
        lock.withLock {
            guard let until = entries[address]?.lockedUntil, until > now else { return nil }
            return until
        }
    }

    /// A wrong claim from `address`; true when it locks the address out (said once, then).
    @discardableResult
    public func failed(_ address: String, now: Date = Date()) -> Bool {
        lock.withLock {
            var entry = entries[address] ?? Entry(touched: now)
            if let until = entry.lockedUntil, until <= now { entry.lockedUntil = nil }
            entry.failures = entry.failures.filter { now.timeIntervalSince($0) < window } + [now]
            entry.touched = now
            var locked = false
            if entry.lockedUntil == nil, entry.failures.count >= limit {
                entry.lockedUntil = now.addingTimeInterval(lockout)
                entry.failures = []
                locked = true
            }
            entries[address] = entry
            if entries.count > most {
                entries = entries.filter { $0.value.lockedUntil.map { $0 > now } ?? false
                    || $0.value.failures.contains { now.timeIntervalSince($0) < window } }
                while entries.count > most, let oldest = entries.min(by: { $0.value.touched < $1.value.touched })?.key {
                    entries[oldest] = nil
                }
            }
            return locked
        }
    }

    /// Addresses kept now.
    public var count: Int { lock.withLock { entries.count } }
}

/// Random tokens and their digests.
public enum Token {
    /// `bytes` random bytes as lowercase hex, from the system's secure generator.
    public static func random(bytes: Int) -> String {
        var generator = SystemRandomNumberGenerator()
        return (0..<bytes).map { _ in
            let byte = UInt8.random(in: .min ... .max, using: &generator)
            let digits = Array("0123456789abcdef")
            return String(digits[Int(byte >> 4)]) + String(digits[Int(byte & 0xF)])
        }.joined()
    }

    /// Its SHA-256, lowercase hex: what's kept of a code or a session's token.
    public static func digest(_ token: String) -> String {
        SHA256.hash(data: Data(token.utf8)).map { byte in
            let digits = Array("0123456789abcdef")
            return String(digits[Int(byte >> 4)]) + String(digits[Int(byte & 0xF)])
        }.joined()
    }

    /// Whether two digests are equal, compared in constant time.
    public static func equal(_ a: String, _ b: String) -> Bool {
        let a = Array(a.utf8), b = Array(b.utf8)
        guard a.count == b.count else { return false }
        return zip(a, b).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
    }
}
