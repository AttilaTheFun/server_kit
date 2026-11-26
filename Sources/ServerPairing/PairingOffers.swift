import Crypto
import Foundation
import NetworkCore

// Pairing a device with a server: the server's owner asks for a pairing (on the server's own screen, or from a device
// already paired), the server offers a one-time code, shown as a QR (PairingLink) beside its addresses and pins; the
// device claims the code once, within minutes, over TLS, and is given a session of its own (DeviceSessions) for the
// owner the code was offered for. Codes are kept as their SHA-256 alone, in memory (a restart forgets them).

/// The codes offered and not yet claimed, each for an owner (whom a session made from it is for: an account, a person).
public final class PairingOffers: @unchecked Sendable {
    public struct Offer: Sendable, Equatable {
        public let code: String
        public let expires: Date
    }

    /// How long a code is good for.
    public let lifetime: TimeInterval
    /// Codes waiting at once: one is for a device in front of the server, not a stack of them.
    public let maxWaiting: Int
    private let now: @Sendable () -> Date

    private let lock = NSLock()
    private var waiting: [String: (owner: String, expires: Date)] = [:]

    public init(lifetime: TimeInterval = 5 * 60, maxWaiting: Int = 8, now: @escaping @Sendable () -> Date = Date.init) {
        self.lifetime = lifetime
        self.maxWaiting = maxWaiting
        self.now = now
    }

    /// A code for `owner`, good once until it runs out; nil while `maxWaiting` are waiting.
    public func offer(for owner: String) -> Offer? {
        let code = SecretToken.random(bytes: 16)
        let now = now()
        return lock.withLock {
            waiting = waiting.filter { $0.value.expires > now }
            guard waiting.count < maxWaiting else { return nil }
            let expires = now.addingTimeInterval(lifetime)
            waiting[SecretToken.digest(code)] = (owner, expires)
            return Offer(code: code, expires: expires)
        }
    }

    /// The owner a code was offered for, once: nil if it wasn't offered here, was claimed already, or ran out.
    public func claim(_ code: String) -> String? {
        let now = now()
        return lock.withLock {
            guard let offer = waiting.removeValue(forKey: SecretToken.digest(code)), offer.expires > now else { return nil }
            return offer.owner
        }
    }

    /// Codes waiting now.
    public var waitingCount: Int {
        let now = now()
        return lock.withLock { waiting.values.filter { $0.expires > now }.count }
    }
}

/// Wrong claims, counted by where they come from: `limit` wrong, used or run-out codes (or passwords) within `window`
/// from one place, and it's refused for `lockout`; another's never block it. A server on a LAN is reachable by
/// strangers (a café's, a hotel's), so a short secret isn't guessed at leisure.
///
/// - **Where:** an IPv4 address, or an IPv6 address's /64 (one host holds a whole /64, and would walk through it), an
///   IPv4-mapped IPv6 address as its IPv4.
/// - **All at once:** beyond `globalLimit` wrong claims within `window` from anywhere, every claim is refused for
///   `lockout` too: many places guessing together are still guessing.
/// - **In memory,** at most `maxAddresses` places kept: those done with first, then the oldest.
public final class ClaimThrottle: @unchecked Sendable {
    public let limit: Int
    public let globalLimit: Int
    public let window: TimeInterval
    public let lockout: TimeInterval
    public let maxAddresses: Int
    private let now: @Sendable () -> Date

    private struct Entry {
        var failures: [Date] = []
        var lockedUntil: Date?
        var touched: Date
    }

    private let lock = NSLock()
    private var entries: [String: Entry] = [:]
    private var everywhere: [Date] = []
    private var everywhereLockedUntil: Date?

    public init(limit: Int = 5, globalLimit: Int = 50, window: TimeInterval = 60, lockout: TimeInterval = 5 * 60,
                maxAddresses: Int = 1024, now: @escaping @Sendable () -> Date = Date.init) {
        self.limit = limit
        self.globalLimit = globalLimit
        self.window = window
        self.lockout = lockout
        self.maxAddresses = maxAddresses
        self.now = now
    }

    /// Where an address counts from: an IPv6 address's /64, an IPv4-mapped one's IPv4, else the address as given.
    public static func place(_ address: String) -> String {
        var bare = Substring(address)
        if bare.hasPrefix("["), let close = bare.firstIndex(of: "]") { bare = bare[bare.index(after: bare.startIndex)..<close] }
        if bare.lowercased().hasPrefix("::ffff:"), IPv4.parse(bare.dropFirst(7)) != nil { return String(bare.dropFirst(7)) }
        if let prefix = IPv6.prefix64(bare) { return prefix + "::/64" }
        return String(bare)
    }

    /// When `address` may claim again, if it (or everyone) is locked out now.
    public func lockedUntil(_ address: String) -> Date? {
        let now = now(), place = Self.place(address)
        return lock.withLock {
            let own = entries[place]?.lockedUntil.flatMap { $0 > now ? $0 : nil }
            let all = everywhereLockedUntil.flatMap { $0 > now ? $0 : nil }
            switch (own, all) {
            case (let a?, let b?): return max(a, b)
            case (let a?, nil): return a
            case (nil, let b?): return b
            default: return nil
            }
        }
    }

    /// A wrong claim from `address`; true when it locks that place (or everyone) out, said once then.
    @discardableResult
    public func failed(_ address: String) -> Bool {
        let now = now(), place = Self.place(address)
        return lock.withLock {
            var locked = false
            var entry = entries[place] ?? Entry(touched: now)
            if let until = entry.lockedUntil, until <= now { entry.lockedUntil = nil }
            entry.failures = entry.failures.filter { now.timeIntervalSince($0) < window } + [now]
            entry.touched = now
            if entry.lockedUntil == nil, entry.failures.count >= limit {
                entry.lockedUntil = now.addingTimeInterval(lockout)
                entry.failures = []
                locked = true
            }
            entries[place] = entry
            everywhere = everywhere.filter { now.timeIntervalSince($0) < window } + [now]
            if everywhereLockedUntil.map({ $0 <= now }) ?? true, everywhere.count >= globalLimit {
                everywhereLockedUntil = now.addingTimeInterval(lockout)
                everywhere = []
                locked = true
            }
            if entries.count > maxAddresses {
                // Never a place locked out now: forgetting it would let it in again.
                entries = entries.filter { $0.value.lockedUntil.map { $0 > now } ?? false
                    || $0.value.failures.contains { now.timeIntervalSince($0) < window } }
                while entries.count > maxAddresses,
                      let oldest = entries.filter({ $0.value.lockedUntil.map { $0 <= now } ?? true }).min(by: { $0.value.touched < $1.value.touched })?.key {
                    entries[oldest] = nil
                }
            }
            return locked
        }
    }

    /// A right claim from `address`: its wrong ones forgotten (a person who mistyped, then got it right). A lockout in
    /// force stays.
    public func succeeded(_ address: String) {
        let place = Self.place(address)
        lock.withLock {
            guard var entry = entries[place] else { return }
            entry.failures = []
            if entry.lockedUntil == nil { entries[place] = nil } else { entries[place] = entry }
        }
    }

    /// Places kept now.
    public var count: Int { lock.withLock { entries.count } }
}

/// Random secrets and their digests.
public enum SecretToken {
    /// `bytes` random bytes as lowercase hex, from the system's secure generator.
    public static func random(bytes: Int) -> String {
        var generator = SystemRandomNumberGenerator()
        return hex((0..<bytes).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
    }

    /// Its SHA-256, lowercase hex: what's kept of a code or a session's token.
    public static func digest(_ token: String) -> String {
        hex(SHA256.hash(data: Data(token.utf8)))
    }

    /// Whether two strings are equal, compared in constant time for their length.
    public static func equal(_ a: String, _ b: String) -> Bool {
        let a = Array(a.utf8), b = Array(b.utf8)
        guard a.count == b.count else { return false }
        return zip(a, b).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
    }

    static func hex<D: Sequence>(_ bytes: D) -> String where D.Element == UInt8 {
        let digits = Array("0123456789abcdef")
        return bytes.map { String(digits[Int($0 >> 4)]) + String(digits[Int($0 & 0xF)]) }.joined()
    }
}
