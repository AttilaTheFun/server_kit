#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(Android)
import Android
#endif
import Foundation

// A paired device's session: a random token, shown to the device once (the answer to its claim) and kept as its
// SHA-256 alone. It's the device's bearer on every request, so the server knows which device is calling and for whom,
// and a device is unpaired by ending its session. Good for `lifetime` from its last use (sliding), and never past
// `maxAge` from when it was made. Looked up by its digest in memory; its last use written behind, at most once a
// minute.

/// One session, as the server keeps it: never its token.
public struct DeviceSession: Codable, Equatable, Sendable {
    /// Its name, for listing and ending it.
    public var id: String
    public var sha256: String
    /// Whom it's for (the server's own name for them: an account, a person).
    public var owner: String
    /// The device, as it named itself when it paired (control characters taken out, at most 80 characters).
    public var device: String?
    public var created: Date
    public var used: Date

    public init(id: String, sha256: String, owner: String, device: String?, created: Date, used: Date) {
        self.id = id
        self.sha256 = sha256
        self.owner = owner
        self.device = device
        self.created = created
        self.used = used
    }
}

/// Where the sessions are kept, read and written whole. `load` throws when it can't tell (a file it can't read or
/// decode), so a failure is never taken for no sessions and written over.
public protocol SessionStore: Sendable {
    func load() throws -> [DeviceSession]
    func save(_ sessions: [DeviceSession]) throws
}

/// The sessions, kept in `store`.
public final class DeviceSessions: @unchecked Sendable {
    public let store: any SessionStore
    /// What a token starts with (`sws_`, an app's own): told apart from other credentials at a glance.
    public let prefix: String
    /// Unused this long, a session ends.
    public let lifetime: TimeInterval
    /// Made this long ago, a session ends however much it's used; nil for no limit.
    public let maxAge: TimeInterval?
    private let now: @Sendable () -> Date

    private let lock = NSLock()
    /// By digest, once loaded.
    private var byDigest: [String: DeviceSession]?
    /// When a last use was last written.
    private var written = Date.distantPast

    public init(store: any SessionStore, prefix: String = "sess_", lifetime: TimeInterval = 30 * 24 * 3600,
                maxAge: TimeInterval? = 365 * 24 * 3600, now: @escaping @Sendable () -> Date = Date.init) {
        self.store = store
        self.prefix = prefix
        self.lifetime = lifetime
        self.maxAge = maxAge
        self.now = now
    }

    /// A new session for `owner` on `device`: its token, shown this once, and what's kept of it.
    public func make(for owner: String, device: String?) throws -> (token: String, session: DeviceSession) {
        let now = now()
        let token = prefix + SecretToken.random(bytes: 32)
        let session = DeviceSession(id: SecretToken.random(bytes: 6), sha256: SecretToken.digest(token), owner: owner,
                                    device: device.map(Self.deviceName), created: now, used: now)
        try lock.withLock {
            var all = try loaded().filter { live($0.value, now: now) }
            all[session.sha256] = session
            try write(all, now: now)
        }
        return (token, session)
    }

    /// The live session a token is, its last use now (written behind, at most once a minute). Nil for anything else,
    /// and when the store can't be read.
    public func check(_ token: String) -> DeviceSession? {
        guard token.hasPrefix(prefix) else { return nil }
        let now = now(), digest = SecretToken.digest(token)
        return lock.withLock {
            guard var all = try? loaded(), var session = all[digest], live(session, now: now) else { return nil }
            session.used = now
            all[digest] = session
            byDigest = all
            if now.timeIntervalSince(written) > 60 { try? write(all, now: now) }
            return session
        }
    }

    /// The live sessions, oldest first.
    public func list() throws -> [DeviceSession] {
        let now = now()
        return try lock.withLock { try loaded().values.filter { live($0, now: now) }.sorted { $0.created < $1.created } }
    }

    /// One ended (its device unpaired): whether there was such a session.
    @discardableResult
    public func end(_ id: String) throws -> Bool {
        try lock.withLock {
            var all = try loaded()
            guard let digest = all.first(where: { $0.value.id == id })?.key else { return false }
            all[digest] = nil
            try write(all, now: now())
            return true
        }
    }

    /// Only those `keep` keeps, the rest ended: how many were.
    @discardableResult
    public func keep(where keep: (DeviceSession) -> Bool) throws -> Int {
        try lock.withLock {
            let all = try loaded()
            let kept = all.filter { keep($0.value) }
            guard kept.count != all.count else { return 0 }
            try write(kept, now: now())
            return all.count - kept.count
        }
    }

    /// The last uses held in memory, written now (before the process ends).
    public func flush() throws {
        try lock.withLock { if let byDigest { try write(byDigest, now: now()) } }
    }

    /// A device's name as it's listed and logged: control characters out (no forged log line), at most 80 characters.
    public static func deviceName(_ given: String) -> String {
        var kept = String.UnicodeScalarView()
        kept.append(contentsOf: given.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) })
        return String(String(kept).prefix(80))
    }

    private func live(_ session: DeviceSession, now: Date) -> Bool {
        now.timeIntervalSince(session.used) < lifetime && (maxAge.map { now.timeIntervalSince(session.created) < $0 } ?? true)
    }

    private func loaded() throws -> [String: DeviceSession] {
        if let byDigest { return byDigest }
        let read = Dictionary(try store.load().map { ($0.sha256, $0) }, uniquingKeysWith: { a, b in a.used > b.used ? a : b })
        byDigest = read
        return read
    }

    private func write(_ all: [String: DeviceSession], now: Date) throws {
        try store.save(all.values.sorted { $0.created < $1.created })
        byDigest = all
        written = now
    }
}

/// A JSON file, readable by its owner alone (0600), written whole (a new file renamed over it).
public struct FileSessionStore: SessionStore {
    public let path: String

    public init(path: String) { self.path = path }

    public func load() throws -> [DeviceSession] {
        guard FileManager.default.fileExists(atPath: path) else { return [] }
        guard let data = FileManager.default.contents(atPath: path) else { throw SessionStoreError("\(path) can't be read") }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        do {
            return try decoder.decode([DeviceSession].self, from: data)
        } catch {
            throw SessionStoreError("\(path) isn't a sessions file: \(error)")
        }
    }

    public func save(_ sessions: [DeviceSession]) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(sessions)
        try FileManager.default.createDirectory(atPath: (path as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        let temporary = path + ".partial-\(getpid())"
        unlink(temporary)
        let descriptor = open(temporary, O_WRONLY | O_CREAT | O_EXCL, 0o600)
        guard descriptor >= 0 else { throw SessionStoreError("\(temporary) couldn't be made") }
        var written = 0
        let ok = data.withUnsafeBytes { buffer -> Bool in
            while written < buffer.count {
                let result = write(descriptor, buffer.baseAddress! + written, buffer.count - written)
                guard result > 0 else { return false }
                written += result
            }
            return fsync(descriptor) == 0
        }
        close(descriptor)
        guard ok, rename(temporary, path) == 0 else {
            unlink(temporary)
            throw SessionStoreError("\(path) couldn't be written")
        }
    }
}

public struct SessionStoreError: Error, CustomStringConvertible {
    public let description: String
    init(_ description: String) { self.description = description }
}
