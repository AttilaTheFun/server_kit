import Foundation

// A paired device's session: a random token, shown to the device once (the answer to its claim) and kept as its SHA-256
// alone. It's sent as the device's bearer on every request, so the server knows which device is calling, and whose it
// is, and a device is unpaired by ending its session. Good for `lifetime` from its last use (sliding), its last use
// written at most once a minute.

/// One session, as the server keeps it: never its token.
public struct DeviceSession: Codable, Equatable, Sendable {
    /// Its name, for listing and ending it.
    public var id: String
    public var sha256: String
    /// Whom it's for (the server's own name for them: an account, an owner).
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

/// Where the sessions are kept, read and written whole.
public protocol SessionStore: Sendable {
    func load() -> [DeviceSession]
    func save(_ sessions: [DeviceSession]) throws
}

/// The sessions, kept in `store`.
public final class DeviceSessions: @unchecked Sendable {
    public let store: any SessionStore
    /// What a token starts with (`sws_`, an app's own): told apart from other credentials at a glance.
    public let prefix: String
    public let lifetime: TimeInterval

    private let lock = NSLock()
    private var entries: [DeviceSession]?

    public init(store: any SessionStore, prefix: String = "sess_", lifetime: TimeInterval = 30 * 24 * 3600) {
        self.store = store
        self.prefix = prefix
        self.lifetime = lifetime
    }

    /// A new session for `owner` on `device`: its token, shown this once, and what's kept of it.
    public func make(for owner: String, device: String?, now: Date = Date()) throws -> (token: String, session: DeviceSession) {
        let token = prefix + Token.random(bytes: 32)
        let session = DeviceSession(id: Token.random(bytes: 6), sha256: Token.digest(token), owner: owner,
                                    device: device.map(Self.deviceName), created: now, used: now)
        try lock.withLock {
            var all = loaded().filter { now.timeIntervalSince($0.used) < lifetime }
            all.append(session)
            try write(all)
        }
        return (token, session)
    }

    /// The live session a token is, its last use now.
    public func check(_ token: String, now: Date = Date()) -> DeviceSession? {
        guard token.hasPrefix(prefix) else { return nil }
        let given = Token.digest(token)
        return lock.withLock {
            var all = loaded()
            // Every session compared, so how long it takes says nothing of which matched.
            var found: Int?
            for (index, session) in all.enumerated() where Token.equal(session.sha256, given) { found = index }
            guard let index = found, now.timeIntervalSince(all[index].used) < lifetime else { return nil }
            if now.timeIntervalSince(all[index].used) > 60 {
                all[index].used = now
                try? write(all)
            }
            return all[index]
        }
    }

    /// The live sessions.
    public func list(now: Date = Date()) -> [DeviceSession] {
        lock.withLock { loaded().filter { now.timeIntervalSince($0.used) < lifetime } }
    }

    /// One ended (its device unpaired): whether there was such a session.
    @discardableResult
    public func end(_ id: String) throws -> Bool {
        try lock.withLock {
            let all = loaded()
            guard all.contains(where: { $0.id == id }) else { return false }
            try write(all.filter { $0.id != id })
            return true
        }
    }

    /// Only those `keep` keeps, the rest ended: how many were.
    @discardableResult
    public func keep(where keep: (DeviceSession) -> Bool) throws -> Int {
        try lock.withLock {
            let all = loaded()
            let kept = all.filter(keep)
            guard kept.count != all.count else { return 0 }
            try write(kept)
            return all.count - kept.count
        }
    }

    /// A device's name as it's listed and logged: control characters out (no forged log line), at most 80 characters.
    public static func deviceName(_ given: String) -> String {
        var kept = String.UnicodeScalarView()
        kept.append(contentsOf: given.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) })
        return String(String(kept).prefix(80))
    }

    private func loaded() -> [DeviceSession] {
        if let entries { return entries }
        let read = store.load()
        entries = read
        return read
    }

    private func write(_ all: [DeviceSession]) throws {
        try store.save(all)
        entries = all
    }
}

/// A JSON file, readable by its owner alone (0600).
public struct FileSessionStore: SessionStore {
    public var path: String

    public init(path: String) { self.path = path }

    public func load() -> [DeviceSession] {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return FileManager.default.contents(atPath: path).flatMap { try? decoder.decode([DeviceSession].self, from: $0) } ?? []
    }

    public func save(_ sessions: [DeviceSession]) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(sessions)
        try FileManager.default.createDirectory(atPath: (path as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        let partial = path + ".partial"
        guard FileManager.default.createFile(atPath: partial, contents: data, attributes: [.posixPermissions: 0o600]) else {
            throw CocoaError(.fileWriteUnknown)
        }
        // In one step (rename(2)): a reader sees the old file or the new, never half of one.
        guard rename(partial, path) == 0 else {
            try? FileManager.default.removeItem(atPath: partial)
            throw CocoaError(.fileWriteUnknown)
        }
    }
}
