#if canImport(Network)
import Network
#endif
import Foundation

/// The device's networks changing (NWPathMonitor), said a moment after they settle (400 ms): each change a new
/// `generation`, by which a client ranks its server's addresses again and moves to a better one. Where there's no
/// Network framework, nothing changes (generation 0).
public final class NetworkWatch: @unchecked Sendable {
    public static let shared = NetworkWatch()

    private let lock = NSLock()
    private var count = 0
    private var started = false
    private var pending: Task<Void, Never>?
    private var handlers: [UUID: @Sendable (Int) -> Void] = [:]
    #if canImport(Network)
    private var monitor: NWPathMonitor?
    #endif

    public init() {}

    /// Bumped at each settled change; 0 until the first.
    public var generation: Int {
        start()
        return lock.withLock { count }
    }

    /// `handler` called with each new generation, until the token returned is passed to `stop`.
    public func onChange(_ handler: @escaping @Sendable (Int) -> Void) -> UUID {
        start()
        let id = UUID()
        lock.withLock { handlers[id] = handler }
        return id
    }

    public func stop(_ token: UUID) {
        _ = lock.withLock { handlers.removeValue(forKey: token) }
    }

    /// Watching, from the first ask on.
    public func start() {
        #if canImport(Network)
        let begin: Bool = lock.withLock {
            guard !started else { return false }
            started = true
            return true
        }
        guard begin else { return }
        // Its first report is the path as it is at the start, not a change.
        let monitor = NWPathMonitor()
        let first = FirstTime()
        monitor.pathUpdateHandler = { [weak self] _ in
            if first.take() { return }
            self?.changed()
        }
        monitor.start(queue: DispatchQueue(label: "server-kit.network-watch"))
        lock.withLock { self.monitor = monitor }
        #endif
    }

    func changed(settle: Duration = .milliseconds(400)) {
        lock.withLock {
            pending?.cancel()
            pending = Task { [weak self] in
                try? await Task.sleep(for: settle)
                guard !Task.isCancelled, let self else { return }
                let (now, told) = self.lock.withLock { () -> (Int, [@Sendable (Int) -> Void]) in
                    self.count += 1
                    return (self.count, Array(self.handlers.values))
                }
                for handler in told { handler(now) }
            }
        }
    }
}

/// True the first time it's taken, false after.
final class FirstTime: @unchecked Sendable {
    private let lock = NSLock()
    private var taken = false

    func take() -> Bool {
        lock.withLock {
            defer { taken = true }
            return !taken
        }
    }
}
