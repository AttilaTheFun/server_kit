// Several ways to a server tried at once: the first at once, each next its head start after the one before unless one
// has answered (or at once when every one started has failed or run out of time), the first to answer taken and the
// rest cancelled. A way that doesn't answer (one left behind, a network the device isn't on) then costs a moment, not
// its whole timeout, and the order still says which gets its head start.
//
// The winner is given back as soon as it answers. Attempts should end when cancelled; one that doesn't runs on, its
// answer unused, but holds up neither the race's answer nor the next path (past its timeout, it's counted as failed).

public enum PathRace {
    public static let headStart: Duration = .milliseconds(400)

    public struct NoneAnswered: Error, CustomStringConvertible {
        public var errors: [any Error]
        public var description: String {
            errors.isEmpty ? "no way to try" : "no way answered: " + errors.map { "\($0)" }.joined(separator: "; ")
        }
    }

    /// A path that didn't answer in its time.
    public struct TimedOut: Error, CustomStringConvertible {
        public var description: String { "no answer in time" }
    }

    /// The first of `paths` (best first) whose `attempt` succeeds, and its answer: each `headStart` apart.
    public static func first<P: Sendable, T: Sendable>(_ paths: [P], headStart: Duration = PathRace.headStart,
                                                       attempt: @escaping @Sendable (P) async throws -> T) async throws -> (path: P, value: T) {
        try await first(paths, headStart: { _ in headStart }, timeout: { _ in nil }, attempt: attempt)
    }

    /// The first of a server's routes (`PairedServer.routes`) whose `attempt` succeeds, each with its own head start
    /// and timeout.
    public static func first<T: Sendable>(_ routes: [ServerRoute],
                                          attempt: @escaping @Sendable (ServerRoute) async throws -> T) async throws -> (path: ServerRoute, value: T) {
        try await first(routes, headStart: { $0.headStart }, timeout: { $0.timeout }, attempt: attempt)
    }

    /// The first of `paths` (best first) whose `attempt` succeeds within its `timeout` (nil: none), the next starting
    /// `headStart` of the one before after it.
    public static func first<P: Sendable, T: Sendable>(_ paths: [P], headStart: @escaping @Sendable (P) -> Duration,
                                                       timeout: @escaping @Sendable (P) -> Duration?,
                                                       attempt: @escaping @Sendable (P) async throws -> T) async throws -> (path: P, value: T) {
        guard !paths.isEmpty else { throw NoneAnswered(errors: []) }
        let finish = Finish<(path: P, value: T)>()
        let runner = Task {
            do {
                try await race(paths, headStart: headStart, timeout: timeout, attempt: attempt) { won in await finish.end(.success(won)) }
            } catch {
                await finish.end(.failure(error))
            }
        }
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                Task { await finish.wait(continuation) }
            }
        } onCancel: {
            runner.cancel()
            Task { await finish.end(.failure(CancellationError())) }
        }
    }

    private enum Event<T: Sendable>: Sendable {
        case done(Int, Result<T, any Error>)
        case turn(Int)
        case expired(Int)
    }

    /// The race itself: `won` told of the first to answer at once; then it returns once its tasks have all ended.
    private static func race<P: Sendable, T: Sendable>(_ paths: [P], headStart: @escaping @Sendable (P) -> Duration,
                                                       timeout: @escaping @Sendable (P) -> Duration?,
                                                       attempt: @escaping @Sendable (P) async throws -> T,
                                                       won: @Sendable ((path: P, value: T)) async -> Void) async throws {
        try await withThrowingTaskGroup(of: Event<T>.self) { group in
            var started = 0, running = 0
            var over: Set<Int> = []
            var errors: [any Error] = []
            func startNext() {
                let index = started
                started += 1
                running += 1
                let path = paths[index]
                group.addTask {
                    do { return .done(index, .success(try await attempt(path))) } catch { return .done(index, .failure(error)) }
                }
                if let limit = timeout(path) {
                    group.addTask {
                        try? await Task.sleep(for: limit)
                        return .expired(index)
                    }
                }
                if started < paths.count {
                    let wait = headStart(path)
                    group.addTask {
                        try? await Task.sleep(for: wait)
                        return .turn(index)
                    }
                }
            }
            /// One path out (failed, or out of time): the next at once when none is left running.
            func lost(_ index: Int, _ error: any Error) throws {
                guard !over.contains(index) else { return }
                over.insert(index)
                running -= 1
                errors.append(error)
                guard running == 0 else { return }
                if Task.isCancelled { throw CancellationError() }
                guard started < paths.count else { throw NoneAnswered(errors: errors) }
                startNext()
            }
            startNext()
            while let event = try await group.next() {
                switch event {
                case .done(let index, .success(let value)):
                    guard !over.contains(index) else { continue }
                    await won((paths[index], value))
                    group.cancelAll()
                    return
                case .done(let index, .failure(let error)):
                    try lost(index, error)
                case .expired(let index):
                    try lost(index, TimedOut())
                case .turn(let index):
                    // Its head start over, and still no answer: the next beside it.
                    if index == started - 1, started < paths.count, !Task.isCancelled { startNext() }
                }
            }
            if Task.isCancelled { throw CancellationError() }
            throw NoneAnswered(errors: errors)
        }
    }
}

/// A race's answer, given once, to whoever waits for it, whichever comes first.
private actor Finish<R: Sendable> {
    private var waiting: CheckedContinuation<R, any Error>?
    private var result: Result<R, any Error>?

    func wait(_ continuation: CheckedContinuation<R, any Error>) {
        if let result { return continuation.resume(with: result) }
        waiting = continuation
    }

    func end(_ outcome: Result<R, any Error>) {
        guard result == nil else { return }
        result = outcome
        waiting?.resume(with: outcome)
        waiting = nil
    }
}
