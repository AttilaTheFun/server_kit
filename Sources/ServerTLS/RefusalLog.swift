import NIOConcurrencyHelpers
import NIOCore

/// What the front says of the connections it refuses or closes early, kept from flooding: of each kind, one line in
/// `every`, and the next one says how many were left unsaid meanwhile.
final class RefusalLog: Sendable {
    let sink: @Sendable (String) -> Void
    let every: TimeAmount
    private let state = NIOLockedValueBox([String: (last: NIODeadline, unsaid: Int)]())

    init(every: TimeAmount = .seconds(10), _ sink: @escaping @Sendable (String) -> Void) {
        self.sink = sink
        self.every = every
    }

    /// `line` said, unless one of its `kind` was said less than `every` ago (then counted).
    func say(_ kind: String, _ line: @autoclosure () -> String, now: NIODeadline = .now()) {
        let unsaid: Int? = state.withLockedValue { kinds in
            if let seen = kinds[kind], now - seen.last < every {
                kinds[kind] = (seen.last, seen.unsaid + 1)
                return nil
            }
            let unsaid = kinds[kind]?.unsaid ?? 0
            kinds[kind] = (now, 0)
            return unsaid
        }
        guard let unsaid else { return }
        sink(unsaid > 0 ? "\(line()) (and \(unsaid) more like it since the last)" : line())
    }
}
