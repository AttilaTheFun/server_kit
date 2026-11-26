import NetworkCore
import PairingLink

// Reaching a paired server by every address it has, nearest first: its addresses ranked by how they fit where the
// device is now (ServerPaths), tried a moment apart with the first to answer taken (PathRace), and ranked again when
// the device's networks change (NetworkWatch).

public enum ServerPaths {
    /// How an address fits where the device is now, best first.
    public enum Fit: Int, Comparable, Sendable {
        /// This device's own loopback: a server on the same machine.
        case loopback
        /// An address on one of the device's networks (the LAN at home).
        case local
        /// The tailnet (its 100.64/10 addresses, its `*.ts.net` names), while the device is on it.
        case overlay
        /// A `.local` name (or another a home network gives), while the device is on a private network: after the
        /// tailnet, as it may be another network (a café's) whose names don't answer until mDNS gives up.
        case bonjour
        /// Anything else: a public name, a public address, an IPv6 address.
        case other
        /// A tailnet address off the tailnet, a private address on no network of the device's.
        case unlikely

        public static func < (a: Fit, b: Fit) -> Bool { a.rawValue < b.rawValue }
    }

    /// How `address` (a URL's text, or a bare host) fits.
    public static func fit(of address: String, network: NetworkInterfaces) -> Fit {
        guard let raw = PairingHost.host(of: address) else { return .unlikely }
        var host = raw.lowercased()
        if host.hasPrefix("["), host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
        if host.hasSuffix(".") { host = String(host.dropLast()) }
        if host == "localhost" || host == "::1" { return .loopback }
        if let value = IPv4.parse(host) {
            if IPv4.isLoopback(value) { return .loopback }
            // The tailnet's addresses are the tailnet's, whatever mask its interface has.
            if IPv4.isTailnet(value) { return network.hasTailnet ? .overlay : .unlikely }
            if network.isOnLocalNetwork(host) { return .local }
            return IPv4.isPrivate(value) ? .unlikely : .other
        }
        if host.contains(":") { return .other }
        if host.hasSuffix(".ts.net") { return network.hasTailnet ? .overlay : .unlikely }
        if host.hasSuffix(".local") || host.hasSuffix(".lan") || host.hasSuffix(".home.arpa") || host.hasSuffix(".home")
            || !host.contains(".") {
            return network.hasLAN ? .bonjour : .unlikely
        }
        return .other
    }

    /// `addresses` best first: by fit, the one that answered last (`lastGood`) first among its equals, the rest in
    /// their order; each once.
    public static func ranked(_ addresses: [String], network: NetworkInterfaces, lastGood: String? = nil) -> [String] {
        var unique: [String] = []
        for address in addresses where !unique.contains(address) { unique.append(address) }
        return unique.enumerated().sorted { a, b in
            let fa = fit(of: a.element, network: network), fb = fit(of: b.element, network: network)
            if fa != fb { return fa < fb }
            let la = a.element == lastGood, lb = b.element == lastGood
            if la != lb { return la }
            return a.offset < b.offset
        }.map(\.element)
    }
}

/// A host read out of an address: a URL's (`https://host:port/…`) or a bare one's (`user@host:22`).
enum PairingHost {
    static func host(of address: String) -> String? {
        PairingLink.host(of: address) ?? PairingLink.pathHost(of: address)
    }
}

/// Several addresses tried at once: the first at once, each next `headStart` after the one before unless one has
/// answered (or at once when every one started has failed), the first to answer taken and the rest cancelled. An
/// address that doesn't answer (one left behind, a network the device isn't on) then costs a moment, not its whole
/// timeout, and the order still says which gets its head start.
public enum PathRace {
    public static let headStart: Duration = .milliseconds(400)

    public struct NoneAnswered: Error, CustomStringConvertible {
        public var errors: [any Error]
        public var description: String {
            errors.isEmpty ? "no address to try" : "no address answered: " + errors.map { "\($0)" }.joined(separator: "; ")
        }
    }

    private enum Event<T: Sendable>: Sendable {
        case done(Int, Result<T, any Error>)
        case turn(Int)
    }

    /// The first of `paths` (best first) whose `attempt` succeeds, and its answer.
    public static func first<P: Sendable, T: Sendable>(_ paths: [P], headStart: Duration = PathRace.headStart,
                                                       attempt: @escaping @Sendable (P) async throws -> T) async throws -> (path: P, value: T) {
        guard !paths.isEmpty else { throw NoneAnswered(errors: []) }
        return try await withThrowingTaskGroup(of: Event<T>.self) { group in
            var started = 0, running = 0
            var errors: [any Error] = []
            func startNext() {
                let index = started
                started += 1
                running += 1
                let path = paths[index]
                group.addTask {
                    do { return .done(index, .success(try await attempt(path))) } catch { return .done(index, .failure(error)) }
                }
                if started < paths.count {
                    group.addTask {
                        try? await Task.sleep(for: headStart)
                        return .turn(index)
                    }
                }
            }
            startNext()
            while let event = try await group.next() {
                switch event {
                case .done(let index, .success(let value)):
                    group.cancelAll()
                    return (paths[index], value)
                case .done(_, .failure(let error)):
                    running -= 1
                    errors.append(error)
                    if running == 0 {
                        guard started < paths.count else { throw NoneAnswered(errors: errors) }
                        startNext()
                    }
                case .turn(let index):
                    // Its head start over, and still no answer: the next beside it.
                    if index == started - 1, started < paths.count, !Task.isCancelled { startNext() }
                }
            }
            throw NoneAnswered(errors: errors)
        }
    }
}
