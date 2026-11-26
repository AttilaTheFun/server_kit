#if !os(iOS) && !os(tvOS) && !os(watchOS) && !os(visionOS)
import Foundation

// A tailnet's certificate for a server's TLS front: asked of Tailscale's own command (`tailscale cert`), which gets it
// from Let's Encrypt and renews it as it nears its end (it lasts 90 days). Ask at the start and twice a day, and give
// the front the new pair (`TLSFront.use`); serve the kept copies when Tailscale can't be asked.

public struct TailscaleCertificate: Sendable {
    /// The machine's name on the tailnet (`mac.example.ts.net`).
    public let name: String
    /// Where the chain and key are kept: `<folder>/tailscale`, the folder and key readable by this user alone.
    public let folder: URL
    /// Tailscale's command, where it is on this computer.
    let tool: String

    /// Where Tailscale's command is found: Homebrew's or the open-source build's, the Mac App Store app's own, Linux's.
    public static let places = ["/usr/local/bin/tailscale", "/opt/homebrew/bin/tailscale",
                                "/Applications/Tailscale.app/Contents/MacOS/Tailscale", "/usr/bin/tailscale"]

    /// Nil for a name that isn't one, or where Tailscale isn't installed.
    public init?(name: String, folder: URL, tool: String? = Self.places.first { FileManager.default.isExecutableFile(atPath: $0) }) {
        guard Self.isName(name), let tool else { return nil }
        self.name = name
        self.folder = folder.appendingPathComponent("tailscale", isDirectory: true)
        self.tool = tool
    }

    /// A machine's full name on a tailnet: letters, digits, hyphens and dots, ending in `.ts.net`.
    public static func isName(_ name: String) -> Bool {
        name.hasSuffix(".ts.net") && name.count > 7 && !name.hasPrefix("-") && !name.hasPrefix(".")
            && name.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == ".") }
    }

    /// The chain and its key, in one file (never one renewed without the other), readable by this user alone.
    var file: URL { folder.appendingPathComponent(name + ".pem") }

    public struct Failure: Error, CustomStringConvertible {
        public let description: String
        public init(_ description: String) { self.description = description }
    }

    /// The pair as Tailscale has it now (renewed by it if it was near its end), kept, or why not. Tailscale writes it to
    /// its standard output, not to files: the Mac App Store's Tailscale is sandboxed and can't write where a server
    /// keeps them.
    public func refresh(timeout: Duration = .seconds(60)) async -> Result<PEMPair, Failure> {
        let ran: Ran
        do {
            ran = try await Self.run(tool, ["cert", "--cert-file=-", "--key-file=-", "--", name],
                                     environment: Self.environment(ProcessInfo.processInfo.environment), timeout: timeout)
        } catch {
            return .failure(Failure("\(tool) won't run: \(error)"))
        }
        guard ran.status == 0 else {
            return .failure(Failure("tailscale cert \(name): exit \(ran.status): \(Self.trimmed(ran.error).prefix(300))"))
        }
        let chain = Self.blocks(in: ran.output, kind: "CERTIFICATE").joined()
        guard !chain.isEmpty, let key = Self.blocks(in: ran.output, kind: "PRIVATE KEY").first else {
            // What it printed instead, when that holds no PEM block (so no key): how it failed is in it.
            let shown = ran.output.contains("-----BEGIN") ? "" : "; it printed: \(Self.trimmed(ran.output).prefix(300))"
            let said = Self.trimmed(ran.error)
            return .failure(Failure("tailscale cert \(name) printed no certificate and key (\(ran.output.utf8.count) bytes out\(shown)"
                + (said.isEmpty ? ")" : "; on its errors: \(said.prefix(300)))")))
        }
        do {
            try PEMPair(chain: chain, key: key).check(now: Date())
        } catch {
            return .failure(Failure("tailscale cert \(name) gave a pair that won't serve: \(error)"))
        }
        do {
            try keep(chain: chain, key: key)
        } catch {
            return .failure(Failure("can't keep the certificate in \(folder.path): \(error)"))
        }
        return .success(PEMPair(chain: chain, key: key))
    }

    /// The pair kept from the last time Tailscale gave it, if it's still good: a chain whose leaf the key is for, not
    /// yet past its end.
    public func kept(now: Date = Date()) -> PEMPair? {
        guard let text = try? String(contentsOf: file, encoding: .utf8) else { return nil }
        let chain = Self.blocks(in: text, kind: "CERTIFICATE").joined()
        guard !chain.isEmpty, let key = Self.blocks(in: text, kind: "PRIVATE KEY").first else { return nil }
        let pair = PEMPair(chain: chain, key: key)
        guard (try? pair.check(now: now)) != nil else { return nil }
        return pair
    }

    func keep(chain: String, key: String) throws {
        let files = FileManager.default
        try files.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        // 0700 whatever made it; the file 0600 from the moment it's made (written beside, then moved in whole).
        try files.setAttributes([.posixPermissions: 0o700], ofItemAtPath: folder.path)
        let fresh = folder.appendingPathComponent(".\(name).pem.\(UUID().uuidString)")
        guard files.createFile(atPath: fresh.path, contents: Data((chain + key).utf8), attributes: [.posixPermissions: 0o600]) else {
            throw Failure("the certificate's file couldn't be made")
        }
        guard rename(fresh.path, file.path) == 0 else {
            let code = errno
            try? files.removeItem(at: fresh)
            throw Failure("the certificate's file couldn't be moved in: \(String(cString: strerror(code)))")
        }
        let mode = (try files.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber)?.intValue
        guard mode == 0o600 else { throw Failure("the certificate's file is \(String(mode ?? 0, radix: 8)), not 600") }
    }

    /// The environment Tailscale's command runs in: the given one, with what a launchd job may lack and a login shell
    /// has (HOME, USER, a PATH beyond the system's).
    static func environment(_ given: [String: String]) -> [String: String] {
        var environment = given
        // Tailscale.app's binary, started by another app's process, starts its GUI and fails unless told it's the
        // command line.
        environment["TAILSCALE_BE_CLI"] = "true"
        if (environment["HOME"] ?? "").isEmpty { environment["HOME"] = NSHomeDirectory() }
        let user = NSUserName()
        if (environment["USER"] ?? "").isEmpty, !user.isEmpty { environment["USER"] = user }
        if (environment["LOGNAME"] ?? "").isEmpty, !user.isEmpty { environment["LOGNAME"] = user }
        let path = environment["PATH"] ?? "/usr/bin:/bin:/usr/sbin:/sbin"
        let more = ["/usr/local/bin", "/opt/homebrew/bin"].filter { !path.split(separator: ":").contains(Substring($0)) }
        environment["PATH"] = (more + [path]).joined(separator: ":")
        return environment
    }

    /// The PEM blocks of a kind (`CERTIFICATE`, or any `… PRIVATE KEY`) in text, in order, each ending in a newline:
    /// found by their markers, wherever lines break.
    static func blocks(in text: String, kind: String) -> [String] {
        var found: [String] = []
        var rest = text[...]
        while let begin = rest.range(of: "-----BEGIN ") {
            guard let close = rest[begin.upperBound...].range(of: "-----") else { break }
            let label = rest[begin.upperBound..<close.lowerBound]
            guard let end = rest[close.upperBound...].range(of: "-----END \(label)-----") else { break }
            if label == kind || (kind == "PRIVATE KEY" && label.hasSuffix(" PRIVATE KEY")) {
                found.append(String(rest[begin.lowerBound..<end.upperBound]) + "\n")
            }
            rest = rest[end.upperBound...]
        }
        return found
    }

    static func trimmed(_ text: String) -> String { text.trimmingCharacters(in: .whitespacesAndNewlines) }

    struct Ran {
        var status: Int32
        var output: String
        var error: String
    }

    /// Runs a program in a process group of its own, both its outputs read as they come (one read to its end before
    /// the other could block on a full pipe), stopped after `timeout`: the whole group asked to (TERM), then, 5 seconds
    /// on, made to (KILL), so nothing it started is left holding its pipes or the answer.
    static func run(_ tool: String, _ arguments: [String], environment: [String: String], timeout: Duration) async throws -> Ran {
        let child = try Spawned(tool, arguments, environment: environment)
        let watchdog = Task {
            try await Task.sleep(for: timeout)
            guard !child.exited else { return }
            kill(-child.pid, SIGTERM)
            try await Task.sleep(for: .seconds(5))
            if !child.exited { kill(-child.pid, SIGKILL) }
        }
        let output = Task { await Spawned.readAll(child.output) }
        let error = Task { await Spawned.readAll(child.error) }
        let status = await child.wait()
        watchdog.cancel()
        // Exited, but something it started may still hold the pipes: a moment's grace, then its group stopped (its
        // group lives while any of it does, so the number names no one else's).
        let read = Task { _ = (await output.value, await error.value) }
        let grace = Task {
            try await Task.sleep(for: .milliseconds(500))
            kill(-child.pid, SIGKILL)
        }
        await read.value
        grace.cancel()
        let (o, e) = (await output.value, await error.value)
        return Ran(status: status, output: String(decoding: o, as: UTF8.self), error: String(decoding: e, as: UTF8.self))
    }

    /// A program started with posix_spawn in a new process group, its standard output and error on pipes.
    final class Spawned: @unchecked Sendable {
        let pid: pid_t
        let output: Int32
        let error: Int32
        private let lock = NSLock()
        private var done = false

        var exited: Bool { lock.withLock { done } }

        struct Failure: Error, CustomStringConvertible {
            var description: String
        }

        init(_ tool: String, _ arguments: [String], environment: [String: String]) throws {
            var out: [Int32] = [0, 0], err: [Int32] = [0, 0]
            guard pipe(&out) == 0 else { throw Failure(description: "no pipe: \(String(cString: strerror(errno)))") }
            guard pipe(&err) == 0 else {
                close(out[0]); close(out[1])
                throw Failure(description: "no pipe: \(String(cString: strerror(errno)))")
            }
            #if canImport(Darwin)
            var actions: posix_spawn_file_actions_t?
            var attributes: posix_spawnattr_t?
            #else
            var actions = posix_spawn_file_actions_t()
            var attributes = posix_spawnattr_t()
            #endif
            posix_spawn_file_actions_init(&actions)
            posix_spawnattr_init(&attributes)
            defer {
                posix_spawn_file_actions_destroy(&actions)
                posix_spawnattr_destroy(&attributes)
            }
            posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0)
            posix_spawn_file_actions_adddup2(&actions, out[1], 1)
            posix_spawn_file_actions_adddup2(&actions, err[1], 2)
            // Nothing else of this process's goes with it (its listeners, its clients' sockets): only 0, 1 and 2.
            #if canImport(Darwin)
            posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT))
            #else
            posix_spawn_file_actions_addclosefrom_np(&actions, 3)
            posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETPGROUP))
            #endif
            posix_spawnattr_setpgroup(&attributes, 0)
            let argv = ([tool] + arguments).map { strdup($0) } + [nil]
            let envp = environment.map { strdup("\($0.key)=\($0.value)") } + [nil]
            defer {
                for pointer in argv { free(pointer) }
                for pointer in envp { free(pointer) }
            }
            var pid: pid_t = 0
            let spawned = posix_spawn(&pid, tool, &actions, &attributes, argv, envp)
            close(out[1])
            close(err[1])
            guard spawned == 0 else {
                close(out[0]); close(err[0])
                throw Failure(description: String(cString: strerror(spawned)))
            }
            self.pid = pid
            output = out[0]
            error = err[0]
        }

        /// Its exit status (a signal's number for one killed by a signal), once it has exited.
        func wait() async -> Int32 {
            let pid = pid
            let status = await Task.detached { () -> Int32 in
                var status: Int32 = 0
                while waitpid(pid, &status, 0) == -1 && errno == EINTR {}
                return status
            }.value
            lock.withLock { done = true }
            // WIFEXITED / WEXITSTATUS, WTERMSIG, by hand (they're macros).
            let signal = status & 0x7F
            return signal == 0 ? (status >> 8) & 0xFF : signal
        }

        /// Everything read from `fd` to its end; it's closed after.
        static func readAll(_ fd: Int32) async -> [UInt8] {
            await Task.detached { () -> [UInt8] in
                var bytes: [UInt8] = []
                var chunk = [UInt8](repeating: 0, count: 16_384)
                while true {
                    let count = chunk.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
                    if count > 0 { bytes += chunk[0..<count] } else if count == -1 && errno == EINTR { continue } else { break }
                }
                close(fd)
                return bytes
            }.value
        }
    }
}
#endif
