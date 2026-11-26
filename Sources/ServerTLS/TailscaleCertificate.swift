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

    var chainFile: URL { folder.appendingPathComponent(name + ".crt") }
    var keyFile: URL { folder.appendingPathComponent(name + ".key") }

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
            try keep(chain: chain, key: key)
        } catch {
            return .failure(Failure("can't keep the certificate in \(folder.path): \(error)"))
        }
        return .success(PEMPair(chain: chain, key: key))
    }

    /// The pair kept from the last time Tailscale gave it, if any.
    public func kept() -> PEMPair? {
        guard let chain = try? String(contentsOf: chainFile, encoding: .utf8), chain.contains("BEGIN CERTIFICATE"),
              let key = try? String(contentsOf: keyFile, encoding: .utf8), key.contains("PRIVATE KEY") else { return nil }
        return PEMPair(chain: chain, key: key)
    }

    func keep(chain: String, key: String) throws {
        let files = FileManager.default
        try files.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        // 0700 whatever made it; the key's file 0600 from the moment it's made (written beside, then moved in).
        try files.setAttributes([.posixPermissions: 0o700], ofItemAtPath: folder.path)
        try Data(chain.utf8).write(to: chainFile, options: .atomic)
        let fresh = folder.appendingPathComponent(".\(name).key.\(UUID().uuidString)")
        guard files.createFile(atPath: fresh.path, contents: Data(key.utf8), attributes: [.posixPermissions: 0o600]) else {
            throw Failure("the key's file couldn't be made")
        }
        guard rename(fresh.path, keyFile.path) == 0 else {
            let code = errno
            try? files.removeItem(at: fresh)
            throw Failure("the key's file couldn't be moved in: \(String(cString: strerror(code)))")
        }
        let mode = (try files.attributesOfItem(atPath: keyFile.path)[.posixPermissions] as? NSNumber)?.intValue
        guard mode == 0o600 else { throw Failure("the key's file is \(String(mode ?? 0, radix: 8)), not 600") }
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

    /// Runs a program, both its outputs read as they come (one read to its end before the other could block on a full
    /// pipe), stopped after `timeout`.
    static func run(_ tool: String, _ arguments: [String], environment: [String: String], timeout: Duration) async throws -> Ran {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: tool)
        process.arguments = arguments
        process.environment = environment
        process.standardInput = FileHandle.nullDevice
        let out = Pipe(), err = Pipe()
        process.standardOutput = out
        process.standardError = err
        let exited = AsyncStream<Void> { continuation in
            process.terminationHandler = { _ in continuation.yield(); continuation.finish() }
        }
        try process.run()
        async let output = Task.detached { out.fileHandleForReading.readDataToEndOfFile() }.value
        async let error = Task.detached { err.fileHandleForReading.readDataToEndOfFile() }.value
        let watchdog = Task {
            try await Task.sleep(for: timeout)
            if process.isRunning { process.terminate() }
        }
        for await _ in exited {}
        watchdog.cancel()
        let (o, e) = await (output, error)
        return Ran(status: process.terminationStatus, output: String(decoding: o, as: UTF8.self), error: String(decoding: e, as: UTF8.self))
    }
}
#endif
