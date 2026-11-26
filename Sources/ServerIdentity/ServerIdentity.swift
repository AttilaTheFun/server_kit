#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(Android)
import Android
#endif
import Crypto
import Foundation
import NetworkCore
import PairingLink
import ServerAddresses
import SwiftASN1
import X509

// A server's own TLS identity, for every name no CA vouches for (its LAN addresses, its `.local` name): a certificate
// it makes itself, ECDSA P-256, self-signed, made once and kept. Clients trust it by its pins (PinSet), carried in the
// pairing link and in what the server says of itself over TLS; so it needn't name the addresses it's reached at (they
// move, its pins mustn't). It names those it was made at, and its `.local` name, for a person reading it.
//
// Or an identity supplied (a company's certificate and its key): served as it is, pinned the same way.

/// A certificate chain and its key (PEM), and the pins a client trusts it by.
public struct ServerIdentity: Sendable, Equatable {
    /// The chain, leaf first (PEM).
    public let chain: String
    /// The leaf's private key (PEM).
    public let key: String
    /// The leaf's SubjectPublicKeyInfo pin, then its whole certificate's.
    public let pins: PinSet
    /// The SubjectPublicKeyInfo pin: what survives the certificate being made again for the same key.
    public let spkiPin: Pin

    /// Twenty years: it's trusted by its pins, not its dates, and a new key would unpair every device.
    public static let lifetime: TimeInterval = 20 * 365 * 24 * 3600

    /// An identity from a chain and its key, both PEM: one kept, or one supplied. Throws if the chain has no
    /// certificate, the key can't be read, or the key isn't the leaf certificate's.
    public init(chain: String, key: String) throws {
        let certificates = PEM.blocks(in: chain, kind: "CERTIFICATE")
        guard !certificates.isEmpty else { throw IdentityError("the chain has no PEM certificate") }
        try self.init(certificateDERs: certificates.map { try PEMDocument(pemString: $0).derBytes }, privateKeyPEM: key, chainPEM: chain)
    }

    /// An identity from DER certificates (leaf first) and its key (PEM).
    public init(certificateDERs: [[UInt8]], privateKeyPEM: String) throws {
        let chain = try certificateDERs.map { der -> String in
            try PEMDocument(type: "CERTIFICATE", derBytes: der).pemString + "\n"
        }.joined()
        try self.init(certificateDERs: certificateDERs, privateKeyPEM: privateKeyPEM, chainPEM: chain)
    }

    private init(certificateDERs: [[UInt8]], privateKeyPEM key: String, chainPEM chain: String) throws {
        guard let leafDER = certificateDERs.first else { throw IdentityError("there's no certificate") }
        let leaf = try Certificate(derEncoded: leafDER)
        guard let privateKey = try? Certificate.PrivateKey(pemEncoded: key) else {
            throw IdentityError("the key isn't a PEM private key this reads")
        }
        // A key that isn't the certificate's would be served and fail every handshake: refused here instead.
        guard privateKey.publicKey == leaf.publicKey else { throw IdentityError("the key isn't the certificate's") }
        let pins = try Self.pins(ofCertificateDER: leafDER)
        self.chain = chain
        self.key = key
        self.pins = pins
        self.spkiPin = pins.pins[0]
    }

    /// A new one, named for a person to read: `commonName` (`"Example on mac.local"`), `organization`, and its
    /// subject alternative names `dnsNames` and `ipv4` (dotted).
    public static func make(commonName: String, organization: String? = nil, dnsNames: [String], ipv4: [String] = [],
                            now: Date = Date()) throws -> ServerIdentity {
        let key = P256.Signing.PrivateKey()
        let name: DistinguishedName
        if let organization {
            name = try DistinguishedName {
                CommonName(commonName)
                OrganizationName(organization)
            }
        } else {
            name = try DistinguishedName { CommonName(commonName) }
        }
        var names: [GeneralName] = dnsNames.map { .dnsName($0) }
        for address in ipv4 {
            guard let value = IPv4.parse(address) else { continue }
            let bytes: [UInt8] = [UInt8(value >> 24), UInt8(value >> 16 & 0xFF), UInt8(value >> 8 & 0xFF), UInt8(value & 0xFF)]
            names.append(.ipAddress(ASN1OctetString(contentBytes: ArraySlice(bytes))))
        }
        let extensions = try Certificate.Extensions {
            Critical(BasicConstraints.notCertificateAuthority)
            Critical(KeyUsage(digitalSignature: true))
            try ExtendedKeyUsage([.serverAuth])
            SubjectAlternativeNames(names)
        }
        let certificate = try Certificate(
            version: .v3, serialNumber: Certificate.SerialNumber(), publicKey: .init(key.publicKey),
            notValidBefore: now.addingTimeInterval(-3600), notValidAfter: now.addingTimeInterval(lifetime),
            issuer: name, subject: name, signatureAlgorithm: .ecdsaWithSHA256, extensions: extensions,
            issuerPrivateKey: .init(key))
        return try ServerIdentity(chain: try certificate.serializeAsPEM().pemString + "\n", key: key.pemRepresentation + "\n")
    }

    /// For a server at `addresses` (LocalAddresses): its `.local` name and LAN addresses named.
    public static func make(product: String, addresses: LocalAddresses, now: Date = Date()) throws -> ServerIdentity {
        let host = addresses.bonjour ?? "localhost"
        return try make(commonName: "\(product) on \(host)", organization: product, dnsNames: [host], ipv4: addresses.lan, now: now)
    }

    /// A certificate's pins, from its DER: the SHA-256 of its SubjectPublicKeyInfo as the certificate encodes it
    /// (`spki`), then of the whole certificate (`certificate`). What a server says of its identity, and what a client
    /// computes of the certificate it's shown, by the same code; no store needed.
    public static func pins(ofCertificateDER der: [UInt8]) throws -> PinSet {
        let spki = try subjectPublicKeyInfo(ofCertificateDER: der)
        return PinSet([Pin(.spki, sha256: hex(SHA256.hash(data: spki)))!,
                       Pin(.certificate, sha256: hex(SHA256.hash(data: der)))!])
    }

    /// A certificate's SubjectPublicKeyInfo, its own bytes (not a re-encoding: a key encoded another way, a compressed
    /// point, keeps its own pin): Certificate → TBSCertificate → the field after the subject.
    static func subjectPublicKeyInfo(ofCertificateDER der: [UInt8]) throws -> ArraySlice<UInt8> {
        let root = try DER.parse(der)
        guard case .constructed(let certificate) = root.content, let tbs = certificate.first(where: { _ in true }),
              case .constructed(let fields) = tbs.content else { throw IdentityError("not a certificate") }
        var rest = Array(fields)
        // An explicit version ([0]) first, when there is one.
        if let first = rest.first, first.identifier.tagClass == .contextSpecific, first.identifier.tagNumber == 0 { rest.removeFirst() }
        // serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo.
        guard rest.count > 5 else { throw IdentityError("a certificate with no public key") }
        return rest[5].encodedBytes
    }

    static func hex<D: Sequence>(_ digest: D) -> String where D.Element == UInt8 {
        let digits = Array("0123456789abcdef")
        return digest.map { String(digits[Int($0 >> 4)]) + String(digits[Int($0 & 0xF)]) }.joined()
    }
}

/// Where a server keeps its identity: the key is a secret (an app's Keychain, a file only its owner reads). `read`
/// says what's there: nothing (nil, never made), or both; it throws when it can't tell (a locked Keychain, a file it
/// can't read), so a failure is never taken for nothing and a new key made over the old.
public protocol IdentityStore: Sendable {
    func read() throws -> (chain: String, key: String)?
    func write(chain: String, key: String) throws
}

extension ServerIdentity {
    /// The one kept in `store`; else, when nothing is kept, `make()`'s, kept there. `kept` tells which: a new one
    /// unpairs every device's pinned addresses until they learn its pins again over a trusted connection, so a server
    /// says when it makes one. Throws when the store can't be read, or what it holds isn't an identity: never a new
    /// key over one it couldn't read.
    public static func ensure(in store: any IdentityStore, make: () throws -> ServerIdentity) throws -> (identity: ServerIdentity, kept: Bool) {
        if let kept = try store.read() {
            return (try ServerIdentity(chain: kept.chain, key: kept.key), true)
        }
        let made = try make()
        try store.write(chain: made.chain, key: made.key)
        return (made, false)
    }
}

/// One file, `<name>.pem`: the chain and the key together, so they can't come apart, readable by its owner alone
/// (0600). Written whole or not at all: a new file made with that mode from the start, synced, and renamed over the
/// old one.
public struct FileIdentityStore: IdentityStore {
    public let folder: String
    public let name: String

    public init(folder: String, name: String = "server") {
        self.folder = folder
        self.name = name
    }

    public var path: String { "\(folder)/\(name).pem" }

    public func read() throws -> (chain: String, key: String)? {
        guard FileManager.default.fileExists(atPath: path) else { return nil }
        guard let data = FileManager.default.contents(atPath: path) else { throw IdentityError("\(path) can't be read") }
        let text = String(decoding: data, as: UTF8.self)
        let chain = PEM.blocks(in: text, kind: "CERTIFICATE").joined(separator: "\n")
        guard !chain.isEmpty, let key = PEM.privateKey(in: text) else { throw IdentityError("\(path) holds no certificate and key") }
        return (chain + "\n", key + "\n")
    }

    public func write(chain: String, key: String) throws {
        try FileManager.default.createDirectory(atPath: folder, withIntermediateDirectories: true)
        try AtomicFile.store(Array((chain + key).utf8), at: path, mode: 0o600)
    }
}

/// A file written whole: a new one beside it (O_CREAT | O_EXCL, its mode from the start), synced, and renamed over it.
enum AtomicFile {
    static func store(_ bytes: [UInt8], at path: String, mode: mode_t) throws {
        let temporary = path + ".partial-\(getpid())"
        unlink(temporary)
        let descriptor = open(temporary, O_WRONLY | O_CREAT | O_EXCL, mode)
        guard descriptor >= 0 else { throw IdentityError("\(temporary) couldn't be made") }
        var written = 0
        let ok = bytes.withUnsafeBytes { buffer -> Bool in
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
            throw IdentityError("\(path) couldn't be written")
        }
    }
}

public struct IdentityError: Error, CustomStringConvertible {
    public let description: String
    init(_ description: String) { self.description = description }
}

/// PEM blocks, in order.
enum PEM {
    static func blocks(in text: String, kind: String) -> [String] {
        let begin = "-----BEGIN \(kind)-----", end = "-----END \(kind)-----"
        var blocks: [String] = []
        var rest = Substring(text)
        while let start = rest.firstRange(of: begin), let stop = rest[start.upperBound...].firstRange(of: end) {
            blocks.append(String(rest[start.lowerBound..<stop.upperBound]))
            rest = rest[stop.upperBound...]
        }
        return blocks
    }

    /// The first private key, of any kind (`PRIVATE KEY`, `EC PRIVATE KEY`, `RSA PRIVATE KEY`).
    static func privateKey(in text: String) -> String? {
        for kind in ["PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY"] {
            if let first = blocks(in: text, kind: kind).first { return first }
        }
        return nil
    }
}
