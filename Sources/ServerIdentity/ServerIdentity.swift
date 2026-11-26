import Crypto
import Foundation
import PairingLink
import ServerAddresses
import SwiftASN1
import X509

// A server's own TLS identity, for every name no CA vouches for (its LAN addresses, its `.local` name): a certificate
// it makes itself, ECDSA P-256, self-signed, made once and kept. Clients trust it by its pins (PinSet), carried in the
// pairing link and in what the server says of itself over TLS; so it needn't name the addresses it's reached at (they
// move, its pins mustn't). It names those it was made at, and its `.local` name, for a person reading it.
//
// Or an identity supplied (a company's certificate, its key): served as it is, pinned the same way.

/// A certificate chain and its key (PEM), and the pins a client trusts it by.
public struct ServerIdentity: Sendable, Equatable {
    /// The chain, leaf first (PEM).
    public var chain: String
    /// The leaf's private key (PEM).
    public var key: String
    /// The leaf's SubjectPublicKeyInfo pin and its whole certificate's: `pins.pins[0]` the SPKI's.
    public var pins: PinSet

    /// Twenty years: it's trusted by its pins, not its dates, and a new key would unpair every device.
    public static let lifetime: TimeInterval = 20 * 365 * 24 * 3600

    /// An identity from a chain and its key, both PEM: one kept, or one supplied. Throws if the chain's leaf isn't a
    /// certificate, or the key can't be read.
    public init(chain: String, key: String) throws {
        guard let leaf = PEMBlocks.first(in: chain, kind: "CERTIFICATE") else {
            throw IdentityError("the chain has no PEM certificate")
        }
        guard (try? P256.Signing.PrivateKey(pemRepresentation: key)) != nil || (try? Certificate.PrivateKey(pemEncoded: key)) != nil else {
            throw IdentityError("the key isn't a PEM private key this reads")
        }
        self.chain = chain
        self.key = key
        self.pins = try Self.pins(ofCertificateDER: try PEMDocument(pemString: leaf).derBytes)
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
            guard let value = IPv4Text.parse(address) else { continue }
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

    /// A certificate's pins, from its DER: its SubjectPublicKeyInfo's SHA-256 (`spki`) and its own (`certificate`). What
    /// a server says of its identity, and what a client computes of the certificate it's shown, by the same code.
    public static func pins(ofCertificateDER der: [UInt8]) throws -> PinSet {
        let certificate = try Certificate(derEncoded: der)
        var serializer = DER.Serializer()
        try serializer.serialize(certificate.publicKey)
        return PinSet([Pin(.spki, sha256: hex(SHA256.hash(data: serializer.serializedBytes)))!,
                       Pin(.certificate, sha256: hex(SHA256.hash(data: der)))!])
    }

    /// The SPKI pin alone.
    public var spkiPin: Pin { pins.pins.first { $0.kind == .spki }! }

    static func hex<D: Sequence>(_ digest: D) -> String where D.Element == UInt8 {
        digest.map { byte in
            let digits = Array("0123456789abcdef")
            return String(digits[Int(byte >> 4)]) + String(digits[Int(byte & 0xF)])
        }.joined()
    }
}

/// Where a server keeps its identity: the certificate is no secret, the key is (an app's Keychain, a file only its
/// owner reads). Each is read and written whole.
public protocol IdentityStore: Sendable {
    func readCertificate() -> String?
    func readKey() -> String?
    func write(certificate: String, key: String) throws
}

extension ServerIdentity {
    /// The one kept in `store`, else `make()`'s, kept there; `kept` tells which (a new one unpairs every device's
    /// pinned addresses until they learn its pins again over a trusted connection, so a server says when it makes one).
    public static func ensure(in store: any IdentityStore, make: () throws -> ServerIdentity) throws -> (identity: ServerIdentity, kept: Bool) {
        if let chain = store.readCertificate(), let key = store.readKey(), let kept = try? ServerIdentity(chain: chain, key: key) {
            return (kept, true)
        }
        let made = try make()
        try store.write(certificate: made.chain, key: made.key)
        return (made, false)
    }
}

/// A folder's files, `<name>.crt` (0644) and `<name>.key` (0600): a store for a server with no secret store of its own.
public struct FileIdentityStore: IdentityStore {
    public var folder: String
    public var name: String

    public init(folder: String, name: String = "server") {
        self.folder = folder
        self.name = name
    }

    var certificateFile: String { "\(folder)/\(name).crt" }
    var keyFile: String { "\(folder)/\(name).key" }

    public func readCertificate() -> String? { FileManager.default.contents(atPath: certificateFile).map { String(decoding: $0, as: UTF8.self) } }
    public func readKey() -> String? { FileManager.default.contents(atPath: keyFile).map { String(decoding: $0, as: UTF8.self) } }

    public func write(certificate: String, key: String) throws {
        try FileManager.default.createDirectory(atPath: folder, withIntermediateDirectories: true)
        for (path, contents, mode) in [(keyFile, key, 0o600), (certificateFile, certificate, 0o644)] {
            try? FileManager.default.removeItem(atPath: path)
            guard FileManager.default.createFile(atPath: path, contents: Data(contents.utf8), attributes: [.posixPermissions: mode]) else {
                throw IdentityError("\(path) couldn't be written")
            }
        }
    }
}

public struct IdentityError: Error, CustomStringConvertible {
    public var description: String
    init(_ description: String) { self.description = description }
}

/// PEM blocks of a kind, in order.
public enum PEMBlocks {
    public static func all(in text: String, kind: String) -> [String] {
        let begin = "-----BEGIN \(kind)-----", end = "-----END \(kind)-----"
        var blocks: [String] = []
        var rest = Substring(text)
        while let start = rest.firstRange(of: begin), let stop = rest[start.upperBound...].firstRange(of: end) {
            blocks.append(String(rest[start.lowerBound..<stop.upperBound]))
            rest = rest[stop.upperBound...]
        }
        return blocks
    }

    public static func first(in text: String, kind: String) -> String? { all(in: text, kind: kind).first }
}
