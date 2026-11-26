import Crypto
import Foundation
import PairingLink
import ServerAddresses
import SwiftASN1
import Testing
import X509
@testable import ServerIdentity

@Test func aServersIdentityIsMadeAndPinnedTwoWays() throws {
    let identity = try ServerIdentity.make(product: "Example", addresses: LocalAddresses(lan: ["192.168.1.5"], tailnet: [], bonjour: "mac.local"))
    #expect(identity.chain.hasPrefix("-----BEGIN CERTIFICATE-----") && identity.key.contains("PRIVATE KEY"))
    #expect(identity.pins.pins.map(\.kind) == [.spki, .certificate] && identity.spkiPin == identity.pins.pins[0])
    #expect(try ServerIdentity(chain: identity.chain, key: identity.key).pins == identity.pins, "read again from its PEM")
    // A client's view: the pins it computes of the certificate it's shown match.
    let der = try PEMDocument(pemString: PEM.blocks(in: identity.chain, kind: "CERTIFICATE")[0]).derBytes
    let shown = try ServerIdentity.pins(ofCertificateDER: der)
    let spki = shown.pins.first { $0.kind == .spki }!.sha256, whole = shown.pins.first { $0.kind == .certificate }!.sha256
    #expect(PinTrust.decide(host: "192.168.1.5", pins: identity.pins, spki: spki, certificate: whole) == .accept)
    // From DER too.
    #expect(try ServerIdentity(certificateDERs: [der], privateKeyPEM: identity.key).pins == identity.pins)
}

@Test func anSPKIPinIsOfTheCertificatesOwnBytesAndOutlivesIt() throws {
    let first = try ServerIdentity.make(commonName: "A", dnsNames: ["a.local"], now: Date(timeIntervalSince1970: 1_000_000))
    let key = try P256.Signing.PrivateKey(pemRepresentation: first.key)
    // The SubjectPublicKeyInfo pinned is the key's own DER (as `openssl x509 -pubkey | openssl pkey -pubin -outform der` gives).
    #expect(first.spkiPin.sha256 == ServerIdentity.hex(SHA256.hash(data: key.publicKey.derRepresentation)))
    // The same key in a certificate made again (new dates, new names): the same SPKI pin, another certificate pin.
    let name = try DistinguishedName { CommonName("A, again") }
    let again = try Certificate(version: .v3, serialNumber: .init(), publicKey: .init(key.publicKey),
                                notValidBefore: Date(timeIntervalSince1970: 2_000_000), notValidAfter: Date(timeIntervalSince1970: 3_000_000),
                                issuer: name, subject: name, signatureAlgorithm: .ecdsaWithSHA256,
                                extensions: try Certificate.Extensions { SubjectAlternativeNames([.dnsName("b.local")]) },
                                issuerPrivateKey: .init(key))
    var serializer = DER.Serializer()
    try serializer.serialize(again)
    let pins = try ServerIdentity.pins(ofCertificateDER: serializer.serializedBytes)
    #expect(pins.pins[0] == first.spkiPin && pins.pins[1] != first.pins.pins[1])
}

@Test func aKeyThatIsntTheCertificatesIsRefused() throws {
    let a = try ServerIdentity.make(commonName: "A", dnsNames: ["a.local"])
    let b = try ServerIdentity.make(commonName: "B", dnsNames: ["b.local"])
    #expect(throws: IdentityError.self) { try ServerIdentity(chain: a.chain, key: b.key) }
    #expect(throws: IdentityError.self) { try ServerIdentity(chain: "nothing", key: a.key) }
    #expect(throws: IdentityError.self) { try ServerIdentity(chain: a.chain, key: "nothing") }
}

func folder() -> String { NSTemporaryDirectory() + "server-identity-\(UUID().uuidString)" }

@Test func anIdentityIsKeptOnceInOneFileItsOwnerReads() throws {
    let place = folder()
    defer { try? FileManager.default.removeItem(atPath: place) }
    let store = FileIdentityStore(folder: place)
    var made = 0
    let make = { () throws -> ServerIdentity in
        made += 1
        return try ServerIdentity.make(commonName: "Kept", dnsNames: ["k.local"])
    }
    let first = try ServerIdentity.ensure(in: store, make: make)
    let second = try ServerIdentity.ensure(in: store, make: make)
    #expect(!first.kept && second.kept && made == 1 && second.identity == first.identity)
    let mode = try FileManager.default.attributesOfItem(atPath: store.path)[.posixPermissions] as? Int
    #expect(mode == 0o600)
    #expect(try FileManager.default.contentsOfDirectory(atPath: place) == ["server.pem"], "no temporary file left")
}

@Test func aStoreThatCantBeReadIsNeverMadeAnew() throws {
    let place = folder()
    defer { try? FileManager.default.removeItem(atPath: place) }
    let store = FileIdentityStore(folder: place)
    _ = try ServerIdentity.ensure(in: store) { try ServerIdentity.make(commonName: "K", dnsNames: ["k.local"]) }
    // Spoilt (a disk's fault, a hand's): an error, not a new key over the old one that every device pins.
    try Data("not an identity".utf8).write(to: URL(fileURLWithPath: store.path))
    var made = false
    #expect(throws: IdentityError.self) {
        try ServerIdentity.ensure(in: store) { made = true; return try ServerIdentity.make(commonName: "New", dnsNames: ["n.local"]) }
    }
    #expect(!made)
    // A store that can't tell (a locked Keychain): the same.
    struct Locked: IdentityStore {
        func read() throws -> (chain: String, key: String)? { throw IdentityError("locked") }
        func write(chain: String, key: String) throws {}
    }
    #expect(throws: IdentityError.self) { try ServerIdentity.ensure(in: Locked()) { made = true; return try ServerIdentity.make(commonName: "N", dnsNames: []) } }
    #expect(!made)
}

@Test func aStoreThatCantBeWrittenSaysSo() throws {
    // A folder where the file should be: nothing written, an error said.
    let place = folder()
    defer { try? FileManager.default.removeItem(atPath: place) }
    try FileManager.default.createDirectory(atPath: place + "/server.pem", withIntermediateDirectories: true)
    let store = FileIdentityStore(folder: place)
    #expect(throws: (any Error).self) { try store.write(chain: "c", key: "k") }
}
