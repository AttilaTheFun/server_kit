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
    #expect(identity.pins.pins.map(\.kind) == [.spki, .certificate])
    // Read again from its PEM: the same pins.
    #expect(try ServerIdentity(chain: identity.chain, key: identity.key).pins == identity.pins)
    // A client's view: the pins it computes of the certificate it's shown match.
    let der = try PEMDocument(pemString: PEMBlocks.first(in: identity.chain, kind: "CERTIFICATE")!).derBytes
    let shown = try ServerIdentity.pins(ofCertificateDER: der)
    let spki = shown.pins.first { $0.kind == .spki }!.sha256, whole = shown.pins.first { $0.kind == .certificate }!.sha256
    #expect(PinTrust.decide(host: "192.168.1.5", pins: identity.pins, spki: spki, certificate: whole) == .accept)
}

@Test func anSPKIPinOutlivesItsCertificate() throws {
    // The same key in a certificate made again (new dates, new names): the same SPKI pin, another certificate pin.
    let first = try ServerIdentity.make(commonName: "A", dnsNames: ["a.local"], now: Date(timeIntervalSince1970: 1_000_000))
    let key = try P256.Signing.PrivateKey(pemRepresentation: first.key)
    let name = try DistinguishedName { CommonName("A, again") }
    let again = try Certificate(version: .v3, serialNumber: .init(), publicKey: .init(key.publicKey),
                                notValidBefore: Date(timeIntervalSince1970: 2_000_000), notValidAfter: Date(timeIntervalSince1970: 3_000_000),
                                issuer: name, subject: name, signatureAlgorithm: .ecdsaWithSHA256,
                                extensions: try Certificate.Extensions { SubjectAlternativeNames([.dnsName("b.local")]) },
                                issuerPrivateKey: .init(key))
    var serializer = DER.Serializer()
    try serializer.serialize(again)
    let pins = try ServerIdentity.pins(ofCertificateDER: serializer.serializedBytes)
    #expect(pins.pins[0] == first.spkiPin)
    #expect(pins.pins[1] != first.pins.pins[1])
}

@Test func anIdentityIsKeptOnceAndReadAfter() throws {
    let folder = NSTemporaryDirectory() + "server-identity-\(UUID().uuidString)"
    defer { try? FileManager.default.removeItem(atPath: folder) }
    let store = FileIdentityStore(folder: folder)
    var made = 0
    let make = { () throws -> ServerIdentity in
        made += 1
        return try ServerIdentity.make(commonName: "Kept", dnsNames: ["k.local"])
    }
    let first = try ServerIdentity.ensure(in: store, make: make)
    let second = try ServerIdentity.ensure(in: store, make: make)
    #expect(!first.kept && second.kept && made == 1)
    #expect(second.identity.pins == first.identity.pins)
    let mode = try FileManager.default.attributesOfItem(atPath: folder + "/server.key")[.posixPermissions] as? Int
    #expect(mode == 0o600)
    // One that can't be read: a new one made in its place.
    try Data("not a key".utf8).write(to: URL(fileURLWithPath: folder + "/server.key"))
    #expect(try !ServerIdentity.ensure(in: store, make: make).kept && made == 2)
}

@Test func aSuppliedIdentityThatIsntOneIsRefused() {
    #expect(throws: IdentityError.self) { try ServerIdentity(chain: "nothing", key: "nothing") }
}
