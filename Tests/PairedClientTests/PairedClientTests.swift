import Foundation
import NetworkCore
import PairingLink
import ServerIdentity
import Testing
@testable import PairedClient

@Test func aCertificatesPinsAreTheServersOwn() throws {
    let identity = try ServerIdentity.make(commonName: "Mac", dnsNames: ["mac.local"], ipv4: ["192.168.1.5"])
    let der = try #require(derOfLeaf(identity.chain))
    let shown = try #require(CertificatePins.of(der: der))
    #expect(Pin(.spki, sha256: shown.spki) == identity.spkiPin)
    #expect(PinSet([Pin(.spki, sha256: shown.spki)!, Pin(.certificate, sha256: shown.certificate)!]) == identity.pins)
    #expect(CertificatePins.match(identity.pins, der: der))
    let other = try ServerIdentity.make(commonName: "Other", dnsNames: ["other.local"])
    #expect(!CertificatePins.match(other.pins, der: der))
}

@Test func whatIsntACertificateHasNoPins() throws {
    let identity = try ServerIdentity.make(commonName: "Mac", dnsNames: ["mac.local"])
    let der = try #require(derOfLeaf(identity.chain))
    #expect(CertificatePins.of(der: []) == nil)
    #expect(CertificatePins.of(der: Array(der.dropLast())) == nil, "cut short")
    #expect(CertificatePins.of(der: der + [0]) == nil, "something after it")
    #expect(CertificatePins.of(der: [0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF]) == nil, "a length past its end")
    #expect(CertificatePins.of(der: [0x30, 0x81, 0x05, 1, 2, 3, 4, 5]) == nil, "the long form for a short length")
}

func derOfLeaf(_ pem: String) -> [UInt8]? {
    guard let begin = pem.range(of: "-----BEGIN CERTIFICATE-----"), let end = pem.range(of: "-----END CERTIFICATE-----") else { return nil }
    let body = pem[begin.upperBound..<end.lowerBound].filter { !$0.isWhitespace }
    return Data(base64Encoded: String(body)).map { [UInt8]($0) }
}

@Test func networkChangesAreSaidOnceTheySettle() async throws {
    let watch = NetworkWatch()
    let told = Told()
    let token = watch.onChange { generation in told.add(generation) }
    defer { watch.stop(token) }
    watch.networkChanged(settle: .milliseconds(20))
    watch.networkChanged(settle: .milliseconds(20))
    try await Task.sleep(for: .milliseconds(300))
    #expect(told.values == [1], "two changes at once: one")
}

final class Told: @unchecked Sendable {
    private let lock = NSLock()
    private var seen: [Int] = []
    func add(_ value: Int) { lock.withLock { seen.append(value) } }
    var values: [Int] { lock.withLock { seen } }
}
