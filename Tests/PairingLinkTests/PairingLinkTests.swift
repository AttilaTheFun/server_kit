import Testing
@testable import PairingLink

let spki = String(repeating: "ab", count: 32)
let whole = String(repeating: "cd", count: 32)

@Test func aPinIsAKindAndASHA256() {
    #expect(Pin("spki:" + spki) == Pin(.spki, sha256: spki))
    #expect(Pin("SPKI:" + spki.uppercased())?.sha256 == spki, "kept lowercase")
    // Bare hex: a whole certificate's, as servers wrote pins before kinds.
    #expect(Pin(whole) == Pin(.certificate, sha256: whole))
    #expect(Pin(whole)?.description == whole && Pin("spki:" + spki)?.description == "spki:" + spki)
    #expect(Pin("spki:abc") == nil && Pin("md5:" + spki) == nil && Pin(String(repeating: "g", count: 64)) == nil)
}

@Test func aPinSetMatchesAnyOfItsPins() {
    let set = PinSet([Pin(.spki, sha256: spki)!, Pin(.certificate, sha256: whole)!, Pin(.spki, sha256: spki)!])
    #expect(set.pins.count == 2, "each once")
    #expect(set.matches(spki: spki, certificate: nil))
    #expect(set.matches(spki: nil, certificate: whole.uppercased()))
    #expect(!set.matches(spki: whole, certificate: spki), "each by its own kind")
    #expect(!PinSet([]).matches(spki: spki, certificate: whole))
}

@Test func aServersOwnCertificateIsTrustedByItsPinsAlone() {
    let pins = PinSet([Pin(.spki, sha256: spki)!])
    #expect(PinTrust.decide(host: "mac.example.ts.net", pins: pins, spki: nil, certificate: nil) == .system)
    #expect(PinTrust.decide(host: "192.168.1.5", pins: pins, spki: spki, certificate: nil) == .accept)
    #expect(PinTrust.decide(host: "mac.local", pins: pins, spki: whole, certificate: nil) == .refuse)
    #expect(PinTrust.decide(host: "[fe80::1]", pins: PinSet([]), spki: spki, certificate: nil) == .refuse, "nothing pinned: refused")
    #expect(PinTrust.isPinned(host: "mac.local.") && !PinTrust.isPinned(host: "example.com"))
}

@Test func aLinkIsWrittenAndReadAgain() {
    let link = PairingLink(scheme: "nimbus", code: "c0de", servers: ["https://mac.example.ts.net:7445", "https://192.168.1.5:7445",
                                                                       "https://mac.local:7445"],
                           pins: PinSet([Pin(.spki, sha256: spki)!, Pin(.certificate, sha256: whole)!]), serverID: "srv-1", name: "Mac Studio")
    let text = link.text
    #expect(text.hasPrefix("nimbus://pair?v=1&server=https%3A%2F%2Fmac.example.ts.net%3A7445&code=c0de&address="))
    #expect(PairingLink.parse(text, schemes: ["nimbus"]) == link)
    #expect(PairingLink.parse(text, schemes: ["visor"]) == nil, "another app's scheme")
}

@Test func aLinkFromBeforeVersionsAndKindsIsRead() {
    // What servers wrote before (`server`, `code`, LAN `address`es, a bare whole-certificate `pin`).
    let old = "nimbus://pair?server=https://mac.example.ts.net:7445&code=abc&address=https://192.168.1.5:7445&pin=\(whole)"
    let link = PairingLink.parse(old, schemes: ["nimbus", "shireworks"])
    #expect(link?.version == 1 && link?.code == "abc")
    #expect(link?.servers == ["https://mac.example.ts.net:7445", "https://192.168.1.5:7445"])
    #expect(link?.pins == PinSet([Pin(.certificate, sha256: whole)!]))
}

@Test func aPinnedAddressIsKeptOnlyWithAPin() {
    let unpinned = "nimbus://pair?server=https://mac.example.ts.net:7445&code=abc&address=https://192.168.1.5:7445&address=https://other.example.com"
    #expect(PairingLink.parse(unpinned, schemes: ["nimbus"])?.servers == ["https://mac.example.ts.net:7445", "https://other.example.com"])
    // Written so too: no pinned address leaves without its pins.
    let link = PairingLink(scheme: "nimbus", code: "x", servers: ["https://a.example.ts.net", "https://10.0.0.2"])
    #expect(!link.text.contains("10.0.0.2"))
}

@Test func whatIsntALinkIsntRead() {
    #expect(PairingLink.parse("nimbus://pair?code=abc", schemes: ["nimbus"]) == nil, "no server")
    #expect(PairingLink.parse("nimbus://pair?server=http://x:1&code=abc", schemes: ["nimbus"]) == nil, "not https")
    #expect(PairingLink.parse("nimbus://connect?server=https://x&code=abc", schemes: ["nimbus"]) == nil, "not pair")
    #expect(PairingLink.parse("nimbus://pair?v=2&server=https://x&code=abc", schemes: ["nimbus"]) == nil, "a version this doesn't know")
    #expect(PairingLink.parse("nimbus://pair?server=https://x&code=%zz", schemes: ["nimbus"]) == nil, "bad percent-coding")
}

@Test func aLinkPastedWithWordsAroundItIsRead() {
    let pasted = "  Pair with this: nimbus://pair?server=https://mac.example.ts.net&code=abc  (good for 5 minutes)\n"
    #expect(PairingLink.parse(pasted, schemes: ["nimbus"])?.code == "abc")
}

@Test func anAppsOwnFormatIsReadThroughTheSameEntry() {
    struct Old: PairingLinkFormat {
        func parse(_ text: String) -> PairingLink? {
            guard text.hasPrefix("visor://connect?code=") else { return nil }
            return PairingLink(scheme: "visor", code: String(text.dropFirst("visor://connect?code=".count)), servers: ["https://mac.example.ts.net"])
        }
    }
    #expect(PairingLink.parse("visor://connect?code=xyz", schemes: ["visor"], formats: [Old()])?.code == "xyz")
}

@Test func aReachSaysItsPinsForOldClientsAndNew() {
    let reach = ServerReach(addresses: ["https://a.example.ts.net"], pins: PinSet([Pin(.spki, sha256: spki)!, Pin(.certificate, sha256: whole)!]))
    #expect(reach.pins == ["spki:" + spki, whole] && reach.lanPin == whole)
    #expect(reach.pinSet.pins.count == 2)
    // An older server's, its whole certificate's pin alone.
    #expect(ServerReach(addresses: [], pins: PinSet([])).pinSet.isEmpty)
}

@Test func hostsAreReadOutOfAddresses() {
    #expect(PairingLink.host(of: "https://mac.local:7445/x") == "mac.local")
    #expect(PairingLink.host(of: "https://[fe80::1]:7445") == "[fe80::1]")
    #expect(PairingLink.host(of: "https://user@10.0.0.1") == "10.0.0.1")
    #expect(PairingLink.host(of: "nonsense") == nil)
}
