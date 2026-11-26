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
    #expect(Pin("spki:abc") == nil && Pin(String(repeating: "g", count: 64)) == nil)
}

@Test func aPinOfAKindThisDoesntKnowFailsClosed() {
    // Not read as some other kind, nor as a whole certificate's: dropped, so a link with only such pins has none.
    #expect(Pin("sha3:" + spki) == nil && Pin("md5:" + spki) == nil)
    let link = PairingLink.parse("nimbus://pair?server=https://192.168.1.5&pin=sha3:\(spki)&code=c", schemes: ["nimbus"])
    #expect(link == nil, "its only server presents its own certificate, and there's no pin it can be checked by")
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
    // A caller's own names.
    #expect(PinTrust.decide(host: "mac.example.ts.net", pins: pins, spki: spki, certificate: nil, isPinned: { _ in true }) == .accept)
}

@Test func namesNoCAVouchesForArePinned() {
    for host in ["studio", "studio.", "mac.local", "mac.local.", "nas.lan", "box.home.arpa", "api.internal", "10.0.0.2", "[::1]"] {
        #expect(PinTrust.isPinned(host: host), "\(host)")
    }
    for host in ["example.com", "mac.example.ts.net", ""] { #expect(!PinTrust.isPinned(host: host), "\(host)") }
}

let example = PairingLink(scheme: "nimbus", servers: ["https://mac.example.ts.net:7445", "https://192.168.1.5:7445", "https://mac.local:7445"],
                          paths: ["http://127.0.0.1:7480", "ssh://mac.local"],
                          pins: PinSet([Pin(.spki, sha256: spki)!, Pin(.certificate, sha256: whole)!]), credential: .oneTimeCode("c0de"),
                          serverID: "srv-1", name: "Mac Studio", extensions: ["auth": "github"])!

@Test func aLinkIsWrittenAndReadAgain() {
    let text = example.text
    #expect(text.hasPrefix("nimbus://pair?v=1&server=https%3A%2F%2Fmac.example.ts.net%3A7445&address="))
    #expect(text.contains("&x-auth=github"))
    #expect(PairingLink.parse(text, schemes: ["nimbus"]) == example)
    #expect(PairingLink.parse(text, schemes: ["visor"]) == nil, "another app's scheme")
}

@Test func eachCredentialIsWrittenAndReadAgain() {
    for credential: PairingLink.Credential in [.oneTimeCode("one-time"), .password("correct horse"), .none] {
        let link = PairingLink(scheme: "visor", servers: ["https://mac.example.ts.net"], credential: credential)!
        #expect(PairingLink.parse(link.text, schemes: ["visor"])?.credential == credential)
    }
    // Paths alone, a password: a server reached over its own ways.
    let paths = PairingLink(scheme: "visor", servers: [], paths: ["http://192.168.1.5:8080"], credential: .password("pw"))!
    #expect(PairingLink.parse(paths.text, schemes: ["visor"]) == paths)
}

@Test func aLinkThatCouldntBeWrittenIsntMade() {
    #expect(PairingLink(scheme: "nimbus", servers: ["http://mac.example.ts.net"], credential: .none) == nil, "not https")
    #expect(PairingLink(scheme: "nimbus", servers: ["https://10.0.0.2"], credential: .none) == nil, "its own certificate, no pins")
    #expect(PairingLink(scheme: "nimbus", servers: [], credential: .none) == nil, "nowhere to go")
    #expect(PairingLink(scheme: "Nimbus", servers: ["https://a.example.com"], credential: .none) == nil, "the scheme as it's written")
    #expect(PairingLink(scheme: "nimbus", servers: ["https://a.example.com"], credential: .none, version: 2) == nil)
}

@Test func aLinkFromBeforeVersionsAndKindsIsRead() {
    // What servers wrote before (`server`, `code`, LAN `address`es, a bare whole-certificate `pin`).
    let old = "nimbus://pair?server=https://mac.example.ts.net:7445&code=abc&address=https://192.168.1.5:7445&pin=\(whole)"
    let link = PairingLink.parse(old, schemes: ["nimbus", "shireworks"])
    #expect(link?.version == 1 && link?.code == "abc")
    #expect(link?.servers == ["https://mac.example.ts.net:7445", "https://192.168.1.5:7445"])
    #expect(link?.pins == PinSet([Pin(.certificate, sha256: whole)!]))
}

@Test func anAddressWithItsOwnCertificateIsKeptOnlyWithAPin() {
    let unpinned = "nimbus://pair?server=https://mac.example.ts.net:7445&code=abc&address=https://192.168.1.5:7445&address=https://other.example.com"
    #expect(PairingLink.parse(unpinned, schemes: ["nimbus"])?.servers == ["https://mac.example.ts.net:7445", "https://other.example.com"])
    // The `server` too: an IP with no pins is dropped, and with nothing else left, there's no link.
    #expect(PairingLink.parse("nimbus://pair?server=https://192.168.1.5&code=abc", schemes: ["nimbus"]) == nil)
    #expect(PairingLink.parse("nimbus://pair?server=https://192.168.1.5&address=https://mac.example.ts.net&code=abc",
                              schemes: ["nimbus"])?.servers == ["https://mac.example.ts.net"])
}

@Test func whatIsntALinkIsntRead() {
    #expect(PairingLink.parse("nimbus://pair?code=abc", schemes: ["nimbus"]) == nil, "nowhere to go")
    #expect(PairingLink.parse("nimbus://connect?server=https://x.example.com&code=abc", schemes: ["nimbus"]) == nil, "not pair")
    #expect(PairingLink.parse("nimbus://pair?v=2&server=https://x.example.com&code=abc", schemes: ["nimbus"]) == nil, "a version this doesn't know")
    #expect(PairingLink.parse("nimbus://pair?server=https://x.example.com&code=%zz", schemes: ["nimbus"]) == nil, "bad percent-coding")
    #expect(PairingLink.parse("nimbus://pair?server=https://x.example.com&code=%FF", schemes: ["nimbus"]) == nil, "not UTF-8")
}

@Test func aLinkPastedWithWordsAroundItIsRead() {
    let pasted = "  Pair with this: nimbus://pair?server=https://mac.example.ts.net&code=abc  (good for 5 minutes)\n"
    #expect(PairingLink.parse(pasted, schemes: ["nimbus"])?.code == "abc")
    // Capitalised at the start of a sentence, and a full stop after it: the pin, and the addresses it keeps, read.
    let sentence = "Nimbus://pair?server=https://mac.example.ts.net&address=https://192.168.1.5&code=abc&pin=spki:\(spki)."
    let link = PairingLink.parse(sentence, schemes: ["nimbus"])
    #expect(link?.pins == PinSet([Pin(.spki, sha256: spki)!]) && link?.servers.count == 2)
    #expect(PairingLink.parse("(see nimbus://pair?server=https://a.example.com&code=x)", schemes: ["nimbus"])?.code == "x")
    // The earliest in the text, whichever scheme.
    let two = "visor://pair?server=https://v.example.com&code=v then nimbus://pair?server=https://n.example.com&code=n"
    #expect(PairingLink.parse(two, schemes: ["nimbus", "visor"])?.code == "v")
}

@Test func anAppsOwnFormatIsReadThroughTheSameEntry() {
    struct Old: PairingLinkFormat {
        func parse(_ text: String) -> PairingLink? {
            guard text.hasPrefix("visor://connect?code=") else { return nil }
            return PairingLink(scheme: "visor", servers: ["https://mac.example.ts.net"],
                               credential: .password(String(text.dropFirst("visor://connect?code=".count))))
        }
    }
    #expect(PairingLink.parse("visor://connect?code=xyz", schemes: ["visor"], formats: [Old()])?.credential == .password("xyz"))
}

@Test func aReachSaysItsPinsForOldClientsAndNew() {
    let reach = ServerReach(addresses: ["https://a.example.ts.net"], pins: PinSet([Pin(.spki, sha256: spki)!, Pin(.certificate, sha256: whole)!]))
    #expect(reach.pins == ["spki:" + spki, whole] && reach.lanPin == whole)
    #expect(reach.pinSet.pins.count == 2)
    #expect(ServerReach(addresses: [], pins: PinSet([])).pinSet.isEmpty)
}

@Test func hostsAreReadOutOfAddresses() {
    #expect(PairingLink.host(of: "https://mac.local:7445/x") == "mac.local")
    #expect(PairingLink.host(of: "https://[fe80::1]:7445") == "[fe80::1]")
    #expect(PairingLink.host(of: "ssh://user@10.0.0.1") == "10.0.0.1")
    #expect(PairingLink.host(of: "https://a.example.com?x=1") == "a.example.com")
    #expect(PairingLink.host(of: "nonsense") == nil)
}
