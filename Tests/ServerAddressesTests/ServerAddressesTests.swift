import Testing
@testable import ServerAddresses

struct Fixed: NetworkReader {
    var network: NetworkInterfaces
    func read() -> NetworkInterfaces { network }
}

@Test func aMachinesAddressesAreItsLANsAndTailnetsBridgesLeftOut() {
    let network = NetworkInterfaces([
        .init(address: IPv4.parse("192.168.1.5")!, mask: IPv4.parse("255.255.255.0")!, name: "en0"),
        .init(address: IPv4.parse("100.73.57.115")!, mask: IPv4.parse("255.255.255.255")!, name: "utun4"),
        .init(address: IPv4.parse("192.168.64.1")!, mask: IPv4.parse("255.255.255.0")!, name: "bridge100"),
        .init(address: IPv4.parse("203.0.113.9")!, mask: IPv4.parse("255.255.255.0")!, name: "en1"),
    ])
    let addresses = LocalAddresses.current(reader: Fixed(network: network), host: "Studio")
    #expect(addresses.lan == ["192.168.1.5"])
    #expect(addresses.tailnet == ["100.73.57.115"])
    #expect(addresses.bonjour == "Studio.local")
    #expect(addresses.httpsURLs(port: 7445) == ["https://192.168.1.5:7445", "https://Studio.local:7445"])
}

@Test func aHostNameIsItsLocalName() {
    #expect(LocalAddresses.bonjourName("mac.local.") == "mac.local")
    #expect(LocalAddresses.bonjourName("mac.example.com") == "mac.local")
    #expect(LocalAddresses.bonjourName("192.168.1.5") == nil && LocalAddresses.bonjourName("") == nil)
}

@Test func aNetworkSaysWhatItsOn() {
    let network = NetworkInterfaces([("192.168.1.5", "255.255.255.0"), ("100.64.0.2", "255.192.0.0")])
    #expect(network.isOnLocalNetwork("192.168.1.77") && !network.isOnLocalNetwork("192.168.2.1"))
    #expect(network.hasTailnet && network.hasLAN)
    #expect(!NetworkInterfaces([("203.0.113.9", "255.255.255.0")]).hasLAN)
}

@Test func theSystemsInterfacesAreRead() {
    // Whatever this machine has: read without failing, loopback left out.
    #expect(!SystemNetwork().read().ipv4.contains { IPv4.isLoopback($0.address) })
}
