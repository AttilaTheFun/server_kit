import Testing
@testable import NetworkCore

@Test func ipv6AddressesAreReadToTheirBytes() {
    #expect(IPv6.parse("::1") == Array(repeating: 0, count: 15) + [1])
    #expect(IPv6.parse("[fe80::1%en0]") == [0xfe, 0x80] + Array(repeating: 0, count: 13) + [1])
    #expect(IPv6.parse("2001:db8:0:0:0:0:0:1")?.count == 16)
    #expect(IPv6.parse("::ffff:192.0.2.1")?.suffix(6) == [0xff, 0xff, 192, 0, 2, 1])
    #expect(IPv6.parse("1::2::3") == nil && IPv6.parse("12345::") == nil && IPv6.parse("192.0.2.1") == nil && IPv6.parse("1:2:3") == nil)
}

@Test func anIPv6HostsNetworkIsItsFirst64Bits() {
    #expect(IPv6.prefix64("2001:db8:1:2:aaaa::1") == IPv6.prefix64("2001:db8:1:2:bbbb:cccc:dddd:eeee"))
    #expect(IPv6.prefix64("2001:db8:1:2::1") != IPv6.prefix64("2001:db8:1:3::1"))
}

@Test func aBridgeHandsOverItsNetworksAsLines() {
    let network = NetworkInterfaces(lines: ["192.168.1.5/255.255.255.0", "nonsense", "100.64.0.2/255.192.0.0"])
    #expect(network.ipv4.count == 2 && network.hasTailnet && network.hasLAN)
    #expect(network.isOnLocalNetwork("192.168.1.200") && !network.isOnLocalNetwork("192.168.2.1"))
}

@Test func ipv4IsReadAndWritten() {
    #expect(IPv4.parse("10.0.0.1").map(IPv4.format) == "10.0.0.1")
    #expect(IPv4.parse("256.0.0.1") == nil && IPv4.parse("1.2.3") == nil && IPv4.parse("a.b.c.d") == nil)
    #expect(IPv4.isTailnet(IPv4.parse("100.100.1.1")!) && !IPv4.isTailnet(IPv4.parse("100.128.0.1")!))
}
