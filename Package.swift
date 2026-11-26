// swift-tools-version: 6.0

// Server Kit: utilities for building self-hosted servers and the apps that pair with them. One library a concern, so
// an app takes only its side:
//
// - NetworkCore: a machine's networks (IPv4, IPv6, getifaddrs, or a reader of an app's own). No Foundation.
// - PairingLink: the `<scheme>://pair?…` link a server shows as a QR, its pins, and what a server says of where it's
//   reached. No Foundation (NetworkCore alone).
// - ServerAddresses: where this machine is reached (its LAN, `.local` and tailnet addresses), read without a CLI.
// - ServerIdentity: a server's own self-signed TLS identity, made once and kept, and the pins clients trust it by.
// - ServerPairing: pairing offers with one-time codes, the throttle on wrong claims, and per-device sessions.
// - ServerTLS: a TLS front on every interface (SwiftNIO), a CA's certificate or the server's own by SNI, handing each
//   connection to the server's plain listener on loopback behind a PROXY v1 line; Tailscale's certificates.
//
// Linux and Apple's systems alike.
import PackageDescription

let package = Package(
    name: "server_kit",
    platforms: [.macOS(.v14), .iOS(.v17), .tvOS(.v17), .watchOS(.v10), .visionOS(.v1)],
    products: [
        .library(name: "NetworkCore", targets: ["NetworkCore"]),
        .library(name: "PairingLink", targets: ["PairingLink"]),
        .library(name: "ServerAddresses", targets: ["ServerAddresses"]),
        .library(name: "ServerIdentity", targets: ["ServerIdentity"]),
        .library(name: "ServerPairing", targets: ["ServerPairing"]),
        .library(name: "ServerTLS", targets: ["ServerTLS"]),
    ],
    dependencies: [
        // Ranges: the apps pin these themselves, and theirs are taken.
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"5.0.0"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.21.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.7.0"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.27.0"),
    ],
    targets: [
        .target(name: "NetworkCore"),
        .target(name: "PairingLink", dependencies: ["NetworkCore"]),
        .target(name: "ServerAddresses", dependencies: ["NetworkCore"]),
        .target(name: "ServerIdentity", dependencies: [
            "NetworkCore", "PairingLink", "ServerAddresses",
            .product(name: "Crypto", package: "swift-crypto"),
            .product(name: "X509", package: "swift-certificates"),
            .product(name: "SwiftASN1", package: "swift-asn1"),
        ]),
        .target(name: "ServerPairing", dependencies: [
            "NetworkCore",
            .product(name: "Crypto", package: "swift-crypto"),
        ]),
        .target(name: "ServerTLS", dependencies: [
            "NetworkCore",
            .product(name: "NIOCore", package: "swift-nio"),
            .product(name: "NIOPosix", package: "swift-nio"),
            .product(name: "NIOConcurrencyHelpers", package: "swift-nio"),
            .product(name: "NIOTLS", package: "swift-nio"),
            .product(name: "NIOSSL", package: "swift-nio-ssl"),
        ]),
        .testTarget(name: "NetworkCoreTests", dependencies: ["NetworkCore"]),
        .testTarget(name: "PairingLinkTests", dependencies: ["PairingLink", "NetworkCore"]),
        .testTarget(name: "ServerAddressesTests", dependencies: ["ServerAddresses"]),
        .testTarget(name: "ServerIdentityTests", dependencies: [
            "ServerIdentity", "PairingLink", "ServerAddresses",
            .product(name: "Crypto", package: "swift-crypto"),
            .product(name: "X509", package: "swift-certificates"),
            .product(name: "SwiftASN1", package: "swift-asn1"),
        ]),
        .testTarget(name: "ServerPairingTests", dependencies: ["ServerPairing"]),
        .testTarget(name: "ServerTLSTests", dependencies: [
            "ServerTLS", "ServerIdentity",
            .product(name: "NIOCore", package: "swift-nio"),
            .product(name: "NIOPosix", package: "swift-nio"),
            .product(name: "NIOEmbedded", package: "swift-nio"),
            .product(name: "NIOConcurrencyHelpers", package: "swift-nio"),
            .product(name: "NIOSSL", package: "swift-nio-ssl"),
        ]),
    ]
)
