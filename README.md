# Server Kit

Utilities for building self-hosted servers, and the apps that pair with them, in Swift: on Linux and on Apple's systems
(macOS 14, iOS 17 and later). `NetworkCore` and `PairingLink` use no Foundation, so that a WebAssembly client can take
them; that's a design aim, not yet tested in CI.

A self-hosted server is reached by many addresses (its LAN's, its `.local` name, a tailnet's) and has no certificate a
CA would vouch for on most of them. Server Kit is how a server serves TLS anyway and how a device pairs with it: the
server makes an identity of its own, shows a QR with its addresses, its pins and a one-time code, and gives each
device that claims the code a session of its own. A device then reaches the server by whichever address answers first,
trusting its certificate by the pins it was given.

One library a concern, so an app takes only its side:

| Library | What it does | Depends on |
| --- | --- | --- |
| `NetworkCore` | A machine's networks: IPv4 and IPv6 addresses, its interfaces (getifaddrs), or a reader of an app's own (another language's, a browser's) | nothing (no Foundation) |
| `PairingLink` | The `<scheme>://pair?…` link (written and read, a format of an app's own read beside it) with its credential (a one-time code, a password, or none), pins and pin sets, the trust decision for an address, and what a server says of where it's reached | `NetworkCore` (no Foundation) |
| `ServerAddresses` | Where a server is reached: its LAN, tailnet and `.local` addresses, bridges left out | `NetworkCore`, Foundation |
| `ServerIdentity` | A server's own TLS identity (ECDSA P-256, self-signed, made once and kept) or one supplied, and its pins: of its SubjectPublicKeyInfo, which outlives a re-issued certificate, and of the whole certificate | swift-crypto, swift-certificates |
| `ServerPairing` | One-time pairing codes, the throttle on wrong claims (by address, an IPv6 host's /64, and all at once), and per-device sessions (a token shown once, kept as its SHA-256) | `NetworkCore`, swift-crypto |
| `ServerTLS` | A TLS front on every interface: a CA's certificate (a tailnet's, a domain's) for its names and the server's own for the rest, by the hello's SNI; each connection handed to the server's plain listener on loopback behind a secret line and a PROXY v1 line naming the client, with back-pressure, a connection cap and an idle timeout; Tailscale's certificates asked for and kept | SwiftNIO, swift-nio-ssl, Foundation |

More are coming: the client's pinned transport with address ranking and fallback, and the QR.

```swift
.package(url: "https://github.com/AttilaTheFun/server_kit.git", exact: "0.1.0")

.product(name: "ServerIdentity", package: "server_kit")
```

## Pairing, in short

```swift
// The server, once: its identity, kept.
let (identity, _) = try ServerIdentity.ensure(in: FileIdentityStore(folder: stateFolder)) {
    try ServerIdentity.make(product: "Example", addresses: .current())
}

let offers = PairingOffers()
let throttle = ClaimThrottle()
let sessions = DeviceSessions(store: FileSessionStore(path: stateFolder + "/sessions.json"), prefix: "ex_")

// Asked to pair a device: a code, and the link its QR shows.
let offer = offers.offer(for: "owner")!
let link = PairingLink(scheme: "example",
                       servers: ["https://mac.example.ts.net:8443"] + LocalAddresses.current().httpsURLs(port: 8443),
                       pins: identity.pins, credential: .oneTimeCode(offer.code), serverID: serverID, name: "Example on Mac")!

// The device claims the code over TLS: a session of its own.
func claim(code: String, device: String, from clientAddress: String) throws -> String? {
    guard throttle.lockedUntil(clientAddress) == nil else { return nil }   // 429
    guard let owner = offers.claim(code) else {
        throttle.failed(clientAddress)
        return nil                                                          // 403
    }
    throttle.succeeded(clientAddress)
    return try sessions.make(for: owner, device: device).token              // shown to the device once
}

// Every request after: the device's bearer, checked.
let session = sessions.check(bearer)
```

## Serving TLS

The server's own listener stays plain, on loopback; `TLSFront` ends TLS in front of it on every interface and hands each
connection on after two lines: `SERVERKIT-TLS <secret>` (made at each start, so no other process on the machine can
claim to be the front) and a PROXY v1 line naming the client. The server reads both with `ProxyV1.parse` before the
request.

```swift
let secret = SecretToken.random(bytes: 32)
let tailnet = TailscaleCertificate(name: "mac.example.ts.net", folder: stateFolder)
let certificates = ServerCertificates(caNames: ["mac.example.ts.net"], ca: tailnet?.kept(),
                                      own: PEMPair(chain: identity.chain, key: identity.key))
let front = TLSFront()
try front.start(port: 8443, inner: 8080, secret: secret, certificates: certificates)

// Twice a day: a renewed certificate, taken up without a restart.
if case .success(let pair) = await tailnet?.refresh() {
    try front.use(ServerCertificates(caNames: ["mac.example.ts.net"], ca: pair, own: certificates.own))
}
```

## Developing

`swift build` and `swift test`. CI builds and tests every pull request on Linux, and on macOS. Changes are
described in `changes/` (see `changes/README.md`), folded into the release notes when a release is proposed.

## License

Apache 2.0. See `LICENSE`.
