# Server Kit

Utilities for building self-hosted servers, and the apps that pair with them, in Swift: on a Mac, on Linux, and on the
devices that talk to them.

A self-hosted server is reached by many addresses (its LAN's, its `.local` name, a tailnet's) and has no certificate a
CA would vouch for on most of them. Server Kit is how a server serves TLS anyway and how a device pairs with it: the
server makes an identity of its own, shows a QR with its addresses, its pins and a one-time code, and gives each
device that claims the code a session of its own. A device then reaches the server by whichever address answers first,
trusting its certificate by the pins it was given.

One library a concern, so an app takes only its side:

| Library | What it does | Depends on |
| --- | --- | --- |
| `PairingLink` | The `<scheme>://pair?…` link (written and read, a format of an app's own read beside it), pins and pin sets, the trust decision for an address, and what a server says of where it's reached | nothing (no Foundation: WebAssembly too) |
| `ServerAddresses` | Where a machine is reached: its LAN, tailnet and `.local` addresses, read from its interfaces (no CLI), or from a reader of an app's own | Foundation |
| `ServerIdentity` | A server's own TLS identity (ECDSA P-256, self-signed, made once and kept) or one supplied, and its pins: of its SubjectPublicKeyInfo, which outlives a re-issued certificate, and of the whole certificate | swift-crypto, swift-certificates |
| `ServerPairing` | One-time pairing codes, the throttle on wrong claims, and per-device sessions (a token shown once, kept as its SHA-256) | swift-crypto |

More are coming: the TLS listener for every interface (SwiftNIO), the client's pinned transport with address ranking
and fallback, and the QR.

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

// Asked to pair a device: a code, and the link its QR shows.
let offers = PairingOffers<String>()
let offer = offers.offer(for: "owner")!
let link = PairingLink(scheme: "example", code: offer.code,
                       servers: ["https://mac.example.ts.net:8443"] + LocalAddresses.current().httpsURLs(port: 8443),
                       pins: identity.pins, serverID: serverID, name: "Example on Mac")

// The device claims the code over TLS: a session of its own.
let throttle = ClaimThrottle()
guard throttle.lockedUntil(clientAddress) == nil else { /* 429 */ }
guard let owner = offers.claim(code) else { throttle.failed(clientAddress); /* 403 */ }
let (token, session) = try sessions.make(for: owner, device: deviceName)
```

## Developing

`swift build` and `swift test`, on a Mac or on Linux. CI builds and tests every pull request on Linux. Changes are
described in `changes/` (see `changes/README.md`), folded into the release notes when a release is proposed.

## License

Apache 2.0. See `LICENSE`.
