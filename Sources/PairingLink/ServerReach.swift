// What a server says of where it's reached: every address over TLS, the one a CA vouches for first, and the pins of
// its own certificate. A client takes it only from an answer it already trusts (over TLS, by the system's trust or a
// pin it holds), never over plain HTTP, where anyone on the way could name another address and certificate; and a
// server says it only to a caller it knows, since its addresses may name a private network.

public struct ServerReach: Codable, Hashable, Sendable {
    /// `https://<host>:<port>`, the one a CA vouches for first.
    public var addresses: [String]
    /// The pins (`spki:<hex>`, or bare hex for a whole certificate's), current first.
    public var pins: [String]?
    /// A whole certificate's pin, as servers said it before `pins` (read, and written beside `pins` for older clients).
    public var lanPin: String?

    public init(addresses: [String], pins: PinSet) {
        self.addresses = addresses
        self.pins = pins.isEmpty ? nil : pins.pins.map(\.description)
        self.lanPin = pins.pins.first { $0.kind == .certificate }?.sha256
    }

    /// Every pin it names.
    public var pinSet: PinSet {
        PinSet((pins ?? []).compactMap(Pin.init) + [lanPin].compactMap { $0.flatMap { Pin(.certificate, sha256: $0) } })
    }
}
