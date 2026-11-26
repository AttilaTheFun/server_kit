import Foundation
import Testing
@testable import ServerPairing

@Test func aCodeIsClaimedOnceWithinItsTime() {
    let offers = PairingOffers<String>(lifetime: 300, most: 2)
    let now = Date(timeIntervalSince1970: 1_000)
    let first = offers.offer(for: "owner", now: now)!
    #expect(first.code.count == 32 && first.expires == now.addingTimeInterval(300))
    #expect(offers.claim(first.code, now: now.addingTimeInterval(10)) == "owner")
    #expect(offers.claim(first.code, now: now.addingTimeInterval(11)) == nil, "once")
    let late = offers.offer(for: "owner", now: now)!
    #expect(offers.claim(late.code, now: now.addingTimeInterval(301)) == nil, "run out")
    #expect(offers.claim("never-offered", now: now) == nil)
    // At most `most` waiting at once.
    _ = offers.offer(for: "a", now: now)
    _ = offers.offer(for: "b", now: now)
    #expect(offers.offer(for: "c", now: now) == nil)
    #expect(offers.offer(for: "c", now: now.addingTimeInterval(400)) != nil, "once those ran out")
}

@Test func wrongClaimsFromOneAddressAreRefusedAWhile() {
    let throttle = ClaimThrottle(limit: 3, window: 60, lockout: 300, most: 4)
    let now = Date(timeIntervalSince1970: 2_000)
    #expect(!throttle.failed("10.0.0.9", now: now) && !throttle.failed("10.0.0.9", now: now.addingTimeInterval(1)))
    #expect(throttle.failed("10.0.0.9", now: now.addingTimeInterval(2)), "the third locks it out")
    #expect(throttle.lockedUntil("10.0.0.9", now: now.addingTimeInterval(3)) == now.addingTimeInterval(302))
    #expect(throttle.lockedUntil("10.0.0.8", now: now.addingTimeInterval(3)) == nil, "another's never blocked")
    #expect(throttle.lockedUntil("10.0.0.9", now: now.addingTimeInterval(303)) == nil, "until the lockout's end")
    // Spread out past the window: never locked.
    for i in 0..<5 { #expect(!throttle.failed("10.0.0.7", now: now.addingTimeInterval(Double(i) * 61))) }
    // At most `most` addresses kept.
    for i in 0..<10 { throttle.failed("10.0.1.\(i)", now: now.addingTimeInterval(10_000)) }
    #expect(throttle.count <= 4)
}

struct Memory: SessionStore, @unchecked Sendable {
    final class Box: @unchecked Sendable { var sessions: [DeviceSession] = [] }
    let box = Box()
    func load() -> [DeviceSession] { box.sessions }
    func save(_ sessions: [DeviceSession]) throws { box.sessions = sessions }
}

@Test func aDevicesSessionIsMadeCheckedAndEnded() throws {
    let store = Memory()
    let sessions = DeviceSessions(store: store, prefix: "sws_", lifetime: 3600)
    let now = Date(timeIntervalSince1970: 5_000)
    let (token, session) = try sessions.make(for: "owner", device: "iPhone\u{0}\nforged line", now: now)
    #expect(token.hasPrefix("sws_") && session.device == "iPhoneforged line", "control characters out")
    #expect(!store.box.sessions.contains { $0.sha256 == token || $0.id == token }, "never the token kept")
    #expect(sessions.check(token, now: now.addingTimeInterval(30))?.id == session.id)
    #expect(sessions.check("sws_wrong", now: now) == nil && sessions.check("other", now: now) == nil)
    // Used: its life slides on.
    #expect(sessions.check(token, now: now.addingTimeInterval(3000))?.id == session.id)
    #expect(sessions.check(token, now: now.addingTimeInterval(6000)) != nil, "used at 3000, so live until 6600")
    #expect(sessions.check(token, now: now.addingTimeInterval(20_000)) == nil, "unused an hour: gone")
    let (other, kept) = try sessions.make(for: "owner", device: "iPad", now: now.addingTimeInterval(20_000))
    #expect(try sessions.end(kept.id) && sessions.check(other, now: now.addingTimeInterval(20_001)) == nil)
    #expect(try !sessions.end(kept.id))
}

@Test func sessionsAreKeptInAFileOnlyItsOwnerReads() throws {
    let path = NSTemporaryDirectory() + "sessions-\(UUID().uuidString)/sessions.json"
    defer { try? FileManager.default.removeItem(atPath: (path as NSString).deletingLastPathComponent) }
    let (token, _) = try DeviceSessions(store: FileSessionStore(path: path)).make(for: "o", device: nil)
    #expect(DeviceSessions(store: FileSessionStore(path: path)).check(token) != nil, "read back by another")
    let mode = try FileManager.default.attributesOfItem(atPath: path)[.posixPermissions] as? Int
    #expect(mode == 0o600)
}
