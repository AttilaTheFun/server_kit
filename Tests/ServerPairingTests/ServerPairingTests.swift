import Foundation
import Testing
@testable import ServerPairing

/// A clock a test moves.
final class Clock: @unchecked Sendable {
    private let lock = NSLock()
    private var current: Date
    init(_ start: TimeInterval) { current = Date(timeIntervalSince1970: start) }
    var now: Date { lock.withLock { current } }
    func advance(_ seconds: TimeInterval) { lock.withLock { current = current.addingTimeInterval(seconds) } }
    var read: @Sendable () -> Date { { self.now } }
}

@Test func aCodeIsClaimedOnceWithinItsTime() {
    let clock = Clock(1_000)
    let offers = PairingOffers(lifetime: 300, maxWaiting: 2, now: clock.read)
    let first = offers.offer(for: "owner")!
    #expect(first.code.count == 32 && first.expires == clock.now.addingTimeInterval(300))
    clock.advance(10)
    #expect(offers.claim(first.code) == "owner")
    #expect(offers.claim(first.code) == nil, "once")
    let late = offers.offer(for: "owner")!
    clock.advance(301)
    #expect(offers.claim(late.code) == nil, "run out")
    #expect(offers.claim("never-offered") == nil)
    _ = offers.offer(for: "a")
    _ = offers.offer(for: "b")
    #expect(offers.offer(for: "c") == nil && offers.waitingCount == 2, "at most maxWaiting")
    clock.advance(400)
    #expect(offers.offer(for: "c") != nil, "once those ran out")
}

@Test func wrongClaimsFromOnePlaceAreRefusedAWhile() {
    let clock = Clock(2_000)
    let throttle = ClaimThrottle(limit: 3, globalLimit: 100, window: 60, lockout: 300, maxAddresses: 4, now: clock.read)
    #expect(!throttle.failed("10.0.0.9") && !throttle.failed("10.0.0.9"))
    #expect(throttle.failed("10.0.0.9"), "the third locks it out")
    #expect(throttle.lockedUntil("10.0.0.9") == clock.now.addingTimeInterval(300))
    #expect(throttle.lockedUntil("10.0.0.8") == nil, "another's never blocked")
    clock.advance(301)
    #expect(throttle.lockedUntil("10.0.0.9") == nil, "until the lockout's end")
    // Spread out past the window: never locked.
    for _ in 0..<5 {
        #expect(!throttle.failed("10.0.0.7"))
        clock.advance(61)
    }
}

@Test func oneHostsManyIPv6AddressesAreOnePlace() {
    let clock = Clock(3_000)
    let throttle = ClaimThrottle(limit: 3, globalLimit: 100, now: clock.read)
    throttle.failed("2001:db8:1:2::a")
    throttle.failed("[2001:db8:1:2::b]")
    #expect(throttle.failed("2001:db8:1:2:ffff:ffff:ffff:ffff"), "the same /64")
    #expect(throttle.lockedUntil("2001:db8:1:2::c") != nil && throttle.lockedUntil("2001:db8:1:3::a") == nil)
    #expect(ClaimThrottle.place("::ffff:192.0.2.1") == "192.0.2.1")
    #expect(ClaimThrottle.place("2001:db8:1:2:aaaa::1") == "2001:db8:1:2::/64", "written as an address is, for the log")
}

@Test func manyPlacesGuessingTogetherAreRefusedToo() {
    let clock = Clock(4_000)
    let throttle = ClaimThrottle(limit: 100, globalLimit: 10, window: 60, lockout: 300, now: clock.read)
    for i in 0..<9 { #expect(!throttle.failed("10.1.0.\(i)")) }
    #expect(throttle.failed("10.1.0.99"), "the tenth from anywhere locks everyone")
    #expect(throttle.lockedUntil("10.9.9.9") != nil)
}

@Test func theGlobalBudgetIsOffUnlessAskedForAndNeverLocksOutTheServersOwnDevices() {
    let clock = Clock(4_500)
    let off = ClaimThrottle(limit: 100, now: clock.read)
    for i in 0..<500 { off.failed("10.3.\(i / 250).\(i % 250)") }
    #expect(off.lockedUntil("10.9.9.9") == nil, "off by default")
    let on = ClaimThrottle(limit: 100, globalLimit: 10, now: clock.read)
    on.succeeded("192.168.1.2")
    for i in 0..<10 { on.failed("10.4.0.\(i)") }
    #expect(on.lockedUntil("10.9.9.9") != nil, "strangers: locked out")
    #expect(on.lockedUntil("192.168.1.2") == nil, "the owner's device, which claimed rightly: not")
}

@Test func aRightClaimForgetsItsWrongOnes() {
    let clock = Clock(5_000)
    let throttle = ClaimThrottle(limit: 3, globalLimit: 100, now: clock.read)
    throttle.failed("10.0.0.5")
    throttle.failed("10.0.0.5")
    throttle.succeeded("10.0.0.5")
    #expect(!throttle.failed("10.0.0.5") && !throttle.failed("10.0.0.5"), "counting again from none")
}

@Test func aLockedOutPlaceIsntForgottenToMakeRoom() {
    let clock = Clock(6_000)
    let throttle = ClaimThrottle(limit: 2, globalLimit: 1_000, window: 60, lockout: 300, maxAddresses: 2, now: clock.read)
    throttle.failed("10.0.0.1")
    #expect(throttle.failed("10.0.0.1"))
    for i in 2..<20 { throttle.failed("10.0.0.\(i)") }
    #expect(throttle.lockedUntil("10.0.0.1") != nil, "still locked out however many came after")
}

@Test func theThrottleHoldsUnderManyClaimsAtOnce() async {
    let throttle = ClaimThrottle(limit: 1_000_000, globalLimit: 1_000_000)
    await withTaskGroup(of: Void.self) { group in
        for i in 0..<200 { group.addTask { throttle.failed("10.2.\(i % 50).1"); _ = throttle.lockedUntil("10.2.0.1") } }
    }
    #expect(throttle.count == 50)
}

final class Memory: SessionStore, @unchecked Sendable {
    var sessions: [DeviceSession] = []
    var saves = 0
    var failing = false
    func load() throws -> [DeviceSession] {
        if failing { throw SessionStoreError("unreadable") }
        return sessions
    }
    func save(_ sessions: [DeviceSession]) throws {
        saves += 1
        self.sessions = sessions
    }
}

@Test func aDevicesSessionIsMadeCheckedAndEnded() throws {
    let clock = Clock(10_000), store = Memory()
    let sessions = DeviceSessions(store: store, prefix: "sws_", lifetime: 3600, maxAge: 5 * 3600, now: clock.read)
    let (token, session) = try sessions.make(for: "owner", device: "iPhone\u{0}\nforged line")
    #expect(token.hasPrefix("sws_") && session.device == "iPhoneforged line", "control characters out")
    #expect(!store.sessions.contains { $0.sha256 == token || $0.id == token }, "never the token kept")
    clock.advance(30)
    #expect(sessions.check(token)?.id == session.id)
    #expect(sessions.check("sws_wrong") == nil && sessions.check("other") == nil)
    // Used: its life slides on, its use written behind at most once a minute.
    let savesBefore = store.saves
    for _ in 0..<5 {
        clock.advance(3000)
        #expect(sessions.check(token) != nil)
    }
    #expect(store.saves - savesBefore <= 5)
    // But never past maxAge, however much it's used: 15,030 s old now, 18,030 s after this.
    clock.advance(3000)
    #expect(sessions.check(token) == nil, "made over five hours ago")
    let (other, kept) = try sessions.make(for: "owner", device: "iPad")
    #expect(try sessions.end(kept.id) && sessions.check(other) == nil && !sessions.end(kept.id))
}

@Test func aStoreThatCantBeReadIsntWrittenOver() throws {
    let clock = Clock(20_000), store = Memory()
    let (token, _) = try DeviceSessions(store: store, now: clock.read).make(for: "o", device: nil)
    store.failing = true
    let sessions = DeviceSessions(store: store, now: clock.read)
    #expect(sessions.check(token) == nil)
    #expect(throws: SessionStoreError.self) { try sessions.make(for: "o", device: nil) }
    #expect(store.sessions.count == 1, "the session kept, not wiped")
}

@Test func sessionsAreKeptInAFileOnlyItsOwnerReads() throws {
    let place = NSTemporaryDirectory() + "sessions-\(UUID().uuidString)"
    defer { try? FileManager.default.removeItem(atPath: place) }
    let path = place + "/sessions.json"
    let (token, _) = try DeviceSessions(store: FileSessionStore(path: path)).make(for: "o", device: nil)
    #expect(DeviceSessions(store: FileSessionStore(path: path)).check(token) != nil, "read back by another")
    let mode = try FileManager.default.attributesOfItem(atPath: path)[.posixPermissions] as? Int
    #expect(mode == 0o600)
    // A file that isn't one: an error, and it's left as it is.
    try Data("{oops".utf8).write(to: URL(fileURLWithPath: path))
    #expect(throws: SessionStoreError.self) { try FileSessionStore(path: path).load() }
    #expect(throws: SessionStoreError.self) { try DeviceSessions(store: FileSessionStore(path: path)).make(for: "o", device: nil) }
    #expect(String(decoding: try Data(contentsOf: URL(fileURLWithPath: path)), as: UTF8.self) == "{oops")
}
