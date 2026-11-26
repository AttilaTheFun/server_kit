// The QR codes made here are read back by a reader of their own: Vision on Apple's systems, zbar's `zbarimg` where
// it's installed (Linux), at every size a pairing link takes: a short address, a few hundred bytes, past a thousand.

import Foundation
import Testing
@testable import PairingQR
#if canImport(Vision)
import CoreGraphics
import Vision
#endif

let link = "example://pair?v=1&server=" + String(repeating: "https%3A%2F%2Fmac.example.ts.net%3A7445&address=", count: 5)
let sizes: [(String, Int)] = [("https://10.0.0.5:7433", 2), (link, 10), (String(repeating: "server-kit-", count: 109), 25)]

@Test func eachTextTakesTheSmallestSymbolThatHoldsIt() throws {
    for (text, version) in sizes {
        let code = try #require(QRCode(text), "no code for \(text.utf8.count) bytes")
        #expect(code.size == version * 4 + 17, "version for \(text.utf8.count) bytes")
    }
    #expect(QRCode(String(repeating: "x", count: 3000)) == nil, "too long for any version")
    // M where it takes no bigger a symbol, L where it would.
    #expect(QRCode.best("https://10.0.0.5:7433") == QRCode("https://10.0.0.5:7433", level: .medium))
    #expect(QRCode.best(link) == QRCode(link, level: .low) && QRCode(link, level: .medium)!.size > QRCode(link)!.size)
}

@Test func theArithmeticUnderneath() {
    // Reed–Solomon: the standard's own check values for version 1-M.
    let data: [UInt8] = [0x10, 0x20, 0x0C, 0x56, 0x61, 0x80, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11]
    #expect(QRCode.ReedSolomon.remainder(data, degree: 10) == [0xA5, 0x24, 0xD4, 0xC1, 0xED, 0x36, 0xC7, 0x87, 0x2C, 0x55])
    #expect(QRCode.rawDataModules(version: 1) == 208 && QRCode.rawDataModules(version: 7) == 1568)
    #expect(QRCode.dataCapacity(version: 1, level: .low) / 8 == 19 && QRCode.dataCapacity(version: 10, level: .low) / 8 == 274)
    #expect(QRCode.Canvas(version: 7).alignmentPositions() == [6, 22, 38])
    #expect(QRCode.Canvas(version: 32).alignmentPositions() == [6, 34, 60, 86, 112, 138])
}

@Test func itIsDrawnForATerminalAndAsAnImage() throws {
    let code = try #require(QRCode("https://10.0.0.5:7433"))
    let lines = code.text(quietZone: 2).split(separator: "\n")
    #expect(lines.count == (code.size + 4 + 1) / 2 && lines.allSatisfy { $0.count == code.size + 4 })
    #expect(lines[0].allSatisfy { $0 == "█" }, "the quiet zone light")
    let svg = code.svg(moduleSize: 8, quietZone: 4)
    #expect(svg.hasPrefix("<svg") && svg.contains("viewBox=\"0 0 \((code.size + 8) * 8) \((code.size + 8) * 8)\""))
    let pbm = code.pbm(quietZone: 4).split(separator: "\n")
    #expect(pbm[0] == "P1" && pbm.count == 2 + code.size + 8)
}

/// What a reader makes of the code, or nil where there's no reader here.
func read(_ code: QRCode) throws -> String? {
    #if canImport(Vision)
    let scale = 8, quiet = 4
    let side = (code.size + quiet * 2) * scale
    let context = try #require(CGContext(data: nil, width: side, height: side, bitsPerComponent: 8, bytesPerRow: side,
                                         space: CGColorSpaceCreateDeviceGray(), bitmapInfo: CGImageAlphaInfo.none.rawValue))
    context.setFillColor(gray: 1, alpha: 1)
    context.fill(CGRect(x: 0, y: 0, width: side, height: side))
    context.setFillColor(gray: 0, alpha: 1)
    for y in 0..<code.size {
        for x in 0..<code.size where code.isDark(x: x, y: y) {
            // CoreGraphics' origin is at the bottom: rows flipped.
            context.fill(CGRect(x: (x + quiet) * scale, y: (code.size - 1 - y + quiet) * scale, width: scale, height: scale))
        }
    }
    let request = VNDetectBarcodesRequest()
    request.symbologies = [.qr]
    try VNImageRequestHandler(cgImage: try #require(context.makeImage())).perform([request])
    return request.results?.first?.payloadStringValue
    #elseif os(Linux)
    let zbar = "/usr/bin/zbarimg"
    guard FileManager.default.isExecutableFile(atPath: zbar) else { return nil }
    // zbar reads PBM; scaled up 4 times, as a camera would see it.
    let file = NSTemporaryDirectory() + "pairing-qr-\(UUID().uuidString).pbm"
    defer { try? FileManager.default.removeItem(atPath: file) }
    try scaled(code.pbm(quietZone: 4), by: 4).write(toFile: file, atomically: true, encoding: .utf8)
    let process = Process()
    process.executableURL = URL(fileURLWithPath: zbar)
    process.arguments = ["--quiet", "--raw", "-Sdisable", "-Sqrcode.enable", "-Sbinary", file]  // QR alone: no linear barcode seen in its modules
    let out = Pipe()
    process.standardOutput = out
    process.standardError = FileHandle.nullDevice
    try process.run()
    let data = out.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    var text = String(decoding: data, as: UTF8.self)
    if text.hasSuffix("\n") { text.removeLast() }
    return text
    #else
    return nil
    #endif
}

func scaled(_ pbm: String, by factor: Int) -> String {
    let lines = pbm.split(separator: "\n")
    let side = Int(lines[1].split(separator: " ")[0])! * factor
    var out = "P1\n\(side) \(side)\n"
    for row in lines.dropFirst(2) {
        let wide = row.split(separator: " ").flatMap { Array(repeating: String($0), count: factor) }.joined(separator: " ")
        for _ in 0..<factor { out += wide + "\n" }
    }
    return out
}

@Test func aReaderReadsWhatIsMade() throws {
    for (text, _) in sizes {
        let code = try #require(QRCode(text))
        guard let read = try read(code) else { return }
        #expect(read == text, "read back at \(text.utf8.count) bytes")
    }
    let medium = try #require(QRCode(link, level: .medium))
    if let read = try read(medium) { #expect(read == link) }
}
