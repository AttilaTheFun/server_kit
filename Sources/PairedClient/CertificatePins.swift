import Crypto
import PairingLink

// What a client checks a certificate it's shown by: the SHA-256s of its SubjectPublicKeyInfo and of the whole
// certificate, as a server's pins name them (ServerIdentity's `pins(ofCertificateDER:)` makes the same). Read with a
// small DER walk of its own, so a client takes no X.509 library for it.

public enum CertificatePins {
    /// A certificate's two SHA-256s, lowercase hex; nil for bytes that aren't a certificate.
    public static func of(der: [UInt8]) -> (spki: String, certificate: String)? {
        guard let spki = subjectPublicKeyInfo(of: der) else { return nil }
        return (hex(SHA256.hash(data: spki)), hex(SHA256.hash(data: der)))
    }

    /// Whether `pins` match the certificate.
    public static func match(_ pins: PinSet, der: [UInt8]) -> Bool {
        guard let shown = of(der: der) else { return false }
        return pins.matches(spki: shown.spki, certificate: shown.certificate)
    }

    /// Certificate → TBSCertificate → the field after the subject, its own bytes.
    static func subjectPublicKeyInfo(of der: [UInt8]) -> ArraySlice<UInt8>? {
        guard let certificate = TLV.read(der[...]), certificate.tag == 0x30, certificate.rest.isEmpty,
              let tbs = TLV.read(certificate.content), tbs.tag == 0x30 else { return nil }
        var fields = tbs.content
        var read: [TLV] = []
        while !fields.isEmpty, read.count < 8 {
            guard let field = TLV.read(fields) else { return nil }
            read.append(field)
            fields = field.rest
        }
        // An explicit version ([0]) first, when there is one; then serialNumber, signature, issuer, validity, subject,
        // subjectPublicKeyInfo.
        if read.first?.tag == 0xA0 { read.removeFirst() }
        guard read.count > 5, read[5].tag == 0x30 else { return nil }
        return read[5].whole
    }

    /// One DER element: its tag (one byte: a certificate's are all low-numbered), content, its whole encoding, and
    /// what follows it.
    struct TLV {
        var tag: UInt8
        var content: ArraySlice<UInt8>
        var whole: ArraySlice<UInt8>
        var rest: ArraySlice<UInt8>

        static func read(_ bytes: ArraySlice<UInt8>) -> TLV? {
            var index = bytes.startIndex
            guard index < bytes.endIndex else { return nil }
            let tag = bytes[index]
            guard tag & 0x1F != 0x1F else { return nil }
            index += 1
            guard index < bytes.endIndex else { return nil }
            var length = Int(bytes[index])
            index += 1
            if length & 0x80 != 0 {
                let count = length & 0x7F
                // DER's long form: 1–4 bytes, no leading zero, never for what the short form says.
                guard (1...4).contains(count), bytes.endIndex - index >= count, bytes[index] != 0 else { return nil }
                length = 0
                for _ in 0..<count {
                    length = length << 8 | Int(bytes[index])
                    index += 1
                }
                guard length >= 0x80 else { return nil }
            }
            guard bytes.endIndex - index >= length else { return nil }
            let end = index + length
            return TLV(tag: tag, content: bytes[index..<end], whole: bytes[bytes.startIndex..<end], rest: bytes[end...])
        }
    }

    static func hex<D: Sequence>(_ digest: D) -> String where D.Element == UInt8 {
        let digits = Array("0123456789abcdef".utf8)
        var out: [UInt8] = []
        for byte in digest {
            out.append(digits[Int(byte >> 4)])
            out.append(digits[Int(byte & 0xF)])
        }
        return String(decoding: out, as: UTF8.self)
    }
}
