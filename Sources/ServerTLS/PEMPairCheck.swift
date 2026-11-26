import Foundation
import NIOSSL

extension PEMPair {
    public struct Unusable: Error, CustomStringConvertible {
        public var description: String
    }

    /// Throws unless the pair would serve at `now`: a chain whose leaf is in its dates, and a key that is that leaf's.
    public func check(now: Date) throws {
        let certificates = try NIOSSLCertificate.fromPEMBytes(Array(chain.utf8))
        guard let leaf = certificates.first else { throw Unusable(description: "no certificate") }
        let seconds = time_t(now.timeIntervalSince1970)
        guard leaf.notValidBefore <= seconds else { throw Unusable(description: "not valid yet") }
        guard leaf.notValidAfter > seconds else { throw Unusable(description: "past its end") }
        let key = try NIOSSLPrivateKey(bytes: Array(self.key.utf8), format: .pem)
        // BoringSSL refuses a key that isn't the leaf's as the context is made.
        let configuration = TLSConfiguration.makeServerConfiguration(certificateChain: certificates.map { .certificate($0) },
                                                                     privateKey: .privateKey(key))
        do {
            _ = try NIOSSLContext(configuration: configuration)
        } catch {
            throw Unusable(description: "the key isn't the certificate's: \(error)")
        }
    }
}
