// The presence payload and the domain-separated signing inputs — the Swift
// twin of shared/receipt.js. Domain tags are NUL-terminated so a signature
// can never be replayed across contexts.

import Foundation
import CryptoKit

public enum Presence {
    static func tag(_ name: String) -> Data {
        var data = Data(name.utf8)
        data.append(0)
        return data
    }

    public static var tagPresence: Data { tag("inkline.presence.v1") }
    public static var tagAssert: Data { tag("inkline.assert.v1") }
    public static var tagEnrollAttest: Data { tag("inkline.attest.v1") }
    public static var tagEnrollBind: Data { tag("inkline.enroll.v1") }

    public struct Payload {
        public let contentHash: String
        public let nonce: String
        public let iat: Int
        public let kid: String

        public init(contentHash: String, nonce: String, iat: Int, kid: String) {
            self.contentHash = contentHash
            self.nonce = nonce
            self.iat = iat
            self.kid = kid
        }

        public func cjson() -> CJSON {
            return .object([
                "v": .int(1),
                "action": .string("email"),
                "contentHash": .string(contentHash),
                "nonce": .string(nonce),
                "iat": .int(iat),
                "kid": .string(kid),
            ])
        }
    }

    public static func kid(ofRawPublicKey raw: Data) -> String {
        return B64.encode(Data(SHA256.hash(data: raw)))
    }

    public static func presenceSignInput(_ payload: Payload) -> Data {
        return tagPresence + payload.cjson().serializedData()
    }

    // Client data covered by the per-send App Attest assertion.
    public static func assertClientData(_ payload: Payload) -> Data {
        return tagAssert + payload.cjson().serializedData()
    }

    // Client data hash covered by the one-time App Attest key attestation.
    public static func enrollAttestClientDataHash(challenge: Data) -> Data {
        return Data(SHA256.hash(data: tagEnrollAttest + challenge))
    }

    // Client data covered by the enrollment assertion binding the presence
    // public key to the attested App Attest key.
    public static func enrollBindClientData(challenge: String, pub: String) -> Data {
        let value: CJSON = .object(["challenge": .string(challenge), "pub": .string(pub)])
        return tagEnrollBind + value.serializedData()
    }
}
