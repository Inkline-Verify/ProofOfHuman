// Asserts byte-identical behavior against canonical/vectors.json — the same
// golden file the Node test suite verifies. If these pass, the Swift helper
// and the JavaScript notary/verifier agree on every signed byte.

import XCTest
import CryptoKit
@testable import InklineCore

final class VectorTests: XCTestCase {
    struct Vectors {
        let cjsonCases: [[String: Any]]
        let canonTextCases: [[String: Any]]
        let emailCases: [[String: Any]]
        let presence: [String: Any]
    }

    static var vectors: Vectors!

    override class func setUp() {
        super.setUp()
        let thisFile = URL(fileURLWithPath: #filePath)
        let url = thisFile
            .deletingLastPathComponent() // -> Tests/InklineCoreTests
            .deletingLastPathComponent() // -> Tests
            .deletingLastPathComponent() // -> helper
            .deletingLastPathComponent() // -> inkline-presence
            .appendingPathComponent("canonical/vectors.json")
        guard let data = try? Data(contentsOf: url),
              let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else {
            fatalError("could not load canonical/vectors.json — run: npm run vectors")
        }
        vectors = Vectors(
            cjsonCases: root["cjson"] as? [[String: Any]] ?? [],
            canonTextCases: root["canonText"] as? [[String: Any]] ?? [],
            emailCases: root["emails"] as? [[String: Any]] ?? [],
            presence: root["presence"] as? [String: Any] ?? [:]
        )
    }

    func testCJSONMatchesGoldenVectors() throws {
        XCTAssertFalse(Self.vectors.cjsonCases.isEmpty)
        for c in Self.vectors.cjsonCases {
            let value = try CJSON.from(any: c["value"] ?? nil)
            let expected = c["expected"] as? String
            XCTAssertEqual(value.serialized(), expected)
        }
    }

    func testCanonTextMatchesGoldenVectors() {
        XCTAssertFalse(Self.vectors.canonTextCases.isEmpty)
        for c in Self.vectors.canonTextCases {
            let input = c["input"] as? String ?? ""
            let expected = c["expected"] as? String ?? ""
            XCTAssertEqual(Canonical.canonText(input), expected, "input: \(input.debugDescription)")
        }
    }

    func testCanonicalEmailMatchesGoldenVectors() {
        XCTAssertFalse(Self.vectors.emailCases.isEmpty)
        for c in Self.vectors.emailCases {
            guard let e = c["email"] as? [String: Any] else {
                XCTFail("malformed email case")
                continue
            }
            let email = Canonical.Email(
                from: e["from"] as? String ?? "",
                to: e["to"] as? [String] ?? [],
                cc: e["cc"] as? [String] ?? [],
                subject: e["subject"] as? String ?? "",
                body: e["body"] as? String ?? ""
            )
            XCTAssertEqual(email.canonicalCJSON().serialized(), c["canonicalJson"] as? String)
            XCTAssertEqual(email.contentHash(), c["contentHash"] as? String)
        }
    }

    func testPresenceSignInputAndGoldenSignatureVerify() throws {
        let p = Self.vectors.presence
        guard let payloadDict = p["payload"] as? [String: Any],
              let pubB64 = p["pub"] as? String,
              let signInputB64 = p["signInput"] as? String,
              let sigB64 = p["sig"] as? String,
              let pubRaw = B64.decode(pubB64),
              let expectedInput = B64.decode(signInputB64),
              let sigRaw = B64.decode(sigB64)
        else {
            return XCTFail("malformed presence vector")
        }

        let payload = Presence.Payload(
            contentHash: payloadDict["contentHash"] as? String ?? "",
            nonce: payloadDict["nonce"] as? String ?? "",
            iat: payloadDict["iat"] as? Int ?? 0,
            kid: payloadDict["kid"] as? String ?? ""
        )

        let input = Presence.presenceSignInput(payload)
        XCTAssertEqual(input, expectedInput, "presence sign input bytes differ from JS")

        XCTAssertEqual(Presence.kid(ofRawPublicKey: pubRaw), payload.kid)

        let key = try P256.Signing.PublicKey(x963Representation: pubRaw)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: sigRaw)
        XCTAssertTrue(key.isValidSignature(signature, for: input),
                      "golden signature from the JS implementation must verify in Swift")
    }

    func testSoftwareKeyRoundTrip() throws {
        // Signs with a CryptoKit software key exactly the way the helper signs
        // with the Secure Enclave key, and verifies the raw-signature format.
        let key = P256.Signing.PrivateKey()
        let payload = Presence.Payload(contentHash: "h", nonce: "n", iat: 1_756_339_200, kid: "k")
        let input = Presence.presenceSignInput(payload)
        let derSig = try key.signature(for: input).derRepresentation
        let raw = try P256.Signing.ECDSASignature(derRepresentation: derSig).rawRepresentation
        XCTAssertEqual(raw.count, 64)
        XCTAssertTrue(key.publicKey.isValidSignature(
            try P256.Signing.ECDSASignature(rawRepresentation: raw), for: input))
    }

    func testDomainTagsAreNulTerminated() {
        XCTAssertEqual(Presence.tagPresence.last, 0)
        XCTAssertEqual(Presence.tagPresence.prefix(Presence.tagPresence.count - 1),
                       Data("inkline.presence.v1".utf8))
    }
}
