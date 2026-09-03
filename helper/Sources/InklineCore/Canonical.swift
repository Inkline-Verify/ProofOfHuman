// Inkline canonical email v1 — the Swift twin of shared/canonical.js.
//
// canonText: NFC, lowercase, NFC again, collapse whitespace runs (the exact
// scalar set below, mirroring ECMAScript \s) to one space, trim.

import Foundation
import CryptoKit

public enum Canonical {
    static let whitespaceScalars: Set<UInt32> = {
        var set: Set<UInt32> = [
            0x0009, 0x000A, 0x000B, 0x000C, 0x000D, 0x0020,
            0x00A0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF,
        ]
        for v in 0x2000...0x200A { set.insert(UInt32(v)) }
        return set
    }()

    public static func canonText(_ input: String) -> String {
        let normalized = input.precomposedStringWithCanonicalMapping
            .lowercased()
            .precomposedStringWithCanonicalMapping

        var out = String.UnicodeScalarView()
        var pendingSpace = false
        var started = false
        for scalar in normalized.unicodeScalars {
            if whitespaceScalars.contains(scalar.value) {
                if started { pendingSpace = true }
            } else {
                if pendingSpace {
                    out.append(UnicodeScalar(32))
                    pendingSpace = false
                }
                out.append(scalar)
                started = true
            }
        }
        return String(out)
    }

    public struct Email {
        public let from: String
        public let to: [String]
        public let cc: [String]
        public let subject: String
        public let body: String

        public init(from: String, to: [String], cc: [String], subject: String, body: String) {
            self.from = from
            self.to = to
            self.cc = cc
            self.subject = subject
            self.body = body
        }

        // The canonical form: what gets rendered for approval and what gets
        // hashed. What you see is what is signed.
        public func canonical() -> Email {
            return Email(
                from: Canonical.canonText(from),
                to: to.map(Canonical.canonText),
                cc: cc.map(Canonical.canonText),
                subject: Canonical.canonText(subject),
                body: Canonical.canonText(body)
            )
        }

        public func canonicalCJSON() -> CJSON {
            let c = canonical()
            return .object([
                "v": .int(1),
                "from": .string(c.from),
                "to": .array(c.to.map { .string($0) }),
                "cc": .array(c.cc.map { .string($0) }),
                "subject": .string(c.subject),
                "body": .string(c.body),
            ])
        }

        public func contentHash() -> String {
            let digest = SHA256.hash(data: canonicalCJSON().serializedData())
            return B64.encode(Data(digest))
        }
    }
}
