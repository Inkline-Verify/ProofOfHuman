// Canonical JSON v1 — the Swift twin of shared/cjson.js.
// Every signature is computed over bytes from this serializer, so it must be
// byte-identical with the JavaScript implementation:
//   - object keys sorted by UTF-16 code units, no whitespace
//   - strings escaped exactly like JSON.stringify (", \, \b \t \n \f \r,
//     other control characters as lowercase \u00xx; non-ASCII verbatim)
//   - numbers: integers only

import Foundation

public indirect enum CJSON {
    case null
    case bool(Bool)
    case int(Int)
    case string(String)
    case array([CJSON])
    case object([String: CJSON])

    public func serialized() -> String {
        switch self {
        case .null:
            return "null"
        case .bool(let b):
            return b ? "true" : "false"
        case .int(let i):
            return String(i)
        case .string(let s):
            return CJSON.escape(s)
        case .array(let items):
            return "[" + items.map { $0.serialized() }.joined(separator: ",") + "]"
        case .object(let dict):
            let keys = dict.keys.sorted { a, b in
                Array(a.utf16).lexicographicallyPrecedes(Array(b.utf16))
            }
            let parts = keys.map { key in
                CJSON.escape(key) + ":" + dict[key]!.serialized()
            }
            return "{" + parts.joined(separator: ",") + "}"
        }
    }

    public func serializedData() -> Data {
        return Data(serialized().utf8)
    }

    static func escape(_ s: String) -> String {
        let quote = UnicodeScalar(34 as UInt8)
        let backslash = UnicodeScalar(92 as UInt8)
        func letter(_ ascii: UInt8) -> UnicodeScalar { UnicodeScalar(ascii) }

        var out = String.UnicodeScalarView()
        out.append(quote)
        for scalar in s.unicodeScalars {
            switch scalar.value {
            case 34:
                out.append(backslash); out.append(quote)
            case 92:
                out.append(backslash); out.append(backslash)
            case 8:
                out.append(backslash); out.append(letter(98)) // b
            case 9:
                out.append(backslash); out.append(letter(116)) // t
            case 10:
                out.append(backslash); out.append(letter(110)) // n
            case 12:
                out.append(backslash); out.append(letter(102)) // f
            case 13:
                out.append(backslash); out.append(letter(114)) // r
            case 0..<32:
                out.append(backslash)
                for u in String(format: "u%04x", scalar.value).unicodeScalars {
                    out.append(u)
                }
            default:
                out.append(scalar)
            }
        }
        out.append(quote)
        return String(out)
    }

    // Bridges a JSONSerialization value (used by the test suite to load the
    // shared golden vectors).
    public static func from(any value: Any?) throws -> CJSON {
        if value == nil || value is NSNull { return .null }
        if let n = value as? NSNumber {
            if CFGetTypeID(n) == CFBooleanGetTypeID() {
                return .bool(n.boolValue)
            }
            return .int(n.intValue)
        }
        if let s = value as? String { return .string(s) }
        if let a = value as? [Any] { return .array(try a.map { try from(any: $0) }) }
        if let d = value as? [String: Any] {
            var out: [String: CJSON] = [:]
            for (k, v) in d { out[k] = try from(any: v) }
            return .object(out)
        }
        throw InklineError.invalid("cjson: unsupported value")
    }
}

public enum InklineError: Error, CustomStringConvertible {
    case invalid(String)

    public var description: String {
        switch self {
        case .invalid(let message):
            return message
        }
    }
}
