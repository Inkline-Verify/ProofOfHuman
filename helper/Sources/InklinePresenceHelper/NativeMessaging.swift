// Chrome native-messaging framing: 4-byte little-endian length prefix + JSON.
//
// The channel is deliberately UNAUTHENTICATED. Whoever connects, the helper
// only ever signs content it canonicalized and rendered itself, behind a
// biometric gate — the human at the screen is the authorization. There is no
// message that accepts a pre-computed hash.

import Foundation

enum NativeMessaging {
    static func readMessage() -> [String: Any]? {
        let stdin = FileHandle.standardInput
        guard let header = try? stdin.read(upToCount: 4), header.count == 4 else { return nil }
        let length = header.withUnsafeBytes { $0.load(as: UInt32.self) }.littleEndian
        guard length > 0, length <= 4_000_000 else { return nil }
        guard let body = try? stdin.read(upToCount: Int(length)), body.count == Int(length) else {
            return nil
        }
        return (try? JSONSerialization.jsonObject(with: body)) as? [String: Any]
    }

    static func writeMessage(_ message: [String: Any]) {
        guard let body = try? JSONSerialization.data(withJSONObject: message) else { return }
        var length = UInt32(body.count).littleEndian
        let header = Data(bytes: &length, count: 4)
        let stdout = FileHandle.standardOutput
        try? stdout.write(contentsOf: header)
        try? stdout.write(contentsOf: body)
    }
}
