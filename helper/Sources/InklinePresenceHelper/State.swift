// Non-secret local state: the enrolled kid, the notary URL, and the
// enrollment mode. The key itself lives in the Secure Enclave — this file
// holds only identifiers.

import Foundation

struct HelperState: Codable {
    var kid: String?
    var notaryURL: String?
    // Always "enclave-unattested" — the single supported tier.
    var mode: String?

    static var fileURL: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("Inkline/state.json")
    }

    static func load() -> HelperState {
        guard let data = try? Data(contentsOf: fileURL),
              let state = try? JSONDecoder().decode(HelperState.self, from: data)
        else { return HelperState() }
        return state
    }

    func save() throws {
        let dir = HelperState.fileURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let data = try JSONEncoder().encode(self)
        try data.write(to: HelperState.fileURL, options: .atomic)
    }
}
