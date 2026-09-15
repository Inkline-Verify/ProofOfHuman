// Non-secret local state: the enrolled kid, the notary URL, the enrollment
// mode, and (attested tier) the App Attest key identifier. Keys themselves
// live in the Secure Enclave / DeviceCheck subsystem — this file holds only
// identifiers.

import Foundation

struct HelperState: Codable {
    var kid: String?
    var notaryURL: String?
    // "enclave-attested" (App Attest, macOS 27+) or "enclave-unattested".
    var mode: String?
    // Apple's identifier for the App Attest key; attested tier only.
    var attestKeyId: String?

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
