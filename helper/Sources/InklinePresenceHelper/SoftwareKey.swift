// DEVELOPMENT-ONLY presence key.
//
// Used only when enrollment was run with --dev on a machine where the real
// path is unavailable (unsigned build, no Secure Enclave access, or App
// Attest unsupported — Mac App Attest requires macOS 27+ and a provisioned
// bundle). The key is a software P-256 key on disk: it preserves the exact
// user experience (a real system authentication prompt gates every signature)
// but it is NOT hardware-bound and proves nothing an agent couldn't fake by
// editing this file's code. Notaries only accept it under the explicit
// 'attestation: none' development policy, and mark the enrollment unattested.

import CryptoKit
import Foundation
import LocalAuthentication

enum SoftwareKeyError: Error, CustomStringConvertible {
    case notFound
    case authenticationFailed(String)

    var description: String {
        switch self {
        case .notFound:
            return "no dev software key found — run enroll --dev first"
        case .authenticationFailed(let detail):
            return "authentication failed: \(detail)"
        }
    }
}

enum SoftwareKey {
    static var fileURL: URL {
        HelperState.fileURL.deletingLastPathComponent()
            .appendingPathComponent("dev-software-key.bin")
    }

    static func load() -> P256.Signing.PrivateKey? {
        guard let data = try? Data(contentsOf: fileURL) else { return nil }
        return try? P256.Signing.PrivateKey(rawRepresentation: data)
    }

    static func loadOrCreate() throws -> P256.Signing.PrivateKey {
        if let existing = load() { return existing }
        let key = P256.Signing.PrivateKey()
        let dir = fileURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try key.rawRepresentation.write(to: fileURL, options: .completeFileProtection)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
        return key
    }

    static func destroy() {
        try? FileManager.default.removeItem(at: fileURL)
    }

    static func publicKeyRaw() throws -> Data {
        guard let key = load() else { throw SoftwareKeyError.notFound }
        return key.publicKey.x963Representation
    }

    // Gates the signature behind a live system authentication prompt —
    // biometrics where available, device passcode otherwise (dev machines
    // without Touch ID). The gate is UX-faithful, not enclave-enforced.
    static func sign(input: Data, reason: String) throws -> Data {
        guard let key = load() else { throw SoftwareKeyError.notFound }

        let context = LAContext()
        var policyError: NSError?
        let policy: LAPolicy = context.canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics, error: &policyError
        ) ? .deviceOwnerAuthenticationWithBiometrics : .deviceOwnerAuthentication

        let semaphore = DispatchSemaphore(value: 0)
        var outcome: Result<Void, Error> = .failure(SoftwareKeyError.authenticationFailed("no response"))
        context.evaluatePolicy(policy, localizedReason: reason) { success, error in
            if success {
                outcome = .success(())
            } else {
                outcome = .failure(SoftwareKeyError.authenticationFailed(
                    error?.localizedDescription ?? "denied"))
            }
            semaphore.signal()
        }
        semaphore.wait()
        try outcome.get()

        return try key.signature(for: input).rawRepresentation
    }
}
