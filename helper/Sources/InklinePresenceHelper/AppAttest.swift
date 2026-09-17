// Apple App Attest client — the hardware-provenance half of the attested
// tier. On macOS 27+ with a provisioned, signed helper, DCAppAttestService
// reports isSupported and the enclave can prove key provenance to the
// notary; everywhere else the helper refuses to enroll or sign (no weaker tier).
//
// The service's async callbacks are bridged to synchronous calls because the
// helper's command flow is synchronous end to end.

import DeviceCheck
import Foundation

enum AppAttestError: Error, CustomStringConvertible {
    case failed(String)

    var description: String {
        switch self {
        case .failed(let detail):
            return "App Attest operation failed: \(detail)"
        }
    }
}

struct AppAttest {
    private let service = DCAppAttestService.shared

    var isSupported: Bool { service.isSupported }

    // Returns Apple's key identifier (a base64 string naming a key that
    // lives in the DeviceCheck subsystem, distinct from the presence key).
    func generateKey() throws -> String {
        try wait { done in service.generateKey { done($0, $1) } }
    }

    // One-time attestation: Apple's certificate chain over this key,
    // bound to clientDataHash.
    func attest(keyId: String, clientDataHash: Data) throws -> Data {
        try wait { done in service.attestKey(keyId, clientDataHash: clientDataHash) { done($0, $1) } }
    }

    // Per-use assertion with a monotonic counter, bound to clientDataHash.
    func assertion(keyId: String, clientDataHash: Data) throws -> Data {
        try wait { done in service.generateAssertion(keyId, clientDataHash: clientDataHash) { done($0, $1) } }
    }

    private func wait<T>(_ operation: (@escaping (T?, Error?) -> Void) -> Void) throws -> T {
        let semaphore = DispatchSemaphore(value: 0)
        var result: Result<T, Error> = .failure(AppAttestError.failed("no response"))
        operation { value, error in
            if let value {
                result = .success(value)
            } else {
                result = .failure(AppAttestError.failed(error?.localizedDescription ?? "unknown"))
            }
            semaphore.signal()
        }
        semaphore.wait()
        return try result.get()
    }
}
