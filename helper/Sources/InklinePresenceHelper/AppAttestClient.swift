// Apple App Attest: proves to the notary that the enrollment and every
// receipt request come from this genuine, legitimately signed app on genuine
// Apple hardware. This is what stops a plain software key from masquerading
// as an enclave-backed one at registration time.
//
// App Attest requires a signed, provisioned build (macOS 27+ for Mac apps).
// There is intentionally no fallback: if attestation is unsupported, Inkline
// refuses to enroll rather than issuing a weaker tier of proof.

import DeviceCheck
import Foundation

enum AppAttestError: Error, CustomStringConvertible {
    case unsupported
    case failed(String)

    var description: String {
        switch self {
        case .unsupported:
            return "App Attest is not supported for this build. Inkline requires a signed app "
                + "with the App Attest entitlement on hardware that supports it; it will not "
                + "fall back to an unattested (spoofable) mode."
        case .failed(let detail):
            return "App Attest operation failed: \(detail)"
        }
    }
}

struct AppAttestClient {
    private let service = DCAppAttestService.shared

    var isSupported: Bool { service.isSupported }

    func generateKey() throws -> String {
        try requireSupported()
        return try wait { done in
            service.generateKey { keyId, error in done(keyId, error) }
        }
    }

    func attest(keyId: String, clientDataHash: Data) throws -> Data {
        try requireSupported()
        return try wait { done in
            service.attestKey(keyId, clientDataHash: clientDataHash) { blob, error in
                done(blob, error)
            }
        }
    }

    func assertion(keyId: String, clientDataHash: Data) throws -> Data {
        try requireSupported()
        return try wait { done in
            service.generateAssertion(keyId, clientDataHash: clientDataHash) { blob, error in
                done(blob, error)
            }
        }
    }

    private func requireSupported() throws {
        guard service.isSupported else { throw AppAttestError.unsupported }
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
