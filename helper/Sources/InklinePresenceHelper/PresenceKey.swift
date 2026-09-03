// The presence key: a P-256 keypair generated inside the Secure Enclave whose
// private half only signs after a live biometric match.
//
//   - kSecAttrTokenIDSecureEnclave: the key never exists outside the enclave.
//   - .biometryCurrentSet: signing requires the CURRENTLY enrolled biometrics;
//     adding or removing a fingerprint permanently invalidates the key, which
//     forces a fresh enrollment ceremony.
//   - .privateKeyUsage: the key can be used for signing but never exported.
//
// There is deliberately no passcode fallback and no recovery path. Keys are
// disposable; identity continuity lives in the notary registry.

import CryptoKit
import Foundation
import LocalAuthentication
import Security

enum PresenceKeyError: Error, CustomStringConvertible {
    case secureEnclaveUnavailable(String)
    case keychain(OSStatus, String)
    case notFound
    case signing(String)
    case cancelled

    var description: String {
        switch self {
        case .secureEnclaveUnavailable(let detail):
            return "Secure Enclave key creation failed: \(detail)"
        case .keychain(let status, let op):
            return "keychain error \(status) during \(op)"
        case .notFound:
            return "no presence key found — run enroll first"
        case .signing(let detail):
            return "presence signing failed: \(detail)"
        case .cancelled:
            return "the user cancelled the Touch ID prompt"
        }
    }
}

enum PresenceKey {
    static let applicationTag = Data("com.inkline.presence.v1".utf8)

    static func create() throws -> SecKey {
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &accessError
        ) else {
            let detail = accessError?.takeRetainedValue().localizedDescription ?? "access control"
            throw PresenceKeyError.secureEnclaveUnavailable(detail)
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: applicationTag,
                kSecAttrAccessControl as String: access,
            ],
        ]

        var createError: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &createError) else {
            let detail = createError?.takeRetainedValue().localizedDescription ?? "unknown"
            throw PresenceKeyError.secureEnclaveUnavailable(detail)
        }
        return key
    }

    static func load(context: LAContext? = nil) throws -> SecKey {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: applicationTag,
            kSecReturnRef as String: true,
        ]
        if let context {
            query[kSecUseAuthenticationContext as String] = context
        }
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { throw PresenceKeyError.notFound }
        guard status == errSecSuccess, let key = item else {
            throw PresenceKeyError.keychain(status, "load")
        }
        return (key as! SecKey)
    }

    static func loadOrCreate() throws -> SecKey {
        do {
            return try load()
        } catch PresenceKeyError.notFound {
            return try create()
        }
    }

    static func destroy() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: applicationTag,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw PresenceKeyError.keychain(status, "destroy")
        }
    }

    // 65-byte uncompressed point (0x04 || X || Y).
    static func publicKeyRaw(_ key: SecKey) throws -> Data {
        guard let publicKey = SecKeyCopyPublicKey(key) else {
            throw PresenceKeyError.signing("cannot derive public key")
        }
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            let detail = error?.takeRetainedValue().localizedDescription ?? "export"
            throw PresenceKeyError.signing(detail)
        }
        return data
    }

    // Signs the domain-tagged payload bytes. The Secure Enclave enforces the
    // biometric gate here: this call blocks on the system Touch ID prompt,
    // whose reason string is composed from the exact content being signed.
    static func sign(input: Data, reason: String, context: LAContext? = nil) throws -> Data {
        let context = context ?? LAContext()
        context.localizedReason = reason
        let key = try load(context: context)

        var error: Unmanaged<CFError>?
        guard let der = SecKeyCreateSignature(
            key,
            .ecdsaSignatureMessageX962SHA256,
            input as CFData,
            &error
        ) as Data? else {
            let cfError = error?.takeRetainedValue()
            if let cfError, isUserCancel(cfError) { throw PresenceKeyError.cancelled }
            let detail = cfError?.localizedDescription ?? "unknown"
            throw PresenceKeyError.signing(detail)
        }
        // Receipts carry raw r||s (64 bytes), matching WebCrypto.
        let signature = try P256.Signing.ECDSASignature(derRepresentation: der)
        return signature.rawRepresentation
    }

    // The Touch ID sheet was dismissed (by the user, by the system, or because
    // the helper invalidated its LAContext). Anything else is a real failure.
    private static func isUserCancel(_ error: CFError) -> Bool {
        let nsError = error as Error as NSError
        if nsError.domain == LAErrorDomain {
            switch LAError.Code(rawValue: nsError.code) {
            case .userCancel, .systemCancel, .appCancel, .invalidContext, .userFallback:
                return true
            default:
                return false
            }
        }
        // errSecUserCanceled: Security.framework's wrapping of the same event.
        return nsError.domain == NSOSStatusErrorDomain && nsError.code == Int(errSecUserCanceled)
    }
}
