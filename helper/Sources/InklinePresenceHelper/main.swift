// InklinePresenceHelper — the native trust anchor.
//
// Commands:
//   InklinePresenceHelper status
//   InklinePresenceHelper enroll  [--notary URL]
//   InklinePresenceHelper sign    --request <path|->  [--notary URL]
//   InklinePresenceHelper native                       (Chrome native-messaging stdio)
//   InklinePresenceHelper reset                        (destroys the local presence key)
//
// A sign request is JSON:
//   { "type": "sign",
//     "email": { "from": "...", "to": ["..."], "cc": ["..."],
//                "subject": "...", "body": "..." } }
//
// The helper canonicalizes the email itself, renders the canonical form for
// approval, obtains the biometric-gated Secure Enclave signature over the
// payload, and exchanges it at the notary for an offline-verifiable receipt.
// It has no code path that signs a hash it was handed.
//
// Single trust tier: "enclave-unattested" — a Secure Enclave P-256 key gated
// by biometryCurrentSet. The notary records the key as attested: false; no
// Apple App Attest material is produced or sent (the isSupported log line at
// startup is informational only).

import AppKit
import CryptoKit
import DeviceCheck
import Foundation
import InklineCore
import LocalAuthentication

// The hosted notary. Override with INKLINE_NOTARY_URL or `enroll --notary`
// (a URL given at enrollment is saved and used for all later signing).
let defaultNotaryURL = ProcessInfo.processInfo.environment["INKLINE_NOTARY_URL"]
    ?? "https://inkline-notary-production.up.railway.app"

struct HelperFailure: Error {
    let code: String
    let message: String
}

func notaryClient(_ arguments: [String]) throws -> NotaryClient {
    var urlString = defaultNotaryURL
    if let index = arguments.firstIndex(of: "--notary"), index + 1 < arguments.count {
        urlString = arguments[index + 1]
    }
    if let saved = HelperState.load().notaryURL, !arguments.contains("--notary") {
        urlString = saved
    }
    guard let url = URL(string: urlString) else {
        throw HelperFailure(code: "bad_notary_url", message: "invalid notary URL: \(urlString)")
    }
    return NotaryClient(baseURL: url)
}

func emitJSON(_ object: [String: Any]) {
    let data = (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data()
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data([10]))
}

func failureJSON(_ error: Error) -> [String: Any] {
    if let f = error as? HelperFailure {
        return ["ok": false, "error": ["code": f.code, "message": f.message]]
    }
    return ["ok": false, "error": ["code": "error", "message": String(describing: error)]]
}

// MARK: - Commands

let enrollmentMode = "enclave-unattested"

func runStatus() -> [String: Any] {
    let state = HelperState.load()
    var presenceKeyPresent = false
    if let key = try? PresenceKey.load(), (try? PresenceKey.publicKeyRaw(key)) != nil {
        presenceKeyPresent = true
    }
    return [
        "ok": true,
        "enrolled": state.kid != nil && presenceKeyPresent,
        "kid": state.kid ?? NSNull(),
        "mode": state.mode ?? NSNull(),
        "attested": false,
        "presenceKeyPresent": presenceKeyPresent,
        "notary": state.notaryURL ?? defaultNotaryURL,
    ]
}

// The one enrollment path: create (or reuse) the Secure Enclave presence key
// and register its public half with the notary as an unattested key.
func runEnroll(_ arguments: [String]) throws -> [String: Any] {
    let notary = try notaryClient(arguments)
    let info = try notary.info()
    guard info.tier == enrollmentMode else {
        throw HelperFailure(
            code: "notary_tier_mismatch",
            message: "notary advertises tier '\(info.tier)'; this helper enrolls as '\(enrollmentMode)'"
        )
    }

    let key: SecKey
    do {
        key = try PresenceKey.loadOrCreate()
    } catch {
        throw HelperFailure(
            code: "secure_enclave_unavailable",
            message: "cannot create the Secure Enclave presence key: \(error). "
                + "Inkline requires a Mac with Touch ID enrolled and a signed helper bundle."
        )
    }
    let pub = B64.encode(try PresenceKey.publicKeyRaw(key))

    let challenge = try notary.enrollChallenge()
    let kid = try notary.enroll(challenge: challenge, pub: pub)

    var state = HelperState.load()
    state.kid = kid
    state.notaryURL = notary.baseURL.absoluteString
    state.mode = enrollmentMode
    try state.save()

    return ["ok": true, "kid": kid, "mode": enrollmentMode, "attested": false]
}

func parseEmail(_ dict: [String: Any]?) throws -> Canonical.Email {
    guard let dict,
          let from = dict["from"] as? String, !from.isEmpty,
          let to = dict["to"] as? [String], !to.isEmpty
    else {
        throw HelperFailure(code: "bad_request", message: "email requires from and a non-empty to[]")
    }
    return Canonical.Email(
        from: from,
        to: to,
        cc: dict["cc"] as? [String] ?? [],
        subject: dict["subject"] as? String ?? "",
        body: dict["body"] as? String ?? ""
    )
}

func runSign(email rawEmail: Canonical.Email, arguments: [String]) throws -> [String: Any] {
    let state = HelperState.load()
    guard let kid = state.kid, state.mode == enrollmentMode else {
        throw HelperFailure(code: "not_enrolled", message: "run: InklinePresenceHelper enroll")
    }
    let notary = try notaryClient(arguments)

    // Canonicalize once; render and sign exactly this.
    let canonical = rawEmail.canonical()
    let contentHash = canonical.contentHash()

    // The system Touch ID prompt names the exact recipient and subject being
    // signed: a second, OS-rendered display of the approved action.
    let reason = "sign the email to \(canonical.to.joined(separator: ", "))"
        + (canonical.subject.isEmpty ? "" : " about \u{201c}\(canonical.subject)\u{201d}")

    // The confirmation window and the Touch ID prompt appear together: one
    // touch approves and signs, no extra click. The nonce (~60 s lifetime) is
    // fetched on the signing thread right before the prompt, so it only starts
    // ticking once the human can act on it.
    let payload: Presence.Payload
    let sig: Data
    do {
        (payload, sig) = try Approval.requestApproval(canonical: canonical) { context in
            let nonce = try notary.nonce(kid: kid)
            let payload = Presence.Payload(
                contentHash: contentHash,
                nonce: nonce,
                iat: Int(Date().timeIntervalSince1970),
                kid: kid
            )
            let sig = try PresenceKey.sign(
                input: Presence.presenceSignInput(payload),
                reason: reason,
                context: context
            )
            return (payload, sig)
        }
    } catch PresenceKeyError.cancelled {
        throw HelperFailure(code: "declined", message: "the user declined to approve this email")
    }

    let pub = B64.encode(try PresenceKey.publicKeyRaw(try PresenceKey.load()))

    let receipt = try notary.cosign(
        payload: [
            "v": 1,
            "action": "email",
            "contentHash": payload.contentHash,
            "nonce": payload.nonce,
            "iat": payload.iat,
            "kid": payload.kid,
        ],
        pub: pub,
        sig: B64.encode(sig)
    )

    return ["ok": true, "receipt": receipt, "contentHash": contentHash, "kid": kid, "mode": enrollmentMode]
}

func runReset() throws -> [String: Any] {
    try PresenceKey.destroy()
    var state = HelperState.load()
    state.kid = nil
    state.mode = nil
    try state.save()
    return ["ok": true, "message": "presence key destroyed; enroll again to continue"]
}

func handleRequest(_ request: [String: Any], arguments: [String]) -> [String: Any] {
    do {
        switch request["type"] as? String {
        case "sign":
            let email = try parseEmail(request["email"] as? [String: Any])
            return try runSign(email: email, arguments: arguments)
        case "status":
            return runStatus()
        default:
            throw HelperFailure(code: "bad_request", message: "unknown request type")
        }
    } catch {
        return failureJSON(error)
    }
}

// MARK: - Entry

let app = NSApplication.shared
app.setActivationPolicy(.accessory)

// App Attest gate: logged on every launch so the tier the helper will run at
// is visible in Chrome's native-host log / the terminal. stderr, never stdout
// (stdout is the native-messaging channel).
FileHandle.standardError.write(
    "[inkline] DCAppAttestService.isSupported = \(DCAppAttestService.shared.isSupported)\n".data(using: .utf8)!)

let arguments = Array(CommandLine.arguments.dropFirst())
// Chrome launches native-messaging hosts with the extension origin as the
// first argument (chrome-extension://<id>/); that invocation is the stdio
// protocol, not a CLI command.
let command: String
if let first = arguments.first, !first.hasPrefix("chrome-extension://") {
    command = first
} else {
    command = "native"
}

switch command {
case "status":
    emitJSON(runStatus())

case "enroll":
    do { emitJSON(try runEnroll(arguments)) } catch {
        emitJSON(failureJSON(error))
        exit(1)
    }

case "reset":
    do { emitJSON(try runReset()) } catch {
        emitJSON(failureJSON(error))
        exit(1)
    }

case "sign":
    do {
        guard let index = arguments.firstIndex(of: "--request"), index + 1 < arguments.count else {
            throw HelperFailure(code: "bad_request", message: "sign requires --request <path|->")
        }
        let source = arguments[index + 1]
        let data: Data
        if source == "-" {
            data = FileHandle.standardInput.readDataToEndOfFile()
        } else {
            data = try Data(contentsOf: URL(fileURLWithPath: source))
        }
        guard let request = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            throw HelperFailure(code: "bad_request", message: "request is not a JSON object")
        }
        emitJSON(handleRequest(request, arguments: arguments))
    } catch {
        emitJSON(failureJSON(error))
        exit(1)
    }

case "native":
    while let request = NativeMessaging.readMessage() {
        NativeMessaging.writeMessage(handleRequest(request, arguments: arguments))
    }

default:
    emitJSON(["ok": false, "error": ["code": "bad_command",
                                     "message": "commands: status, enroll, sign, native, reset"]])
    exit(1)
}
