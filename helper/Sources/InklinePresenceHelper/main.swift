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
// One trust tier, mandatory: "enclave-attested". Apple App Attest (macOS
// 27+, provisioned build) proves the Secure Enclave provenance of the
// biometryCurrentSet presence key at enrollment, and every signature adds a
// fresh assertion. On older macOS the helper refuses to enroll or sign with
// a structured os_upgrade_required error — there is no weaker fallback. No
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

let helperVersion = "0.2.0"
let tierAttested = "enclave-attested"

func requireAppAttest() throws -> AppAttest {
    let attest = AppAttest()
    guard attest.isSupported else {
        throw HelperFailure(
            code: "os_upgrade_required",
            message: "Inkline requires macOS 27 or later (App Attest)."
        )
    }
    return attest
}

func runStatus() -> [String: Any] {
    let state = HelperState.load()
    var presenceKeyPresent = false
    if let key = try? PresenceKey.load(), (try? PresenceKey.publicKeyRaw(key)) != nil {
        presenceKeyPresent = true
    }
    return [
        "ok": true,
        "version": helperVersion,
        "enrolled": state.kid != nil && presenceKeyPresent,
        "kid": state.kid ?? NSNull(),
        "mode": state.mode ?? NSNull(),
        "attested": state.attestKeyId != nil,
        "capable": AppAttest().isSupported,
        "presenceKeyPresent": presenceKeyPresent,
        "notary": state.notaryURL ?? defaultNotaryURL,
    ]
}

// Enrollment. App Attest is mandatory: on a Mac that cannot attest (macOS
// before 27, or an unprovisioned build) this fails with os_upgrade_required
// and no state is touched. There is deliberately no weaker path.
func runEnroll(_ arguments: [String]) throws -> [String: Any] {
    let attest = try requireAppAttest()
    let notary = try notaryClient(arguments)
    let info = try notary.info()
    guard info.tiers.contains(tierAttested) else {
        throw HelperFailure(
            code: "notary_tier_mismatch",
            message: "notary serves tiers \(info.tiers), not '\(tierAttested)'"
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
    return try enrollAttested(notary: notary, attest: attest, pub: pub)
}

// The attested path: a fresh App Attest key attests to Apple, then vouches
// for the presence public key; the notary verifies the whole chain.
func enrollAttested(notary: NotaryClient, attest: AppAttest, pub: String) throws -> [String: Any] {
    let challenge = try notary.enrollChallenge()
    guard let challengeBytes = B64.decode(challenge) else {
        throw HelperFailure(code: "bad_challenge", message: "notary challenge is not base64url")
    }

    let attestKeyId = try attest.generateKey()
    guard let attestKeyIdBytes = Data(base64Encoded: attestKeyId) else {
        throw HelperFailure(code: "bad_key_id", message: "App Attest key id is not base64")
    }

    let attestation = try attest.attest(
        keyId: attestKeyId,
        clientDataHash: Presence.enrollAttestClientDataHash(challenge: challengeBytes)
    )
    let binding = try attest.assertion(
        keyId: attestKeyId,
        clientDataHash: Data(SHA256.hash(data: Presence.enrollBindClientData(challenge: challenge, pub: pub)))
    )

    let (kid, environment) = try notary.enrollAttested(
        challenge: challenge,
        keyId: B64.encode(attestKeyIdBytes),
        attestation: B64.encode(attestation),
        pub: pub,
        binding: B64.encode(binding)
    )
    FileHandle.standardError.write(
        "[inkline] attested enrollment (App Attest environment: \(environment ?? "unknown"))\n".data(using: .utf8)!)

    var state = HelperState.load()
    state.kid = kid
    state.notaryURL = notary.baseURL.absoluteString
    state.mode = tierAttested
    state.attestKeyId = attestKeyId
    try state.save()

    return ["ok": true, "kid": kid, "mode": tierAttested, "attested": true,
            "environment": environment ?? NSNull()]
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
    guard let kid = state.kid, let mode = state.mode, let attestKeyId = state.attestKeyId else {
        // Enrolled under the retired unattested policy (or not at all):
        // signing requires an attested enrollment, which requires macOS 27+.
        if AppAttest().isSupported {
            throw HelperFailure(code: "not_enrolled", message: "run: InklinePresenceHelper enroll")
        }
        throw HelperFailure(
            code: "os_upgrade_required",
            message: "Inkline requires macOS 27 or later (App Attest)."
        )
    }
    let attest = try requireAppAttest()
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

    // A fresh App Attest assertion over the same payload the presence key
    // just signed (two keys, one hash). No extra user prompt — the biometric
    // gate already happened above.
    let assertion = B64.encode(try attest.assertion(
        keyId: attestKeyId,
        clientDataHash: Data(SHA256.hash(data: Presence.assertClientData(payload)))
    ))

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
        sig: B64.encode(sig),
        assertion: assertion
    )

    return ["ok": true, "receipt": receipt, "contentHash": contentHash, "kid": kid, "mode": mode]
}

func runReset() throws -> [String: Any] {
    try PresenceKey.destroy()
    var state = HelperState.load()
    state.attestKeyId = nil
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
