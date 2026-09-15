// Synchronous JSON client for the Inkline notary. The notary never receives
// email content — only hashes, keys, and signatures.

import Foundation

enum NotaryError: Error, CustomStringConvertible {
    case transport(String)
    case api(code: String, message: String)
    case malformed(String)

    var description: String {
        switch self {
        case .transport(let detail): return "notary unreachable: \(detail)"
        case .api(let code, let message): return "notary refused (\(code)): \(message)"
        case .malformed(let detail): return "notary response malformed: \(detail)"
        }
    }
}

struct NotaryClient {
    let baseURL: URL

    struct Info {
        let tier: String        // compat field; the notary's baseline tier
        let tiers: [String]     // every tier this notary serves
        let pub: String
        let kid: String
    }

    func info() throws -> Info {
        let body = try request("GET", "/v1/info")
        guard let tier = body["tier"] as? String,
              let notary = body["notary"] as? [String: Any],
              let pub = notary["pub"] as? String,
              let kid = notary["kid"] as? String
        else { throw NotaryError.malformed("info") }
        let tiers = body["tiers"] as? [String] ?? [tier]
        return Info(tier: tier, tiers: tiers, pub: pub, kid: kid)
    }

    func enrollChallenge() throws -> String {
        let body = try request("POST", "/v1/enroll/challenge", [:])
        guard let challenge = body["challenge"] as? String else {
            throw NotaryError.malformed("enroll/challenge")
        }
        return challenge
    }

    // Attested enrollment: the App Attest material proves to the notary that
    // the key came from a genuine Secure Enclave inside the signed helper.
    // Returns the kid and the Apple environment the notary verified against.
    func enrollAttested(
        challenge: String, keyId: String, attestation: String, pub: String, binding: String
    ) throws -> (kid: String, environment: String?) {
        let body = try request("POST", "/v1/enroll", [
            "challenge": challenge,
            "keyId": keyId,
            "attestation": attestation,
            "pub": pub,
            "binding": binding,
        ])
        guard let kid = body["kid"] as? String else { throw NotaryError.malformed("enroll") }
        return (kid, body["environment"] as? String)
    }

    func nonce(kid: String) throws -> String {
        let body = try request("POST", "/v1/nonce", ["kid": kid])
        guard let nonce = body["nonce"] as? String else { throw NotaryError.malformed("nonce") }
        return nonce
    }

    func cosign(payload: [String: Any], pub: String, sig: String, assertion: String? = nil) throws -> String {
        var req: [String: Any] = ["payload": payload, "pub": pub, "sig": sig]
        if let assertion { req["assertion"] = assertion }
        let body = try self.request("POST", "/v1/cosign", req)
        guard let receipt = body["receipt"] as? String else { throw NotaryError.malformed("cosign") }
        return receipt
    }

    private func request(_ method: String, _ path: String, _ body: [String: Any]? = nil) throws -> [String: Any] {
        var req = URLRequest(url: baseURL.appendingPathComponent(path))
        req.httpMethod = method
        req.timeoutInterval = 15
        if let body {
            req.setValue("application/json", forHTTPHeaderField: "content-type")
            req.httpBody = try? JSONSerialization.data(withJSONObject: body)
        }

        let semaphore = DispatchSemaphore(value: 0)
        var outcome: Result<(Int, Data), Error> = .failure(NotaryError.transport("no response"))
        URLSession.shared.dataTask(with: req) { data, response, error in
            if let error {
                outcome = .failure(NotaryError.transport(error.localizedDescription))
            } else if let http = response as? HTTPURLResponse, let data {
                outcome = .success((http.statusCode, data))
            } else {
                outcome = .failure(NotaryError.transport("not http"))
            }
            semaphore.signal()
        }.resume()
        semaphore.wait()

        let (status, data) = try outcome.get()
        guard let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            throw NotaryError.malformed("non-JSON response (status \(status))")
        }
        if status != 200 {
            let err = json["error"] as? [String: Any]
            throw NotaryError.api(
                code: err?["code"] as? String ?? "http_\(status)",
                message: err?["message"] as? String ?? "unknown error"
            )
        }
        return json
    }
}
