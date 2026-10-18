# Inkline notary protocol (email stamps)

This page documents the email-stamp endpoints of the reference notary in
`notary/`, which is what the Gmail extension and helper use. The hosted
**Approval API** (action approvals, Touch ID or passkey, API keys, webhooks)
runs from a separate service repository and is documented at
https://www.inklineverify.com/docs/api. It is in pilot; to integrate, sign in
to the console at https://www.inklineverify.com/console or email
gigialcaraz38@gmail.com and BhavyaBella@gmail.com.

## The primitive

> A human saw exactly this content and approved it with a device biometric —
> and anyone can verify that offline, forever.

Three roles:

- **Client** (your app): shows the user the exact content, asks the OS for a
  biometric-gated signature over its hash.
- **Notary** (Inkline): verifies key enrollment (App Attest where the platform
  supports it), freshness (nonce), and the presence signature; co-signs and
  issues a receipt. For email stamps it never sees content, only hashes.
- **Verifier** (anyone): checks the receipt offline against the notary's
  public key and the content itself. No account, no network call.

## Notary endpoints (v1)

Base: your deployment of `notary/` (Node, zero deps). All bodies JSON.

### `GET /v1/info`
Trust policy of this notary. The hosted notary also lists `"passkey"` in
`tiers` (Approval API) and adds an `api` object.
```json
{ "v": 1, "tier": "enclave-attested", "tiers": ["enclave-attested"],
  "notary": { "pub": "<b64url P-256>", "kid": "<b64url sha256(pub)>" } }
```

### `POST /v1/enroll/challenge` → `{ "challenge": "<b64url 32B>", "exp": <ms> }`
Single-use, 2-minute TTL.

### `POST /v1/enroll`
Registers a presence public key.
- `{ "challenge", "keyId", "attestation", "pub", "binding" }` — attestation
  is mandatory (Mac App Attest, macOS 27+). A bare `{ "challenge", "pub" }`
  enrollment is refused with
  `{ "error": { "code": "attestation_required", "min_os": "macOS 27" } }`;
  the same error refuses nonces and co-signs for keys enrolled before the
  policy.
  where `attestation` is an Apple App Attest object over
  `sha256("inkline.attest.v1\0" || challenge)` and `binding` an assertion over
  `"inkline.enroll.v1\0" || cjson({challenge, pub})`.

→ `{ "kid": "<b64url sha256(pub)>", "attested": true|false }`

### `POST /v1/nonce`  `{ "kid" }` → `{ "nonce": "<b64url 32B>", "exp": <ms> }`
Single-use, 60-second TTL, bound to the key.

### `POST /v1/cosign`
```json
{ "payload": { "v": 1, "action": "email", "contentHash": "...",
               "nonce": "...", "iat": <sec>, "kid": "..." },
  "pub": "...", "sig": "<b64url 64B r||s>", "assertion": "<b64url, attested tier>" }
```
Checks: enrollment, key match, nonce freshness+ownership, |now−iat| ≤ 120 s,
ECDSA over `"inkline.presence.v1\0" || cjson(payload)`, and (attested tier)
the per-send App Attest assertion with a monotonic counter.
→ `{ "receipt": "<b64url token>" }`

### Receipt format
`b64url(cjson({ v, payload, pub, sig, notary: { iat, kid, sig, tier } }))` —
the notary signature covers
`"inkline.notary.v1\0" || cjson({iat, payload, pub, sig, tier})`, so the tier
cannot be stripped or changed. Receipts issued before tiers existed have no
`tier` and are signed over the four-field shape.
Verification is pure math; see `shared/receipt.js` (`verifyReceipt`) and the
static page in `verifier/`.

## Beyond email

Generic actions, API keys, webhooks, and passkey approvals shipped in the
hosted Approval API (receipt v2): see https://www.inklineverify.com/docs/api.
`shared/action.js` and `packages/inkline-verify` verify those receipts
offline.

What will not change: verification stays free, open source, and offline,
and a receipt that verifies today verifies forever.
