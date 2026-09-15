# Inkline API (draft)

Status: **sketch, seeking design partners.** The notary endpoints below exist
today and are what the Gmail extension uses. The "Partner issuance" section is
the planned generalization. Nothing here is stable yet; if you want to build on
it, email inkline.approved@gmail.com and we will build it with you.

## The primitive

> A human saw exactly this content and approved it with a device biometric —
> and anyone can verify that offline, forever.

Three roles:

- **Client** (your app): shows the user the exact content, asks the OS for a
  biometric-gated signature over its hash.
- **Notary** (Inkline): verifies key enrollment (App Attest where the platform
  supports it), freshness (nonce), and the presence signature; co-signs and
  issues a receipt. Never sees content — hashes only.
- **Verifier** (anyone): checks the receipt offline against the notary's
  public key and the content itself. No account, no network call.

## Current notary endpoints (v1, live)

Base: your deployment of `notary/` (Node, zero deps). All bodies JSON.

### `GET /v1/info`
Trust policy of this notary.
```json
{ "v": 1, "tier": "enclave-unattested", "attested": false,
  "notary": { "pub": "<b64url P-256>", "kid": "<b64url sha256(pub)>" } }
```

### `POST /v1/enroll/challenge` → `{ "challenge": "<b64url 32B>", "exp": <ms> }`
Single-use, 2-minute TTL.

### `POST /v1/enroll`
Registers a presence public key.
- Unattested tier: `{ "challenge", "pub" }`
- Attested tier (not served by the current notary yet; requires Mac App Attest, macOS 27+): `{ "challenge", "keyId", "attestation", "pub", "binding" }`
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
`b64url(cjson({ v, payload, pub, sig, notary: { iat, kid, sig } }))` — the
notary signature covers `"inkline.notary.v1\0" || cjson({iat, payload, pub, sig})`.
Verification is pure math; see `shared/receipt.js` (`verifyReceipt`) and the
static page in `verifier/`.

## Partner issuance (planned)

What changes to make this usable beyond email:

1. **Generic actions.** `payload.action` becomes partner-defined
   (`"payment.approve"`, `"agent.step"`, `"review.publish"` ...) with a
   canonicalization contract per action type published at `/v1/actions`.
2. **API keys + rate limits** per partner; receipts carry the partner id.
3. **Client SDKs.** `inkline.approve({ action, content })` for macOS
   (Swift, Secure Enclave) first; Windows Hello and Android StrongBox next.
4. **Webhooks** on issuance for partner-side audit logs.
5. **Hosted verify page** per partner (`verify.inkline.../p/<partner>`), same
   offline verification.

What will NOT change: verification stays free, open source, and offline; the
notary never receives content; a receipt that verifies today verifies forever.

## Who this is for

Payment/treasury approval flows, AI-agent platforms that need per-action human
authorization, marketplaces and review platforms, hiring tools, e-signature.
If that is you: inkline.approved@gmail.com
