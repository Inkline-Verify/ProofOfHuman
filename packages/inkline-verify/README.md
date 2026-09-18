# inkline-verify

Verify an [Inkline](https://www.inklineverify.com) receipt offline. Works in
Node 20+ and in browsers. No network calls, no dependencies.

```sh
npm install inkline-verify
```

```js
import { verify } from 'inkline-verify';

// From an approval webhook or GET /v1/challenges/:id
const result = await verify(receipt);
if (result.ok) {
  console.log(result.kind);   // 'action'
  console.log(result.tier);   // 'enclave-attested' | 'passkey'
  console.log(result.receipt.canonical_action.description);
} else {
  console.log(result.error);  // e.g. 'notary: receipt was not issued by this notary key'
}
```

Email stamps need the email as received:

```js
const result = await verify(receipt, {
  email: { from, to: [to], cc: [], subject, body },
});
```

`result.checks` lists each check that ran and whether it passed. The tier
tells you what the signature proves: `enclave-attested` means Apple's App
Attest certified the signing key lives in a Mac's Secure Enclave; `passkey`
means a WebAuthn credential the person's device verified, with no hardware
attestation; `legacy` means an email stamp issued before attestation.

By default receipts are checked against the hosted Inkline notary's public
key (`INKLINE_NOTARY_PUB`). Pass `notaryPub` to verify against another
notary. Never fetch the key from the receipt itself.

The code is the same `shared/` module the notary and the public verify page
use, published unchanged. Source: github.com/Inkline-Verify/ProofOfHuman.
