// inkline-verify: verify an Inkline receipt offline, in Node or the browser.
//
//   import { verify, INKLINE_NOTARY_PUB } from 'inkline-verify';
//   const result = await verify(receipt, { notaryPub: INKLINE_NOTARY_PUB, email });
//   // result.ok, result.kind ('email' | 'action'), result.tier, result.checks, result.error
//
// `receipt` is the base64url string from a stamp or approval link (the part
// after '#'). For email receipts pass `email: { from, to, cc, subject, body }`
// as received; for action receipts nothing else is needed. `notaryPub` is
// the notary's public key obtained out of band — the hosted Inkline notary's
// key is exported below. Nothing here makes a network request.

import { verifyReceipt, decodeReceipt } from './shared/receipt.js';
import { verifyActionReceipt, receiptKind } from './shared/action.js';

export { verifyReceipt, verifyActionReceipt, decodeReceipt, receiptKind };

// Public key of the hosted Inkline notary (https://inkline-notary-production.up.railway.app),
// as served by GET /v1/info. Pin it, or fetch and compare.
export const INKLINE_NOTARY_PUB = 'BDnq31ChitMD2Ui8k6a2XV7YgBMr96X5LLgK5Gch8Cw1HMrUm_4h4ENBx0cHO8rYXys_Plxlw125dLFPPF5VWW0';

export const TIERS = {
  'enclave-attested': 'Touch ID on a Mac; Apple App Attest certified the Secure Enclave key.',
  passkey: 'WebAuthn passkey on any device; not hardware-attested.',
  legacy: 'Issued before hardware attestation became part of every stamp.',
};

export async function verify(receipt, { notaryPub = INKLINE_NOTARY_PUB, email } = {}) {
  let kind;
  try {
    kind = receiptKind(decodeReceipt(String(receipt).trim()));
  } catch {
    return { ok: false, kind: null, tier: null, checks: {}, error: 'receipt: not decodable' };
  }
  if (kind === 'action') {
    const r = await verifyActionReceipt({ receipt: String(receipt).trim(), notaryPub });
    return { ok: r.ok, kind, tier: r.ok ? r.tier : null, checks: r.checks, error: r.error, receipt: r.receipt };
  }
  if (!email) return { ok: false, kind: 'email', tier: null, checks: {}, error: 'email receipts need the email { from, to, cc, subject, body }' };
  const r = await verifyReceipt({ receipt: String(receipt).trim(), email, notaryPub });
  return { ok: r.ok, kind: 'email', tier: r.ok ? (r.tier ?? 'legacy') : null, checks: r.checks, error: r.error, payload: r.payload };
}
