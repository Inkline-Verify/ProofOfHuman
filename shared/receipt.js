// Inkline receipt v1: the offline-verifiable proof that travels with an email.
//
// Trust model:
//   - The presence signature comes from a Secure Enclave P-256 key that only
//     signs after a live biometric match (biometryCurrentSet).
//   - The notary co-signature attests that, at issuance time, the notary
//     verified: the presence key was previously enrolled at the tier named
//     in the notary block ("enclave-attested": Apple App Attest certified
//     the key's Secure Enclave provenance; receipts without a tier predate
//     attestation), the server-issued nonce was live and single-use, and
//     the presence signature checked out.
//   - A recipient verifies both signatures offline against the notary's
//     published public key plus the email content itself. No network calls.
//
// Every signing input is prefixed with a NUL-terminated domain tag so a
// signature can never be replayed across contexts.

import { cjson } from './cjson.js';
import {
  b64uEncode,
  b64uDecode,
  bytesEqual,
  concatBytes,
  sha256,
  utf8,
  utf8Decode,
} from './b64.js';
import { emailContentHash } from './canonical.js';

export const TAG_PRESENCE = 'inkline.presence.v1\u0000';
export const TAG_ASSERT = 'inkline.assert.v1\u0000';
export const TAG_ENROLL_ATTEST = 'inkline.attest.v1\u0000';
export const TAG_ENROLL_BIND = 'inkline.enroll.v1\u0000';
export const TAG_NOTARY = 'inkline.notary.v1\u0000';

export const PAYLOAD_ACTION = 'email';

// payload = {v:1, action:"email", contentHash, nonce, iat, kid}
export function presenceSignInput(payload) {
  return concatBytes(utf8(TAG_PRESENCE), utf8(cjson(payload)));
}

// tier is present only in attested-era receipts; including it in the signed
// bytes means it cannot be stripped or altered without breaking the notary
// signature. Receipts issued before tiers existed omit it and verify with
// the original four-field shape.
export function notarySignInput({ iat, payload, pub, sig, tier }) {
  const body = { iat, payload, pub, sig };
  if (tier !== undefined) body.tier = tier;
  return concatBytes(utf8(TAG_NOTARY), utf8(cjson(body)));
}

// Client data covered by the per-send App Attest assertion (attested tier).
export function assertClientData(payload) {
  return concatBytes(utf8(TAG_ASSERT), utf8(cjson(payload)));
}

// Client data hash covered by the one-time App Attest key attestation.
export async function enrollAttestClientDataHash(challengeB64u) {
  return sha256(concatBytes(utf8(TAG_ENROLL_ATTEST), b64uDecode(challengeB64u)));
}

// Client data covered by the enrollment assertion that binds the presence
// public key to the attested App Attest key.
export function enrollBindClientData(challengeB64u, presencePubB64u) {
  return concatBytes(
    utf8(TAG_ENROLL_BIND),
    utf8(cjson({ challenge: challengeB64u, pub: presencePubB64u }))
  );
}

export async function kidOfPub(pubB64u) {
  const raw = b64uDecode(pubB64u);
  if (raw.length !== 65 || raw[0] !== 0x04) {
    throw new Error('kid: public key must be a 65-byte uncompressed P-256 point');
  }
  return b64uEncode(await sha256(raw));
}

export async function p256Verify(pubRaw, sigRaw, message) {
  if (sigRaw.length !== 64) return false;
  let key;
  try {
    key = await globalThis.crypto.subtle.importKey(
      'raw',
      pubRaw,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
  } catch {
    return false;
  }
  return globalThis.crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    sigRaw,
    message
  );
}

export function validatePayload(p) {
  if (p === null || typeof p !== 'object' || Array.isArray(p)) return 'payload: not an object';
  if (p.v !== 1) return 'payload: unsupported version';
  if (p.action !== PAYLOAD_ACTION) return 'payload: unsupported action';
  for (const k of ['contentHash', 'nonce', 'kid']) {
    if (typeof p[k] !== 'string' || p[k].length === 0) return `payload: missing ${k}`;
  }
  if (!Number.isSafeInteger(p.iat) || p.iat <= 0) return 'payload: bad iat';
  const keys = Object.keys(p).sort().join(',');
  if (keys !== 'action,contentHash,iat,kid,nonce,v') return 'payload: unexpected fields';
  return null;
}

export function encodeReceipt(receipt) {
  return b64uEncode(utf8(cjson(receipt)));
}

export function decodeReceipt(receiptB64u) {
  return JSON.parse(utf8Decode(b64uDecode(receiptB64u)));
}

// Full offline verification. `email` is {from, to, cc, subject, body} as the
// recipient sees it; `notaryPub` is the trusted notary public key (b64url raw
// point), obtained out of band.
export async function verifyReceipt({ receipt, email, notaryPub }) {
  const checks = {
    decode: false,
    payload: false,
    contentHash: false,
    kid: false,
    presenceSig: false,
    notaryKid: false,
    notarySig: false,
  };
  const fail = (error) => ({ ok: false, checks, error, payload: null, tier: null });

  let r;
  try {
    r = decodeReceipt(receipt);
  } catch {
    return fail('receipt: not decodable');
  }
  if (r === null || typeof r !== 'object' || r.v !== 1) return fail('receipt: bad envelope');
  if (typeof r.pub !== 'string' || typeof r.sig !== 'string') return fail('receipt: bad envelope');
  const n = r.notary;
  if (
    n === null ||
    typeof n !== 'object' ||
    typeof n.kid !== 'string' ||
    typeof n.sig !== 'string' ||
    !Number.isSafeInteger(n.iat) ||
    (n.tier !== undefined && typeof n.tier !== 'string')
  ) {
    return fail('receipt: bad notary block');
  }
  checks.decode = true;

  const payloadError = validatePayload(r.payload);
  if (payloadError) return fail(payloadError);
  checks.payload = true;

  const expectedHash = await emailContentHash(email);
  if (expectedHash !== r.payload.contentHash) {
    return fail('content: email does not match the signed content hash');
  }
  checks.contentHash = true;

  let pubRaw;
  try {
    pubRaw = b64uDecode(r.pub);
    if ((await kidOfPub(r.pub)) !== r.payload.kid) throw new Error();
  } catch {
    return fail('kid: presence key does not match payload kid');
  }
  checks.kid = true;

  let sigRaw;
  try {
    sigRaw = b64uDecode(r.sig);
  } catch {
    return fail('presence: signature not decodable');
  }
  if (!(await p256Verify(pubRaw, sigRaw, presenceSignInput(r.payload)))) {
    return fail('presence: signature invalid');
  }
  checks.presenceSig = true;

  let notaryPubRaw;
  try {
    notaryPubRaw = b64uDecode(notaryPub);
    if ((await kidOfPub(notaryPub)) !== n.kid) throw new Error();
  } catch {
    return fail('notary: receipt was not issued by this notary key');
  }
  checks.notaryKid = true;

  let notarySigRaw;
  try {
    notarySigRaw = b64uDecode(n.sig);
  } catch {
    return fail('notary: signature not decodable');
  }
  const signedBytes = notarySignInput({
    iat: n.iat,
    payload: r.payload,
    pub: r.pub,
    sig: r.sig,
    tier: n.tier,
  });
  if (!(await p256Verify(notaryPubRaw, notarySigRaw, signedBytes))) {
    return fail('notary: signature invalid');
  }
  checks.notarySig = true;

  return { ok: true, checks, error: null, payload: r.payload, tier: n.tier ?? null };
}

export { bytesEqual };
