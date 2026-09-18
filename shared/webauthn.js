// WebAuthn primitives shared by the notary (server-side ceremony checks) and
// the verifier (offline receipt checks). Browser-safe: no Node imports.
//
// The passkey tier: a person approves an action with a platform passkey
// (Touch ID, Face ID, Windows Hello, a security key) in their browser. The
// authenticator signs `authenticatorData || SHA-256(clientDataJSON)`; the
// server-issued challenge inside clientDataJSON embeds the action hash, so
// the signature is bound to exactly this canonical action. WebAuthn
// registration uses attestation "none": nothing proves what hardware holds
// the credential, so the verify page describes this tier by what the passkey
// proves and reserves Apple's key certification for the attested tier.

import { b64uDecode, bytesEqual, concatBytes, sha256, utf8, utf8Decode } from './b64.js';
import { p256Verify } from './receipt.js';

export const TIER_PASSKEY = 'passkey';
export const TIER_ENCLAVE_UNATTESTED = 'enclave-unattested';
export const TIER_ENCLAVE_ATTESTED = 'enclave-attested';

// authenticatorData = rpIdHash(32) || flags(1) || signCount(4, big-endian)
//                     || [attestedCredentialData] || [extensions]
export function parseAuthenticatorData(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 37) throw new Error('authenticatorData: too short');
  const f = bytes[32];
  return {
    rpIdHash: bytes.slice(0, 32),
    flags: {
      up: !!(f & 0x01),
      uv: !!(f & 0x04),
      be: !!(f & 0x08),
      bs: !!(f & 0x10),
      at: !!(f & 0x40),
      ed: !!(f & 0x80),
    },
    signCount: bytes[33] * 0x1000000 + (bytes[34] << 16) + (bytes[35] << 8) + bytes[36],
    rest: bytes.slice(37),
  };
}

export function parseClientData(bytes) {
  let cd;
  try {
    cd = JSON.parse(utf8Decode(bytes));
  } catch {
    throw new Error('clientDataJSON: not JSON');
  }
  if (
    cd === null || typeof cd !== 'object' ||
    typeof cd.type !== 'string' || typeof cd.challenge !== 'string' || typeof cd.origin !== 'string'
  ) {
    throw new Error('clientDataJSON: missing type, challenge, or origin');
  }
  return cd;
}

// WebAuthn signatures are ASN.1 DER ECDSA-Sig-Value; receipts and the notary
// use the raw 64-byte r||s form everywhere else. Accepts either.
export function derToRaw(sig) {
  if (sig.length === 64) return sig;
  if (sig[0] !== 0x30) throw new Error('signature: not DER');
  let o = 1;
  let len = sig[o++];
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 2) throw new Error('signature: bad DER length');
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | sig[o++];
  }
  if (o + len !== sig.length) throw new Error('signature: DER length mismatch');
  const readInt = () => {
    if (sig[o++] !== 0x02) throw new Error('signature: expected INTEGER');
    const l = sig[o++];
    if (l & 0x80) throw new Error('signature: bad INTEGER length');
    let v = sig.slice(o, o + l);
    o += l;
    while (v.length > 32 && v[0] === 0) v = v.slice(1);
    if (v.length > 32) throw new Error('signature: INTEGER too long');
    const out = new Uint8Array(32);
    out.set(v, 32 - v.length);
    return out;
  };
  const r = readInt();
  const s = readInt();
  if (o !== sig.length) throw new Error('signature: trailing bytes');
  return concatBytes(r, s);
}

export async function webauthnSignInput(authenticatorData, clientDataJSON) {
  return concatBytes(authenticatorData, await sha256(clientDataJSON));
}

// An approval challenge is SHA-256(cjson(canonical_action)) || 32 random
// bytes, so the signed clientDataJSON pins the exact action.
export function challengeEmbedsHash(challengeB64u, hashB64u) {
  let c;
  let h;
  try {
    c = b64uDecode(challengeB64u);
    h = b64uDecode(hashB64u);
  } catch {
    return false;
  }
  return c.length === 64 && h.length === 32 && bytesEqual(c.subarray(0, 32), h);
}

export async function rpIdHashOf(rpId) {
  return sha256(utf8(rpId));
}

// Offline check of a passkey assertion as carried in a receipt. Everything
// needed is in the receipt: the credential public key, the two signed
// blobs, the signature, the RP ID, and the action hash the challenge must
// embed. Returns { ok, error, clientData, authData }.
export async function verifyPasskeyAssertion({
  pub,
  authenticator_data,
  client_data_json,
  signature,
  rp_id,
  action_hash,
  origins = null,
}) {
  let pubRaw;
  let authData;
  let cdj;
  let sigRaw;
  try {
    pubRaw = b64uDecode(pub);
    authData = b64uDecode(authenticator_data);
    cdj = b64uDecode(client_data_json);
    sigRaw = derToRaw(b64uDecode(signature));
  } catch (err) {
    return { ok: false, error: `webauthn: ${err.message}` };
  }
  let clientData;
  try {
    clientData = parseClientData(cdj);
  } catch (err) {
    return { ok: false, error: err.message };
  }
  if (clientData.type !== 'webauthn.get') return { ok: false, error: 'clientDataJSON: not an assertion' };
  if (!challengeEmbedsHash(clientData.challenge, action_hash)) {
    return { ok: false, error: 'challenge: does not embed the action hash' };
  }
  if (origins && !origins.includes(clientData.origin)) return { ok: false, error: 'origin: not allowed' };
  let ad;
  try {
    ad = parseAuthenticatorData(authData);
  } catch (err) {
    return { ok: false, error: err.message };
  }
  if (!bytesEqual(ad.rpIdHash, await rpIdHashOf(rp_id))) return { ok: false, error: 'rpIdHash: does not match rp_id' };
  if (!ad.flags.up) return { ok: false, error: 'flags: user presence not set' };
  if (!ad.flags.uv) return { ok: false, error: 'flags: user verification not set' };
  if (!(await p256Verify(pubRaw, sigRaw, await webauthnSignInput(authData, cdj)))) {
    return { ok: false, error: 'signature: invalid' };
  }
  return { ok: true, error: null, clientData, authData: ad };
}
