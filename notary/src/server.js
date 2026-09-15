// The Inkline notary: the single hosted component.
//
// It never sees email content — only content hashes, public keys,
// signatures, and attestation material. One trust tier, enforced here:
//
//   enclave-attested — enrollment MUST carry a valid Apple App Attest chain
//   proving the key came from a genuine Secure Enclave inside the signed
//   helper, and every co-signature additionally verifies a fresh App Attest
//   assertion (strictly increasing counter) over the same payload.
//
// Enrollments made before this policy (tier enclave-unattested) are kept in
// the registry for the historical record but are INACTIVE: they receive no
// nonces and no co-signatures. Their old receipts remain verifiable.
//
// A co-signature on a receipt means:
//   - the presence key was previously enrolled with this notary at the tier
//     named in the receipt's notary.tier field (covered by the signature),
//   - the server-issued nonce was live, single-use, and bound to that key,
//   - the presence signature over the payload verified,
//   - for the attested tier, the per-send assertion verified.
//
// Endpoints (JSON in, JSON out):
//   GET  /v1/info              -> { v, tier, notary: { pub, kid } }
//   POST /v1/enroll/challenge  -> { challenge, exp }
//   POST /v1/enroll            -> { kid }
//   POST /v1/nonce             -> { nonce, exp }
//   POST /v1/cosign            -> { receipt }

import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { Store } from './store.js';
import { b64uEncode, b64uDecode } from '../../shared/b64.js';
import { verifyAttestation, verifyAssertion } from './appattest.js';
import {
  assertClientData,
  enrollAttestClientDataHash,
  enrollBindClientData,
  encodeReceipt,
  kidOfPub,
  notarySignInput,
  p256Verify,
  presenceSignInput,
  validatePayload,
} from '../../shared/receipt.js';

const subtle = globalThis.crypto.subtle;

class HttpError extends Error {
  constructor(status, code, message, extra = null) {
    super(message);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

const ATTESTATION_REQUIRED = (detail) =>
  new HttpError(403, 'attestation_required', detail, { min_os: 'macOS 27' });

async function loadNotaryKey(store) {
  if (!store.data.notaryKey) {
    const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
      'verify',
    ]);
    store.data.notaryKey = {
      priv: await subtle.exportKey('jwk', pair.privateKey),
      pub: b64uEncode(new Uint8Array(await subtle.exportKey('raw', pair.publicKey))),
    };
    store.save();
  }
  const priv = await subtle.importKey(
    'jwk',
    store.data.notaryKey.priv,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );
  const pub = store.data.notaryKey.pub;
  return {
    pub,
    kid: await kidOfPub(pub),
    sign: async (bytes) =>
      new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, priv, bytes)),
  };
}

function decodeB64uField(value, name, expectedLength = null) {
  if (typeof value !== 'string') throw new HttpError(400, 'bad_request', `${name} must be a string`);
  let bytes;
  try {
    bytes = b64uDecode(value);
  } catch {
    throw new HttpError(400, 'bad_request', `${name} is not valid base64url`);
  }
  if (expectedLength !== null && bytes.length !== expectedLength) {
    throw new HttpError(400, 'bad_request', `${name} has wrong length`);
  }
  return bytes;
}

function requirePub(pubB64u) {
  const raw = decodeB64uField(pubB64u, 'pub', 65);
  if (raw[0] !== 0x04) throw new HttpError(400, 'bad_request', 'pub is not an uncompressed point');
  return raw;
}

export const TIER = 'enclave-unattested';
export const TIER_ATTESTED = 'enclave-attested';

// config:
//   storePath    JSON state file, or null for in-memory
//   nonceTtlMs, challengeTtlMs, iatSkewSec
export async function createNotary(config = {}) {
  const {
    // appId ("TEAMID.bundle.id" of the signed helper) and rootPem (trusted
    // App Attest root CA) enable the enclave-attested tier; without both,
    // the notary serves the unattested tier only.
    appId = null,
    rootPem = null,
    storePath = null, nonceTtlMs = 60_000, challengeTtlMs = 120_000, iatSkewSec = 120,
    // Abuse limits: per-IP token bucket and a hard cap on stored enrollments.
    rateLimit = { windowMs: 60_000, max: 60 },
    maxRegistry = 100_000,
  } = config;
  if (!appId || !rootPem) {
    throw new Error('notary: appId and rootPem are required (attestation is mandatory)');
  }

  // Per-IP sliding-window rate limiter (in-memory; fronting proxy/CDN should
  // be the first line of defense, this is the backstop).
  const hits = new Map();
  function rateLimited(ip) {
    if (!rateLimit) return false;
    const now = Date.now();
    let h = hits.get(ip);
    if (!h || now - h.start > rateLimit.windowMs) { h = { start: now, n: 0 }; hits.set(ip, h); }
    h.n += 1;
    if (hits.size > 50_000) {
      for (const [k, v] of hits) if (now - v.start > rateLimit.windowMs) hits.delete(k);
    }
    return h.n > rateLimit.max;
  }

  const store = new Store(storePath);
  const notaryKey = await loadNotaryKey(store);

  const routes = {
    'GET /v1/info': async () => ({
      v: 1,
      tier: TIER_ATTESTED,
      tiers: [TIER_ATTESTED],
      appId,
      notary: { pub: notaryKey.pub, kid: notaryKey.kid },
    }),

    'POST /v1/enroll/challenge': async () => {
      store.gc();
      const challenge = b64uEncode(randomBytes(32));
      const exp = Date.now() + challengeTtlMs;
      store.data.challenges[challenge] = { exp };
      store.save();
      return { challenge, exp };
    },

    'POST /v1/enroll': async (body) => {
      store.gc();
      const { challenge, pub, keyId, attestation, binding } = body;
      const ch = typeof challenge === 'string' ? store.data.challenges[challenge] : undefined;
      if (!ch || ch.exp < Date.now()) {
        throw new HttpError(403, 'challenge_invalid', 'unknown or expired challenge');
      }
      delete store.data.challenges[challenge];

      if (Object.keys(store.data.registry).length >= maxRegistry) {
        throw new HttpError(503, 'registry_full', 'enrollment is temporarily closed');
      }
      requirePub(pub);
      const kid = await kidOfPub(pub);
      if (store.data.registry[kid]) {
        throw new HttpError(409, 'already_enrolled', 'this presence key is already enrolled');
      }

      const wantsAttested = keyId !== undefined || attestation !== undefined || binding !== undefined;
      if (!wantsAttested) {
        throw ATTESTATION_REQUIRED('enrollment requires Apple App Attest; Inkline needs macOS 27 or later');
      }

      const keyIdBytes = decodeB64uField(keyId, 'keyId', 32);
      const attestationBytes = decodeB64uField(attestation, 'attestation');
      const bindingBytes = decodeB64uField(binding, 'binding');

      // 1) The App Attest key is genuine: Apple-rooted chain, this app.
      //    Both Apple environments are accepted; which one is recorded.
      const clientDataHash = await enrollAttestClientDataHash(challenge);
      let attested;
      try {
        attested = verifyAttestation({
          attestation: attestationBytes,
          clientDataHash,
          keyId: keyIdBytes,
          appId,
          rootPem,
        });
      } catch (err) {
        throw new HttpError(403, 'attestation_invalid', err.message);
      }

      // 2) The attested key vouches for this exact presence public key.
      let bound;
      try {
        bound = verifyAssertion({
          assertion: bindingBytes,
          clientData: enrollBindClientData(challenge, pub),
          appId,
          attestPubSpki: attested.attestPubSpki,
          prevCounter: 0,
        });
      } catch (err) {
        throw new HttpError(403, 'binding_invalid', err.message);
      }

      console.log(`enroll: attested key ${kid} (App Attest environment: ${attested.environment})`);
      store.data.registry[kid] = {
        pub,
        keyId,
        tier: TIER_ATTESTED,
        attested: true,
        attestPubSpki: b64uEncode(attested.attestPubSpki),
        counter: bound.counter,
        environment: attested.environment,
        enrolledAt: Date.now(),
        status: 'active',
      };
      store.save();
      return { kid, tier: TIER_ATTESTED, attested: true, environment: attested.environment };
    },

    'POST /v1/nonce': async (body) => {
      store.gc();
      const entry = typeof body.kid === 'string' ? store.data.registry[body.kid] : undefined;
      if (!entry || entry.status !== 'active') {
        throw new HttpError(403, 'not_enrolled', 'unknown or inactive presence key');
      }
      if (entry.attested !== true) {
        throw ATTESTATION_REQUIRED('this key was enrolled before hardware attestation became mandatory; re-enroll on macOS 27 or later');
      }
      const nonce = b64uEncode(randomBytes(32));
      const exp = Date.now() + nonceTtlMs;
      store.data.nonces[nonce] = { kid: body.kid, exp };
      store.save();
      return { nonce, exp };
    },

    'POST /v1/cosign': async (body) => {
      store.gc();
      const { payload, pub, sig, assertion } = body;
      const payloadError = validatePayload(payload);
      if (payloadError) throw new HttpError(400, 'bad_payload', payloadError);

      const entry = store.data.registry[payload.kid];
      if (!entry || entry.status !== 'active') {
        throw new HttpError(403, 'not_enrolled', 'unknown or inactive presence key');
      }
      if (entry.attested !== true) {
        throw ATTESTATION_REQUIRED('this key was enrolled before hardware attestation became mandatory; re-enroll on macOS 27 or later');
      }
      if (pub !== entry.pub) {
        throw new HttpError(403, 'key_mismatch', 'pub does not match the enrolled key');
      }
      const pubRaw = requirePub(pub);
      if ((await kidOfPub(pub)) !== payload.kid) {
        throw new HttpError(403, 'key_mismatch', 'payload kid does not match pub');
      }

      const nonceEntry = store.data.nonces[payload.nonce];
      if (!nonceEntry || nonceEntry.kid !== payload.kid) {
        throw new HttpError(403, 'nonce_invalid', 'unknown nonce for this key');
      }
      if (nonceEntry.exp < Date.now()) {
        throw new HttpError(403, 'nonce_expired', 'nonce has expired');
      }

      const nowSec = Math.floor(Date.now() / 1000);
      if (Math.abs(nowSec - payload.iat) > iatSkewSec) {
        throw new HttpError(403, 'iat_skew', 'payload timestamp outside tolerance');
      }

      const sigRaw = decodeB64uField(sig, 'sig', 64);
      if (!(await p256Verify(pubRaw, sigRaw, presenceSignInput(payload)))) {
        throw new HttpError(403, 'presence_invalid', 'presence signature does not verify');
      }

      // A fresh App Attest assertion over the same payload; its counter must
      // be strictly increasing.
      const tier = entry.tier;
      {
        const assertionBytes = decodeB64uField(assertion, 'assertion');
        let asserted;
        try {
          asserted = verifyAssertion({
            assertion: assertionBytes,
            clientData: assertClientData(payload),
            appId,
            attestPubSpki: b64uDecode(entry.attestPubSpki),
            prevCounter: entry.counter,
          });
        } catch (err) {
          throw new HttpError(403, 'assertion_invalid', err.message);
        }
        entry.counter = asserted.counter;
      }

      // All checks passed: burn the nonce, co-sign.
      delete store.data.nonces[payload.nonce];
      store.save();

      const iat = nowSec;
      const notarySig = await notaryKey.sign(notarySignInput({ iat, payload, pub, sig, tier }));
      const receipt = encodeReceipt({
        v: 1,
        payload,
        pub,
        sig,
        notary: { iat, kid: notaryKey.kid, sig: b64uEncode(notarySig), tier },
      });
      return { receipt };
    },
  };

  const server = http.createServer(async (req, res) => {
    res.setHeader('content-type', 'application/json');
    try {
      const fwd = req.headers['x-forwarded-for'];
      const ip = (typeof fwd === 'string' && fwd.split(',')[0].trim()) || req.socket.remoteAddress || '?';
      if (req.method === 'POST' && rateLimited(ip)) {
        throw new HttpError(429, 'rate_limited', 'too many requests, slow down');
      }
      const url = new URL(req.url, 'http://localhost');
      const route = routes[`${req.method} ${url.pathname}`];
      if (!route) throw new HttpError(404, 'not_found', 'no such endpoint');
      const body = req.method === 'POST' ? await readJson(req) : null;
      const result = await route(body);
      res.statusCode = 200;
      res.end(JSON.stringify(result));
    } catch (err) {
      const status = err instanceof HttpError ? err.status : 500;
      const code = err instanceof HttpError ? err.code : 'internal';
      const message = err instanceof HttpError ? err.message : 'internal error';
      const extra = err instanceof HttpError && err.extra ? err.extra : {};
      res.statusCode = status;
      res.end(JSON.stringify({ error: { code, message, ...extra } }));
    }
  });

  return { server, store, notary: { pub: notaryKey.pub, kid: notaryKey.kid } };
}

function readJson(req, limit = 1_000_000) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(new HttpError(413, 'too_large', 'request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        const text = Buffer.concat(chunks).toString('utf8');
        const value = text.length ? JSON.parse(text) : {};
        if (value === null || typeof value !== 'object' || Array.isArray(value)) {
          throw new Error();
        }
        resolve(value);
      } catch {
        reject(new HttpError(400, 'bad_json', 'body must be a JSON object'));
      }
    });
    req.on('error', reject);
  });
}
