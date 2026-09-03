// The Inkline notary: the single hosted component.
//
// It never sees email content — only content hashes, public keys, and
// signatures. Single trust tier, "enclave-unattested": the helper's Secure
// Enclave key is registered on an honor basis (attested: false — nothing
// cryptographically proves to the notary that the key lives in an enclave).
// Its co-signature on a receipt means:
//   - the presence key was previously enrolled with this notary,
//   - the server-issued nonce was live, single-use, and bound to that key,
//   - the presence signature over the payload verified.
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
import {
  encodeReceipt,
  kidOfPub,
  notarySignInput,
  p256Verify,
  presenceSignInput,
  validatePayload,
} from '../../shared/receipt.js';

const subtle = globalThis.crypto.subtle;

class HttpError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

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

// config:
//   storePath    JSON state file, or null for in-memory
//   nonceTtlMs, challengeTtlMs, iatSkewSec
export async function createNotary(config = {}) {
  const {
    storePath = null, nonceTtlMs = 60_000, challengeTtlMs = 120_000, iatSkewSec = 120,
    // Abuse limits: per-IP token bucket and a hard cap on stored enrollments.
    rateLimit = { windowMs: 60_000, max: 60 },
    maxRegistry = 100_000,
  } = config;

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
      tier: TIER,
      attested: false,
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
      const { challenge, pub } = body;
      const ch = typeof challenge === 'string' ? store.data.challenges[challenge] : undefined;
      if (!ch || ch.exp < Date.now()) {
        throw new HttpError(403, 'challenge_invalid', 'unknown or expired challenge');
      }
      delete store.data.challenges[challenge];

      requirePub(pub);
      const kid = await kidOfPub(pub);
      if (Object.keys(store.data.registry).length >= maxRegistry) {
        throw new HttpError(503, 'registry_full', 'enrollment is temporarily closed');
      }
      if (store.data.registry[kid]) {
        throw new HttpError(409, 'already_enrolled', 'this presence key is already enrolled');
      }

      store.data.registry[kid] = {
        pub,
        tier: TIER,
        attested: false,
        enrolledAt: Date.now(),
        status: 'active',
      };
      store.save();
      return { kid, tier: TIER, attested: false };
    },

    'POST /v1/nonce': async (body) => {
      store.gc();
      const entry = typeof body.kid === 'string' ? store.data.registry[body.kid] : undefined;
      if (!entry || entry.status !== 'active') {
        throw new HttpError(403, 'not_enrolled', 'unknown or inactive presence key');
      }
      const nonce = b64uEncode(randomBytes(32));
      const exp = Date.now() + nonceTtlMs;
      store.data.nonces[nonce] = { kid: body.kid, exp };
      store.save();
      return { nonce, exp };
    },

    'POST /v1/cosign': async (body) => {
      store.gc();
      const { payload, pub, sig } = body;
      const payloadError = validatePayload(payload);
      if (payloadError) throw new HttpError(400, 'bad_payload', payloadError);

      const entry = store.data.registry[payload.kid];
      if (!entry || entry.status !== 'active') {
        throw new HttpError(403, 'not_enrolled', 'unknown or inactive presence key');
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

      // All checks passed: burn the nonce, co-sign.
      delete store.data.nonces[payload.nonce];
      store.save();

      const iat = nowSec;
      const notarySig = await notaryKey.sign(notarySignInput({ iat, payload, pub, sig }));
      const receipt = encodeReceipt({
        v: 1,
        payload,
        pub,
        sig,
        notary: { iat, kid: notaryKey.kid, sig: b64uEncode(notarySig) },
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
      res.statusCode = status;
      res.end(JSON.stringify({ error: { code, message } }));
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
