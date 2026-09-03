// End-to-end notary flow with a simulated device: enrollment (challenge +
// bare presence key, single enclave-unattested tier), nonce issuance,
// co-signing, and offline receipt verification — plus the failure paths that
// make the guarantees real.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createNotary, TIER } from '../src/server.js';
import { b64uEncode } from '../../shared/b64.js';
import { emailContentHash } from '../../shared/canonical.js';
import { kidOfPub, presenceSignInput, verifyReceipt } from '../../shared/receipt.js';

const subtle = globalThis.crypto.subtle;

const email = {
  from: 'sender@example.com',
  to: ['alice@example.com'],
  cc: [],
  subject: 'Proof of presence',
  body: 'This message was approved with a fingerprint.',
};

async function startNotary(overrides = {}) {
  const { server, notary } = await createNotary({ storePath: null, ...overrides });
  await new Promise((resolve) => server.listen(0, resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const api = async (method, path, body) => {
    const res = await fetch(base + path, {
      method,
      headers: { 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: res.status, body: await res.json() };
  };
  return { api, close: () => new Promise((r) => server.close(r)), notary };
}

// Simulates the helper: a presence key (software here; Secure Enclave on a
// real Mac — the notary cannot tell the difference, which is the point of the
// unattested tier) enrolled via challenge + bare public key.
async function makeDevice(api) {
  const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const pub = b64uEncode(new Uint8Array(await subtle.exportKey('raw', pair.publicKey)));
  const kid = await kidOfPub(pub);

  const { body: ch } = await api('POST', '/v1/enroll/challenge');
  const enroll = await api('POST', '/v1/enroll', { challenge: ch.challenge, pub });

  return {
    pub,
    kid,
    enroll,
    signPresence: async (payload) =>
      b64uEncode(
        new Uint8Array(
          await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, presenceSignInput(payload))
        )
      ),
    buildPayload: async (nonce) => ({
      v: 1,
      action: 'email',
      contentHash: await emailContentHash(email),
      nonce,
      iat: Math.floor(Date.now() / 1000),
      kid,
    }),
  };
}

test('happy path: enroll, nonce, cosign, verify offline', async () => {
  const { api, close, notary } = await startNotary();
  try {
    const device = await makeDevice(api);
    assert.equal(device.enroll.status, 200, JSON.stringify(device.enroll.body));
    assert.equal(device.enroll.body.kid, device.kid);

    const { status: nonceStatus, body: nonceBody } = await api('POST', '/v1/nonce', { kid: device.kid });
    assert.equal(nonceStatus, 200);

    const payload = await device.buildPayload(nonceBody.nonce);
    const sig = await device.signPresence(payload);
    const { status, body } = await api('POST', '/v1/cosign', {
      payload,
      pub: device.pub,
      sig
    });
    assert.equal(status, 200, JSON.stringify(body));

    const result = await verifyReceipt({ receipt: body.receipt, email, notaryPub: notary.pub });
    assert.equal(result.error, null);
    assert.equal(result.ok, true);

    // and the receipt fails against a different message
    const forged = await verifyReceipt({
      receipt: body.receipt,
      email: { ...email, body: 'Different content.' },
      notaryPub: notary.pub,
    });
    assert.equal(forged.ok, false);
  } finally {
    await close();
  }
});

test('a nonce is single-use', async () => {
  const { api, close } = await startNotary();
  try {
    const device = await makeDevice(api);
    const { body: n } = await api('POST', '/v1/nonce', { kid: device.kid });
    const payload = await device.buildPayload(n.nonce);
    const sig = await device.signPresence(payload);
    const first = await api('POST', '/v1/cosign', {
      payload,
      pub: device.pub,
      sig
    });
    assert.equal(first.status, 200);

    const replay = await api('POST', '/v1/cosign', {
      payload,
      pub: device.pub,
      sig
    });
    assert.equal(replay.status, 403);
    assert.equal(replay.body.error.code, 'nonce_invalid');
  } finally {
    await close();
  }
});

test('an expired nonce is refused', async () => {
  const { api, close } = await startNotary({ nonceTtlMs: 1 });
  try {
    const device = await makeDevice(api);
    const { body: n } = await api('POST', '/v1/nonce', { kid: device.kid });
    await new Promise((r) => setTimeout(r, 10));
    const payload = await device.buildPayload(n.nonce);
    const res = await api('POST', '/v1/cosign', {
      payload,
      pub: device.pub,
      sig: await device.signPresence(payload)
    });
    assert.equal(res.status, 403);
    assert.match(res.body.error.code, /nonce/);
  } finally {
    await close();
  }
});

test('an unenrolled key gets no nonce and no co-signature', async () => {
  const { api, close } = await startNotary();
  try {
    const res = await api('POST', '/v1/nonce', { kid: 'nobody' });
    assert.equal(res.status, 403);
    assert.equal(res.body.error.code, 'not_enrolled');
  } finally {
    await close();
  }
});

test('a bad presence signature is refused', async () => {
  const { api, close } = await startNotary();
  try {
    const device = await makeDevice(api);
    const { body: n } = await api('POST', '/v1/nonce', { kid: device.kid });
    const payload = await device.buildPayload(n.nonce);
    const tampered = { ...payload, iat: payload.iat + 1 };
    const res = await api('POST', '/v1/cosign', {
      payload: tampered,
      pub: device.pub,
      sig: await device.signPresence(payload), // signed the original
    });
    assert.equal(res.status, 403);
    assert.equal(res.body.error.code, 'presence_invalid');
  } finally {
    await close();
  }
});

test('enrollment with a reused or unknown challenge is refused', async () => {
  const { api, close } = await startNotary();
  try {
    const device = await makeDevice(api); // consumed its challenge
    assert.equal(device.enroll.status, 200);

    const res = await api('POST', '/v1/enroll', {
      challenge: 'bm90LWEtcmVhbC1jaGFsbGVuZ2U',
      keyId: b64uEncode(new Uint8Array(32)),
      pub: device.pub,
      binding: 'AA',
    });
    assert.equal(res.status, 403);
    assert.equal(res.body.error.code, 'challenge_invalid');
  } finally {
    await close();
  }
});

test('the same presence key cannot enroll twice', async () => {
  const { api, close } = await startNotary();
  try {
    const device = await makeDevice(api);
    assert.equal(device.enroll.status, 200);

    const { body: ch } = await api('POST', '/v1/enroll/challenge');
    const res = await api('POST', '/v1/enroll', { challenge: ch.challenge, pub: device.pub });
    assert.equal(res.status, 409);
    assert.equal(res.body.error.code, 'already_enrolled');
  } finally {
    await close();
  }
});

test('/v1/info advertises the single enclave-unattested tier', async () => {
  const { api, close } = await startNotary();
  try {
    const { body: info } = await api('GET', '/v1/info');
    assert.equal(info.tier, TIER);
    assert.equal(info.tier, 'enclave-unattested');
    assert.equal(info.attested, false);
  } finally {
    await close();
  }
});

test('enrollment records the key as attested: false', async () => {
  const { api, close } = await startNotary();
  try {
    const device = await makeDevice(api);
    assert.equal(device.enroll.status, 200);
    assert.equal(device.enroll.body.attested, false);
    assert.equal(device.enroll.body.tier, 'enclave-unattested');
  } finally {
    await close();
  }
});
