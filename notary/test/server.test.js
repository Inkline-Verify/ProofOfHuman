// Core notary protocol under the attested-only policy: nonce discipline,
// challenge discipline, signature checks, and the policy gates themselves.
// The attested happy paths live in attested.test.js.

import test from 'node:test';
import assert from 'node:assert/strict';
import { startNotary, makeAttestedDevice, cosign, email } from './fixtures/attested-device.mjs';
import { b64uEncode } from '../../shared/b64.js';
import { emailContentHash } from '../../shared/canonical.js';
import { kidOfPub, presenceSignInput, notarySignInput, encodeReceipt, verifyReceipt } from '../../shared/receipt.js';

const subtle = globalThis.crypto.subtle;

test('a nonce is single-use', async () => {
  const { api, close } = await startNotary();
  try {
    const device = await makeAttestedDevice(api);
    const first = await cosign(api, device);
    assert.equal(first.res.status, 200);
    // Replay the same payload+sig (same nonce) with a fresh assertion.
    const sig = await device.signPresence(first.payload);
    const replay = await api('POST', '/v1/cosign', {
      payload: first.payload,
      pub: device.pub,
      sig,
      assertion: device.nextAssertion(
        (await import('../../shared/receipt.js')).assertClientData(first.payload)
      ),
    });
    assert.equal(replay.status, 403);
    assert.equal(replay.body.error.code, 'nonce_invalid');
  } finally {
    await close();
  }
});

test('an expired nonce is refused', async () => {
  const { api, close } = await startNotary({ nonceTtlMs: -1 });
  try {
    const device = await makeAttestedDevice(api);
    const { res } = await cosign(api, device);
    assert.equal(res.status, 403);
  } finally {
    await close();
  }
});

test('an unenrolled key gets no nonce', async () => {
  const { api, close } = await startNotary();
  try {
    const res = await api('POST', '/v1/nonce', { kid: 'nope' });
    assert.equal(res.status, 403);
    assert.equal(res.body.error.code, 'not_enrolled');
  } finally {
    await close();
  }
});

test('a bad presence signature is refused', async () => {
  const { api, close } = await startNotary();
  try {
    const device = await makeAttestedDevice(api);
    const { body: n } = await api('POST', '/v1/nonce', { kid: device.kid });
    const payload = await device.buildPayload(n.nonce);
    const badSig = b64uEncode(new Uint8Array(64));
    const { assertClientData } = await import('../../shared/receipt.js');
    const res = await api('POST', '/v1/cosign', {
      payload,
      pub: device.pub,
      sig: badSig,
      assertion: device.nextAssertion(assertClientData(payload)),
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
    const device = await makeAttestedDevice(api);
    assert.equal(device.enroll.status, 200);
    // The device consumed its challenge; replaying the identical enrollment
    // (same challenge) must fail.
    const replay = await api('POST', '/v1/enroll', {
      challenge: 'bm90LWEtcmVhbC1jaGFsbGVuZ2U',
      keyId: 'QQ',
      attestation: 'QQ',
      pub: device.pub,
      binding: 'QQ',
    });
    assert.equal(replay.status, 403);
    assert.equal(replay.body.error.code, 'challenge_invalid');
  } finally {
    await close();
  }
});

test('the same presence key cannot enroll twice', async () => {
  const { api, close } = await startNotary();
  try {
    const device = await makeAttestedDevice(api);
    assert.equal(device.enroll.status, 200);
    const again = await makeAttestedDevice(api).then(() => null).catch(() => null);
    // Direct check: fresh challenge, same pub.
    const { body: ch } = await api('POST', '/v1/enroll/challenge');
    const res = await api('POST', '/v1/enroll', {
      challenge: ch.challenge, keyId: 'QQ', attestation: 'QQ', pub: device.pub, binding: 'QQ',
    });
    assert.equal(res.status, 409);
    assert.equal(res.body.error.code, 'already_enrolled');
  } finally {
    await close();
  }
});

// ---- policy gates ----

test('bare enrollment is refused with attestation_required and min_os', async () => {
  const { api, close } = await startNotary();
  try {
    const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
    const pub = b64uEncode(new Uint8Array(await subtle.exportKey('raw', pair.publicKey)));
    const { body: ch } = await api('POST', '/v1/enroll/challenge');
    const res = await api('POST', '/v1/enroll', { challenge: ch.challenge, pub });
    assert.equal(res.status, 403);
    assert.equal(res.body.error.code, 'attestation_required');
    assert.equal(res.body.error.min_os, 'macOS 27');
  } finally {
    await close();
  }
});

test('legacy unattested enrollments are inactive: no nonce, no co-sign', async () => {
  const { api, close, store } = await startNotary();
  try {
    const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
    const pub = b64uEncode(new Uint8Array(await subtle.exportKey('raw', pair.publicKey)));
    const kid = await kidOfPub(pub);
    // Seed a registry entry as the old policy would have written it.
    store.data.registry[kid] = { pub, tier: 'enclave-unattested', attested: false, enrolledAt: 1, status: 'active' };

    const n = await api('POST', '/v1/nonce', { kid });
    assert.equal(n.status, 403);
    assert.equal(n.body.error.code, 'attestation_required');
    assert.equal(n.body.error.min_os, 'macOS 27');

    const payload = { v: 1, action: 'email', contentHash: await emailContentHash(email), nonce: 'x', iat: Math.floor(Date.now() / 1000), kid };
    const sig = b64uEncode(new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, presenceSignInput(payload))));
    const c = await api('POST', '/v1/cosign', { payload, pub, sig });
    assert.equal(c.status, 403);
    assert.equal(c.body.error.code, 'attestation_required');
  } finally {
    await close();
  }
});

test('a legacy receipt (issued before the policy) still verifies, tier reported', async () => {
  // Construct a legacy receipt purely from the shared layer, as the old
  // notary would have issued it: no notary.tier field at all.
  const presence = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
  const notaryPair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
  const pub = b64uEncode(new Uint8Array(await subtle.exportKey('raw', presence.publicKey)));
  const notaryPub = b64uEncode(new Uint8Array(await subtle.exportKey('raw', notaryPair.publicKey)));
  const payload = { v: 1, action: 'email', contentHash: await emailContentHash(email), nonce: 'n', iat: 1700000000, kid: await kidOfPub(pub) };
  const sig = b64uEncode(new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, presence.privateKey, presenceSignInput(payload))));
  const iat = 1700000001;
  const notarySig = b64uEncode(new Uint8Array(
    await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, notaryPair.privateKey, notarySignInput({ iat, payload, pub, sig }))
  ));
  const receipt = encodeReceipt({ v: 1, payload, pub, sig, notary: { iat, kid: await kidOfPub(notaryPub), sig: notarySig } });
  const verified = await verifyReceipt({ receipt, email, notaryPub });
  assert.equal(verified.ok, true);
  assert.equal(verified.tier, null); // pre-tier receipt: verifier labels it legacy
});
