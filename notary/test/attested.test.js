// The enclave-attested tier, end to end with fixture App Attest material:
// enrollment (challenge, attestation, binding), assertion-gated co-signing,
// tier-stamped receipts, offline verification — and the failure paths.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createNotary, TIER_ATTESTED } from '../src/server.js';
import { startNotary, makeAttestedDevice, cosign, email, APP_ID, pki } from './fixtures/attested-device.mjs';
import { b64uEncode, b64uDecode, concatBytes, utf8 } from '../../shared/b64.js';
import { sha256 as sha256Sync } from '../src/appattest.js';
import { makeTestPki, makeAttestation, makeAssertion } from './fixtures/appattest-fixture.mjs';
import {
  TAG_ENROLL_ATTEST,
  assertClientData,
  enrollBindClientData,
  decodeReceipt,
  encodeReceipt,
  verifyReceipt,
} from '../../shared/receipt.js';

const subtle = globalThis.crypto.subtle;

test('info advertises the single mandatory attested tier', async () => {
  const { api, close } = await startNotary();
  try {
    const { body: info } = await api('GET', '/v1/info');
    assert.equal(info.tier, TIER_ATTESTED);
    assert.deepEqual(info.tiers, [TIER_ATTESTED]);
    assert.equal(info.appId, APP_ID);
  } finally {
    await close();
  }
});

test('attested happy path: enroll, cosign with assertion, verify offline with tier', async () => {
  const { api, close, notary } = await startNotary();
  try {
    const device = await makeAttestedDevice(api);
    assert.equal(device.enroll.status, 200, JSON.stringify(device.enroll.body));
    assert.equal(device.enroll.body.tier, TIER_ATTESTED);
    assert.equal(device.enroll.body.attested, true);
    assert.equal(device.enroll.body.environment, 'development');

    const { res } = await cosign(api, device);
    assert.equal(res.status, 200, JSON.stringify(res.body));

    const verified = await verifyReceipt({ receipt: res.body.receipt, email, notaryPub: notary.pub });
    assert.equal(verified.error, null);
    assert.equal(verified.ok, true);
    assert.equal(verified.tier, TIER_ATTESTED);
  } finally {
    await close();
  }
});

test('production-environment attestation also enrolls; environment recorded', async () => {
  const { api, close } = await startNotary();
  try {
    const device = await makeAttestedDevice(api, { aaguid: 'appattest' });
    assert.equal(device.enroll.status, 200, JSON.stringify(device.enroll.body));
    assert.equal(device.enroll.body.environment, 'production');
  } finally {
    await close();
  }
});

test('attested enrollment cannot cosign without an assertion', async () => {
  const { api, close } = await startNotary();
  try {
    const device = await makeAttestedDevice(api);
    const { res } = await cosign(api, device, { assertion: undefined });
    assert.equal(res.status, 400);
  } finally {
    await close();
  }
});

test('a replayed assertion counter is refused', async () => {
  const { api, close } = await startNotary();
  try {
    const device = await makeAttestedDevice(api);
    const first = await cosign(api, device);
    assert.equal(first.res.status, 200);

    // Force the next assertion to reuse an old counter value.
    const { body: n } = await api('POST', '/v1/nonce', { kid: device.kid });
    const payload = await device.buildPayload(n.nonce);
    const sig = await device.signPresence(payload);
    const stale = device.nextAssertion(assertClientData(payload)); // counter 3
    const res1 = await api('POST', '/v1/cosign', { payload, pub: device.pub, sig, assertion: stale });
    assert.equal(res1.status, 200);

    const { body: n2 } = await api('POST', '/v1/nonce', { kid: device.kid });
    const payload2 = await device.buildPayload(n2.nonce);
    const sig2 = await device.signPresence(payload2);
    // Replay the previous assertion bytes (old counter, wrong client data).
    const res2 = await api('POST', '/v1/cosign', { payload: payload2, pub: device.pub, sig: sig2, assertion: stale });
    assert.equal(res2.status, 403);
    assert.equal(res2.body.error.code, 'assertion_invalid');
  } finally {
    await close();
  }
});

test('an attestation from a foreign CA is refused', async () => {
  const { api, close } = await startNotary();
  try {
    const foreignPki = makeTestPki();
    const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
    const pub = b64uEncode(new Uint8Array(await subtle.exportKey('raw', pair.publicKey)));
    const { body: ch } = await api('POST', '/v1/enroll/challenge');
    const clientDataHash = sha256Sync(concatBytes(utf8(TAG_ENROLL_ATTEST), b64uDecode(ch.challenge)));
    const attest = makeAttestation({ pki: foreignPki, appId: APP_ID, clientDataHash });
    const res = await api('POST', '/v1/enroll', {
      challenge: ch.challenge,
      keyId: b64uEncode(attest.keyId),
      attestation: b64uEncode(attest.attestation),
      pub,
      binding: b64uEncode(
        makeAssertion({ credKeyPem: attest.credKeyPem, appId: APP_ID, clientData: enrollBindClientData(ch.challenge, pub), counter: 1 })
      ),
    });
    assert.equal(res.status, 403);
    assert.equal(res.body.error.code, 'attestation_invalid');
  } finally {
    await close();
  }
});

test('stripping the tier from a receipt breaks the notary signature', async () => {
  const { api, close, notary } = await startNotary();
  try {
    const device = await makeAttestedDevice(api);
    const { res } = await cosign(api, device);
    const r = decodeReceipt(res.body.receipt);
    assert.equal(r.notary.tier, TIER_ATTESTED);
    delete r.notary.tier;
    const stripped = encodeReceipt(r);
    const verified = await verifyReceipt({ receipt: stripped, email, notaryPub: notary.pub });
    assert.equal(verified.ok, false);
    assert.match(verified.error, /notary/);
  } finally {
    await close();
  }
});

test('a notary cannot be started without attestation config', async () => {
  await assert.rejects(
    () => createNotary({ appId: null, rootPem: null, storePath: null }),
    /appId and rootPem are required/
  );
});
