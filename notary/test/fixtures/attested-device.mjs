// Shared test harness for the attested-only notary: a fixture-PKI notary and
// a simulated macOS-27 helper (presence key + fixture App Attest material).

import { createNotary } from '../../src/server.js';
import { sha256 as sha256Sync } from '../../src/appattest.js';
import { makeTestPki, makeAttestation, makeAssertion } from './appattest-fixture.mjs';
import { b64uEncode, b64uDecode, concatBytes, utf8 } from '../../../shared/b64.js';
import { emailContentHash } from '../../../shared/canonical.js';
import {
  TAG_ENROLL_ATTEST,
  assertClientData,
  enrollBindClientData,
  kidOfPub,
  presenceSignInput,
} from '../../../shared/receipt.js';

const subtle = globalThis.crypto.subtle;

export const APP_ID = 'FIXTURETEAM.com.example.inkline';
export const pki = makeTestPki();

export const email = {
  from: 'sender@example.com',
  to: ['alice@example.com'],
  cc: [],
  subject: 'Proof of presence',
  body: 'This message was approved with a fingerprint.',
};

export async function startNotary(overrides = {}) {
  const { server, notary, store } = await createNotary({
    appId: APP_ID,
    rootPem: pki.rootPem,
    storePath: null,
    ...overrides,
  });
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
  return { api, close: () => new Promise((r) => server.close(r)), notary, store };
}

export async function makeAttestedDevice(api, { aaguid = 'appattestdevelop' } = {}) {
  const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const pub = b64uEncode(new Uint8Array(await subtle.exportKey('raw', pair.publicKey)));
  const kid = await kidOfPub(pub);

  const { body: ch } = await api('POST', '/v1/enroll/challenge');
  const clientDataHash = sha256Sync(concatBytes(utf8(TAG_ENROLL_ATTEST), b64uDecode(ch.challenge)));
  const attest = makeAttestation({ pki, appId: APP_ID, clientDataHash, aaguid });
  let counter = 0;
  const nextAssertion = (clientData) =>
    b64uEncode(makeAssertion({ credKeyPem: attest.credKeyPem, appId: APP_ID, clientData, counter: ++counter }));

  const enroll = await api('POST', '/v1/enroll', {
    challenge: ch.challenge,
    keyId: b64uEncode(attest.keyId),
    attestation: b64uEncode(attest.attestation),
    pub,
    binding: nextAssertion(enrollBindClientData(ch.challenge, pub)),
  });

  return {
    pub,
    kid,
    enroll,
    attest,
    nextAssertion,
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

export async function cosign(api, device, extra = {}) {
  const { body: n } = await api('POST', '/v1/nonce', { kid: device.kid });
  if (!n.nonce) return { res: { status: 403, body: n }, payload: null };
  const payload = await device.buildPayload(n.nonce);
  const sig = await device.signPresence(payload);
  const req = { payload, pub: device.pub, sig, ...extra };
  if (!('assertion' in extra)) req.assertion = device.nextAssertion(assertClientData(payload));
  return { res: await api('POST', '/v1/cosign', req), payload };
}
