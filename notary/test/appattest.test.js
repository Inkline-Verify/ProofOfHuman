import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { verifyAttestation, verifyAssertion, sha256 } from '../src/appattest.js';
import { makeTestPki, makeAttestation, makeAssertion } from './fixtures/appattest-fixture.mjs';

const APP_ID = 'FIXTURETEAM.com.example.inkline';
const pki = makeTestPki();
const otherPki = makeTestPki();

function freshAttestation(clientDataHash = sha256(randomBytes(16))) {
  return {
    clientDataHash,
    ...makeAttestation({ pki, appId: APP_ID, clientDataHash }),
  };
}

test('valid attestation verifies and yields the credential key', () => {
  const { attestation, keyId, clientDataHash, pubRaw } = freshAttestation();
  const result = verifyAttestation({
    attestation,
    clientDataHash,
    keyId,
    appId: APP_ID,
    rootPem: pki.rootPem,
    environment: 'development',
  });
  assert.equal(result.counter, 0);
  // stored SPKI must embed the same raw point
  const spki = result.attestPubSpki;
  assert.deepEqual(spki.subarray(spki.length - 65), pubRaw);
});

test('attestation from an untrusted chain is rejected', () => {
  const { attestation, keyId, clientDataHash } = freshAttestation();
  assert.throws(
    () =>
      verifyAttestation({
        attestation,
        clientDataHash,
        keyId,
        appId: APP_ID,
        rootPem: otherPki.rootPem,
        environment: 'development',
      }),
    /chain/
  );
});

test('attestation bound to different client data is rejected (nonce mismatch)', () => {
  const { attestation, keyId } = freshAttestation();
  assert.throws(
    () =>
      verifyAttestation({
        attestation,
        clientDataHash: sha256(randomBytes(16)),
        keyId,
        appId: APP_ID,
        rootPem: pki.rootPem,
        environment: 'development',
      }),
    /nonce/
  );
});

test('attestation with a mismatched keyId is rejected', () => {
  const { attestation, clientDataHash } = freshAttestation();
  assert.throws(
    () =>
      verifyAttestation({
        attestation,
        clientDataHash,
        keyId: new Uint8Array(32),
        appId: APP_ID,
        rootPem: pki.rootPem,
        environment: 'development',
      }),
    /keyId/
  );
});

test('attestation for a different app ID is rejected', () => {
  const { attestation, keyId, clientDataHash } = freshAttestation();
  assert.throws(
    () =>
      verifyAttestation({
        attestation,
        clientDataHash,
        keyId,
        appId: 'OTHERTEAM.com.example.other',
        rootPem: pki.rootPem,
        environment: 'development',
      }),
    /RP ID/
  );
});

test('both Apple environments are accepted and reported', () => {
  const dev = freshAttestation();
  const devResult = verifyAttestation({
    attestation: dev.attestation,
    clientDataHash: dev.clientDataHash,
    keyId: dev.keyId,
    appId: APP_ID,
    rootPem: pki.rootPem,
  });
  assert.equal(devResult.environment, 'development');

  const prodCdh = new Uint8Array(32).fill(7);
  const prod = makeAttestation({ pki, appId: APP_ID, clientDataHash: prodCdh, aaguid: 'appattest' });
  const prodResult = verifyAttestation({
    attestation: prod.attestation,
    clientDataHash: prodCdh,
    keyId: prod.keyId,
    appId: APP_ID,
    rootPem: pki.rootPem,
  });
  assert.equal(prodResult.environment, 'production');
});

test('an unknown attestation environment is rejected', () => {
  const cdh = new Uint8Array(32).fill(9);
  const bogus = makeAttestation({ pki, appId: APP_ID, clientDataHash: cdh, aaguid: 'not-apple-guid' });
  assert.throws(
    () =>
      verifyAttestation({
        attestation: bogus.attestation,
        clientDataHash: cdh,
        keyId: bogus.keyId,
        appId: APP_ID,
        rootPem: pki.rootPem,
      }),
    /environment/
  );
});

test('assertions verify and enforce a monotonic counter', () => {
  const { attestation, keyId, clientDataHash, credKeyPem } = freshAttestation();
  const { attestPubSpki } = verifyAttestation({
    attestation,
    clientDataHash,
    keyId,
    appId: APP_ID,
    rootPem: pki.rootPem,
    environment: 'development',
  });

  const clientData = new TextEncoder().encode('asserted-bytes');
  const assertion = makeAssertion({ credKeyPem, appId: APP_ID, clientData, counter: 1 });
  const r1 = verifyAssertion({ assertion, clientData, appId: APP_ID, attestPubSpki, prevCounter: 0 });
  assert.equal(r1.counter, 1);

  // replaying the same assertion must fail
  assert.throws(
    () => verifyAssertion({ assertion, clientData, appId: APP_ID, attestPubSpki, prevCounter: r1.counter }),
    /counter/
  );

  // tampered client data must fail
  assert.throws(
    () =>
      verifyAssertion({
        assertion,
        clientData: new TextEncoder().encode('other-bytes'),
        appId: APP_ID,
        attestPubSpki,
        prevCounter: 0,
      }),
    /signature/
  );

  // assertion by a different key must fail
  const stranger = makeAttestation({ pki, appId: APP_ID, clientDataHash: sha256(randomBytes(16)) });
  const forged = makeAssertion({ credKeyPem: stranger.credKeyPem, appId: APP_ID, clientData, counter: 2 });
  assert.throws(
    () => verifyAssertion({ assertion: forged, clientData, appId: APP_ID, attestPubSpki, prevCounter: 0 }),
    /signature/
  );
});
