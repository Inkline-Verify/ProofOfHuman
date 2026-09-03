import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { b64uEncode, b64uDecode, utf8, utf8Decode } from '../../shared/b64.js';
import { emailContentHash } from '../../shared/canonical.js';
import {
  presenceSignInput,
  notarySignInput,
  encodeReceipt,
  decodeReceipt,
  kidOfPub,
  p256Verify,
  verifyReceipt,
  validatePayload,
} from '../../shared/receipt.js';

const subtle = globalThis.crypto.subtle;
const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(here, '../../canonical/vectors.json'), 'utf8'));

async function makeKey() {
  const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const pub = b64uEncode(new Uint8Array(await subtle.exportKey('raw', pair.publicKey)));
  return {
    pub,
    kid: await kidOfPub(pub),
    sign: async (bytes) =>
      new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, bytes)),
  };
}

const email = {
  from: 'sender@example.com',
  to: ['alice@example.com'],
  cc: [],
  subject: 'Hello',
  body: 'Typed by an actual person.',
};

async function makeReceipt() {
  const presence = await makeKey();
  const notary = await makeKey();
  const payload = {
    v: 1,
    action: 'email',
    contentHash: await emailContentHash(email),
    nonce: b64uEncode(crypto.getRandomValues(new Uint8Array(32))),
    iat: Math.floor(Date.now() / 1000),
    kid: presence.kid,
  };
  const sig = b64uEncode(await presence.sign(presenceSignInput(payload)));
  const iat = payload.iat + 1;
  const notarySig = b64uEncode(
    await notary.sign(notarySignInput({ iat, payload, pub: presence.pub, sig }))
  );
  const receipt = encodeReceipt({
    v: 1,
    payload,
    pub: presence.pub,
    sig,
    notary: { iat, kid: notary.kid, sig: notarySig },
  });
  return { receipt, notaryPub: notary.pub, payload };
}

test('golden presence signature vector verifies', async () => {
  const p = vectors.presence;
  const input = presenceSignInput(p.payload);
  assert.equal(b64uEncode(input), p.signInput);
  assert.equal(await p256Verify(b64uDecode(p.pub), b64uDecode(p.sig), input), true);
});

test('full receipt verifies offline', async () => {
  const { receipt, notaryPub } = await makeReceipt();
  const result = await verifyReceipt({ receipt, email, notaryPub });
  assert.equal(result.error, null);
  assert.equal(result.ok, true);
  assert.deepEqual(Object.values(result.checks), [true, true, true, true, true, true, true]);
});

test('tampered body fails on content hash', async () => {
  const { receipt, notaryPub } = await makeReceipt();
  const tampered = { ...email, body: 'Actually written by a bot.' };
  const result = await verifyReceipt({ receipt, email: tampered, notaryPub });
  assert.equal(result.ok, false);
  assert.equal(result.checks.contentHash, false);
});

test('tampered payload fails on presence signature', async () => {
  const { receipt, notaryPub } = await makeReceipt();
  const decoded = decodeReceipt(receipt);
  decoded.payload.iat += 1;
  const reencoded = encodeReceipt(decoded);
  const result = await verifyReceipt({ receipt: reencoded, email, notaryPub });
  assert.equal(result.ok, false);
  // iat changes the content-hash-independent part of the payload
  assert.equal(result.checks.presenceSig, false);
});

test('swapped notary key fails on notary kid', async () => {
  const { receipt } = await makeReceipt();
  const other = await makeKey();
  const result = await verifyReceipt({ receipt, email, notaryPub: other.pub });
  assert.equal(result.ok, false);
  assert.equal(result.checks.notaryKid, false);
});

test('substituted presence key fails on kid binding', async () => {
  const { receipt, notaryPub } = await makeReceipt();
  const decoded = decodeReceipt(receipt);
  const other = await makeKey();
  decoded.pub = other.pub; // payload.kid still names the original key
  const result = await verifyReceipt({ receipt: encodeReceipt(decoded), email, notaryPub });
  assert.equal(result.ok, false);
  assert.equal(result.checks.kid, false);
});

test('garbage receipts fail to decode', async () => {
  for (const junk of ['', 'x', b64uEncode(utf8('not json')), b64uEncode(utf8('{"v":2}'))]) {
    const result = await verifyReceipt({ receipt: junk, email, notaryPub: (await makeKey()).pub });
    assert.equal(result.ok, false);
  }
});

test('payload validation rejects malformed payloads', () => {
  const good = {
    v: 1,
    action: 'email',
    contentHash: 'h',
    nonce: 'n',
    iat: 1,
    kid: 'k',
  };
  assert.equal(validatePayload(good), null);
  assert.notEqual(validatePayload({ ...good, v: 2 }), null);
  assert.notEqual(validatePayload({ ...good, action: 'other' }), null);
  assert.notEqual(validatePayload({ ...good, iat: 1.5 }), null);
  assert.notEqual(validatePayload({ ...good, extra: true }), null);
  const { nonce, ...missing } = good;
  assert.notEqual(validatePayload(missing), null);
});

test('receipt encoding round-trips utf8', async () => {
  const { receipt } = await makeReceipt();
  const decoded = decodeReceipt(receipt);
  assert.equal(utf8Decode(b64uDecode(receipt)).includes(decoded.payload.kid), true);
});
