import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { cjson } from '../../shared/cjson.js';
import { canonText, canonicalEmail, emailContentHash } from '../../shared/canonical.js';
import { b64uEncode, b64uDecode } from '../../shared/b64.js';

const vectors = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), '../../canonical/vectors.json'), 'utf8')
);

test('cjson matches golden vectors', () => {
  for (const c of vectors.cjson) {
    assert.equal(cjson(c.value), c.expected);
  }
});

test('cjson rejects non-integer numbers and unsupported types', () => {
  assert.throws(() => cjson(1.5));
  assert.throws(() => cjson(Number.MAX_SAFE_INTEGER + 1));
  assert.throws(() => cjson(undefined));
});

test('canonText matches golden vectors', () => {
  for (const c of vectors.canonText) {
    assert.equal(canonText(c.input), c.expected);
  }
});

test('canonical email matches golden vectors', async () => {
  for (const c of vectors.emails) {
    assert.equal(cjson(canonicalEmail(c.email)), c.canonicalJson);
    assert.equal(await emailContentHash(c.email), c.contentHash);
  }
});

test('canonical email survives transit-style rewrites', async () => {
  const sent = {
    from: 'sender@example.com',
    to: ['alice@example.com'],
    cc: [],
    subject: 'Quick note',
    body: 'Line one.\nLine two has  spacing.\n',
  };
  const received = {
    from: 'Sender@Example.com',
    to: ['Alice@Example.com'],
    cc: [],
    subject: ' Quick  note ',
    body: 'Line one.\r\n Line two has spacing. \r\n\r\n',
  };
  assert.equal(await emailContentHash(sent), await emailContentHash(received));
});

test('b64url round trip', () => {
  const cases = [new Uint8Array(0), Uint8Array.of(0), Uint8Array.of(255, 254, 1), new Uint8Array(33).fill(7)];
  for (const c of cases) {
    assert.deepEqual(b64uDecode(b64uEncode(c)), c);
  }
  assert.throws(() => b64uDecode('a')); // length % 4 === 1
  assert.throws(() => b64uDecode('++++'));
});
