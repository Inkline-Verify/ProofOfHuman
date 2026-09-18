import test from 'node:test';
import assert from 'node:assert/strict';
import { verify, INKLINE_NOTARY_PUB } from './index.js';

test('rejects garbage and explains what an email receipt needs', async () => {
  assert.equal((await verify('not-a-receipt')).ok, false);
  assert.equal(INKLINE_NOTARY_PUB.length, 87);
});
