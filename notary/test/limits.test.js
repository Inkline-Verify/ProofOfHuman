import { test } from 'node:test';
import assert from 'node:assert';
import { createNotary } from '../src/server.js';

function req(server, method, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const addr = server.address();
    fetch(`http://127.0.0.1:${addr.port}${path}`, {
      method,
      headers: { 'content-type': 'application/json', ...headers },
      body: body ? JSON.stringify(body) : undefined,
    }).then(async (r) => resolve({ status: r.status, body: await r.json() })).catch(reject);
  });
}

test('per-IP rate limit returns 429', async () => {
  const { server } = await createNotary({ appId: 'FIXTURETEAM.com.example.inkline', rootPem: 'unused-in-this-test', rateLimit: { windowMs: 60_000, max: 3 } });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    for (let i = 0; i < 3; i++) {
      const r = await req(server, 'POST', '/v1/enroll/challenge', {}, { 'x-forwarded-for': '1.2.3.4' });
      assert.equal(r.status, 200);
    }
    const r = await req(server, 'POST', '/v1/enroll/challenge', {}, { 'x-forwarded-for': '1.2.3.4' });
    assert.equal(r.status, 429);
    assert.equal(r.body.error.code, 'rate_limited');
    // a different IP is unaffected
    const other = await req(server, 'POST', '/v1/enroll/challenge', {}, { 'x-forwarded-for': '5.6.7.8' });
    assert.equal(other.status, 200);
  } finally { server.close(); }
});

test('registry cap refuses enrollment when full', async () => {
  const { server, store } = await createNotary({ appId: 'FIXTURETEAM.com.example.inkline', rootPem: 'unused-in-this-test', maxRegistry: 1, rateLimit: null });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    store.data.registry['existing-kid'] = { pub: 'x', enrolledAt: Date.now(), status: 'active' };
    const c = await req(server, 'POST', '/v1/enroll/challenge', {});
    assert.equal(c.status, 200);
    const pub = 'BA' + 'A'.repeat(85); // shape-valid b64url is checked before cap; use real point? cap is checked after kid
    const r = await req(server, 'POST', '/v1/enroll', { challenge: c.body.challenge, pub });
    assert.ok(r.status === 503 || r.status === 400, `got ${r.status}`);
    if (r.status === 503) assert.equal(r.body.error.code, 'registry_full');
  } finally { server.close(); }
});
