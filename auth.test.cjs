const test = require('node:test');
const assert = require('node:assert/strict');
const { generateKeyPairSync } = require('node:crypto');
const auth = require('./auth.cjs');

const config = {
  provider: 'generic', url: 'https://abcdefghijklmnopqrst.supabase.co/functions/v1/desktop-update/',
  publisherName: ['AI Team Village release'], publishableKey: 'sb_publishable_test_public_key',
  publicKey: generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }),
};
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });

function flow(overrides = {}) {
  const calls = [];
  const options = { platform: 'win32', fetch: async (url, init) => {
    calls.push({ url, init });
    const path = new URL(url).pathname;
    if (path === '/functions/v1/email-login') return overrides.loginStatus ? json({ error: 'sensitive-server-content' }, overrides.loginStatus) : json({ token_hash: 'one-use-hash' });
    if (path === '/auth/v1/verify') return json({ access_token: 'in-memory-access-token', user: { email: 'member@example.invalid' }, ...overrides.session });
    if (path === '/rest/v1/rpc/claim_membership') return json(overrides.member === undefined ? 'm06' : overrides.member, overrides.memberStatus || 200);
    return json({}, 404);
  } };
  return { calls, options };
}

test('a registered email gets a one-time token without mail, verifies it and claims membership', async () => {
  const f = flow();
  assert.equal(await auth.authenticate(config, 'Member@Example.invalid', f.options), 'in-memory-access-token');
  assert.deepEqual(f.calls.map(call => new URL(call.url).pathname), ['/functions/v1/email-login', '/auth/v1/verify', '/rest/v1/rpc/claim_membership']);
  assert.deepEqual(JSON.parse(f.calls[0].init.body), { email: 'member@example.invalid' });
  assert.deepEqual(JSON.parse(f.calls[1].init.body), { type: 'magiclink', token_hash: 'one-use-hash' });
  assert.equal(f.calls[2].init.headers.Authorization, 'Bearer in-memory-access-token');
  for (const { init } of f.calls) { assert.equal(init.redirect, 'error'); assert.equal(init.headers.apikey, config.publishableKey); }
});

test('an unregistered email, a wrong account and a refused membership fail without leaking server text', async () => {
  const cases = [[{ loginStatus: 403 }, 'NOT_REGISTERED'], [{ loginStatus: 500 }, 'AUTH'], [{ session: { user: { email: 'other@example.invalid' } } }, 'AUTH'], [{ member: null }, 'MEMBERSHIP'], [{ memberStatus: 403 }, 'MEMBERSHIP']];
  for (const [overrides, code] of cases) {
    const f = flow(overrides);
    await assert.rejects(auth.authenticate(config, 'member@example.invalid', f.options), error => {
      assert.equal(error.code, code); assert.ok(!error.message.includes('sensitive-server-content')); assert.ok(!error.message.includes('in-memory-access-token')); return true;
    });
  }
});

test('the whole deadline covers every request and cancellation is reported as such', async () => {
  for (const route of ['/functions/v1/email-login', '/auth/v1/verify', '/rest/v1/rpc/claim_membership']) {
    const f = flow(), request = f.options.fetch;
    f.options.timeoutMs = 60; f.options.requestTimeoutMs = 500;
    f.options.fetch = (url, init) => new URL(url).pathname === route ? new Promise(() => {}) : request(url, init);
    const started = Date.now();
    await assert.rejects(auth.authenticate(config, 'member@example.invalid', f.options), error => error.code === 'AUTH_TIMEOUT');
    assert.ok(Date.now() - started < 350);
  }
  const controller = new AbortController(), f = flow();
  f.options.signal = controller.signal; controller.abort();
  await assert.rejects(auth.authenticate(config, 'member@example.invalid', f.options), error => error.code === 'CANCELLED');
});

test('unsupported platform and invalid email never send a request', async () => {
  let requests = 0;
  await assert.rejects(auth.authenticate(config, 'member@example.invalid', { platform: 'linux', fetch: () => { requests++; } }));
  await assert.rejects(auth.authenticate(config, 'invalid-email', { platform: 'win32', fetch: () => { requests++; } }));
  assert.equal(requests, 0);
});
