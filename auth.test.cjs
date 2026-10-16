const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const net = require('node:net');
const fs = require('node:fs');
const { createHash, generateKeyPairSync } = require('node:crypto');
const auth = fs.existsSync(__dirname + '/auth.cjs') ? require('./auth.cjs') : {};

const config = {
  provider: 'generic', url: 'https://abcdefghijklmnopqrst.supabase.co/functions/v1/desktop-update/',
  publisherName: ['AI Team Village release'], publishableKey: 'sb_publishable_test_public_key',
  publicKey: generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }),
};

function localRequest(url, options = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(url, { method: options.method || 'GET', headers: options.headers }, res => {
      let body = '';
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject); req.end();
  });
}

test('PKCE verifier and state are independent random values and challenge hashes the verifier', () => {
  assert.equal(typeof auth.createPKCE, 'function');
  const first = auth.createPKCE(), second = auth.createPKCE();
  assert.match(first.state, /^[A-Za-z0-9_-]{43}$/);
  assert.match(first.verifier, /^[A-Za-z0-9_-]{43,128}$/);
  assert.notEqual(first.state, first.verifier);
  assert.notEqual(first.state, second.state); assert.notEqual(first.verifier, second.verifier);
  assert.equal(first.challenge, createHash('sha256').update(first.verifier).digest('base64url'));
});

test('loopback ignores wrong method, host, path, state and duplicate parameters before a valid one-use callback', async () => {
  assert.equal(typeof auth.startCallback, 'function');
  const pending = await auth.startCallback('expected-state', { port: 0, timeoutMs: 2000 });
  try {
    const good = pending.url + '?state=expected-state&code=accepted-code';
    for (const [url, options] of [
      [good, { method: 'POST' }],
      [good, { headers: { host: 'localhost:' + new URL(good).port } }],
      [good.replace('/install/callback', '/other'), {}],
      [good.replace('/install/callback', '/install/%63allback'), {}],
      [good.replace('expected-state', 'wrong-state'), {}],
      [good + '&state=expected-state', {}],
      [good + '&code=another', {}],
    ]) {
      const rejected = await localRequest(url, options);
      assert.ok(rejected.status >= 400); assert.ok(!rejected.body.includes('accepted-code'));
    }
    assert.equal((await localRequest(good)).status, 200);
    assert.deepEqual(await pending.result, { code: 'accepted-code' });
    const replay = await localRequest(good).catch(() => ({ status: 410 }));
    assert.ok(replay.status >= 400);
  } finally { await pending.close(); }
  await assert.rejects(localRequest(pending.url));
});

test('loopback timeout and abort close pending connections and release the port', async () => {
  assert.equal(typeof auth.startCallback, 'function');
  for (const abort of [false, true]) {
    const controller = new AbortController();
    const pending = await auth.startCallback('state', { port: 0, timeoutMs: 30, signal: controller.signal });
    if (abort) controller.abort();
    assert.ok((await pending.result).error instanceof Error);
    await pending.close();
    await assert.rejects(localRequest(pending.url));
  }
});

function flow(overrides = {}) {
  const calls = [];
  const options = { platform: 'win32', callbackPort: 0, timeoutMs: 2000, requestTimeoutMs: 500,
    fetch: async (url, init) => {
      calls.push({ url: String(url), init });
      const route = new URL(url).pathname;
      if (route === '/auth/v1/otp') {
        const redirect = new URL(url).searchParams.get('redirect_to');
        const callback = new URL(redirect); callback.searchParams.set('code', 'one-use-code');
        setImmediate(() => localRequest(callback).catch(() => {}));
        if (overrides.otpError) return new Response('sensitive-server-content', { status: overrides.otpStatus || 400 });
        return Response.json({});
      }
      if (route === '/auth/v1/token') return Response.json({ access_token: 'in-memory-access-token', refresh_token: 'never-persisted', token_type: 'bearer', expires_in: 3600, ...overrides.session });
      if (route === '/rest/v1/rpc/claim_membership') return Response.json('member' in overrides ? overrides.member : 'm06', { status: overrides.memberStatus || 200 });
      assert.fail('Unexpected endpoint');
    } };
  return { calls, options };
}

test('authentication sends no-account-creation PKCE OTP, exchanges the code and claims text membership', async () => {
  assert.equal(typeof auth.authenticate, 'function');
  const f = flow();
  assert.equal(await auth.authenticate(config, 'member@example.invalid', f.options), 'in-memory-access-token');
  assert.equal(f.calls.length, 3);
  const otp = f.calls[0], token = f.calls[1], claim = f.calls[2];
  assert.equal(new URL(otp.url).pathname, '/auth/v1/otp');
  const redirect = new URL(new URL(otp.url).searchParams.get('redirect_to'));
  assert.equal(redirect.hostname, '127.0.0.1'); assert.equal(redirect.pathname, '/install/callback');
  assert.ok(redirect.searchParams.get('state'));
  const body = JSON.parse(otp.init.body);
  assert.equal(body.email, 'member@example.invalid'); assert.equal(body.create_user, false);
  assert.equal(body.code_challenge_method, 's256');
  assert.equal(new URL(token.url).search, '?grant_type=pkce');
  const exchange = JSON.parse(token.init.body);
  assert.equal(exchange.auth_code, 'one-use-code');
  assert.equal(body.code_challenge, createHash('sha256').update(exchange.code_verifier).digest('base64url'));
  assert.equal(claim.url, 'https://abcdefghijklmnopqrst.supabase.co/rest/v1/rpc/claim_membership');
  assert.equal(claim.init.headers.Authorization, 'Bearer in-memory-access-token');
  for (const { init } of f.calls) { assert.equal(init.redirect, 'error'); assert.equal(init.headers.apikey, config.publishableKey); }
});

test('callback response forbids caching, referrers and active content', async () => {
  const pending = await auth.startCallback('state', { port: 0, timeoutMs: 1000 });
  try {
    await new Promise((resolve, reject) => {
      http.get(pending.url + '?state=wrong&code=secret-query', response => {
        assert.equal(response.headers['cache-control'], 'no-store');
        assert.equal(response.headers['referrer-policy'], 'no-referrer');
        assert.equal(response.headers['content-security-policy'], "default-src 'none'; frame-ancestors 'none'");
        response.resume(); response.on('end', resolve);
      }).on('error', reject);
    });
  } finally { await pending.close(); }
});

test('callback cancellation destroys a connection that has not completed its headers', async () => {
  const controller = new AbortController();
  const pending = await auth.startCallback('state', { port: 0, timeoutMs: 1000, signal: controller.signal });
  const socket = net.connect(Number(new URL(pending.url).port), '127.0.0.1');
  socket.on('error', () => {});
  await new Promise(resolve => socket.once('connect', resolve));
  socket.write('GET /install/callback HTTP/1.1\r\n');
  const closed = new Promise(resolve => socket.once('close', resolve));
  controller.abort();
  await pending.result; await pending.close(); await closed;
  assert.ok(socket.destroyed);
});

test('accepted callback settles even when its response closes before finish', async t => {
  const createServer = http.createServer;
  t.mock.method(http, 'createServer', (options, handler) => createServer(options, (request, response) => {
    response.end = () => response.destroy();
    handler(request, response);
  }));
  const pending = await auth.startCallback('state', { port: 0, timeoutMs: 1000 });
  try {
    await localRequest(pending.url + '?state=state&code=accepted-code').catch(() => {});
    const outcome = await Promise.race([pending.result, new Promise(resolve => setTimeout(() => resolve(null), 80))]);
    assert.deepEqual(outcome, { code: 'accepted-code' });
  } finally { await pending.close(); }
});

test('whole authentication deadline covers token exchange and membership claim', async () => {
  for (const route of ['/auth/v1/token', '/rest/v1/rpc/claim_membership']) {
    const f = flow(), request = f.options.fetch;
    f.options.timeoutMs = 60; f.options.requestTimeoutMs = 500;
    f.options.fetch = (url, init) => new URL(url).pathname === route ? new Promise(() => {}) : request(url, init);
    const started = Date.now();
    await assert.rejects(auth.authenticate(config, 'member@example.invalid', f.options), error => error.code === 'AUTH_TIMEOUT');
    assert.ok(Date.now() - started < 350);
  }
});

test('429 becomes a helpful safe error and mismatched token email cannot claim membership', async () => {
  const rate = flow({ otpError: true, otpStatus: 429 });
  await assert.rejects(auth.authenticate(config, 'member@example.invalid', rate.options), error => error.code === 'RATE_LIMIT' && !error.message.includes('sensitive-server-content'));
  const mismatch = flow({ session: { user: { email: 'other@example.invalid' } } });
  await assert.rejects(auth.authenticate(config, 'member@example.invalid', mismatch.options), error => error.code === 'AUTH');
  assert.equal(mismatch.calls.length, 2);
});

test('fixed default callback binds the allowlisted loopback port before OTP', async () => {
  let redirect;
  await assert.rejects(auth.authenticate(config, 'member@example.invalid', { platform: 'win32', fetch: async url => {
    redirect = new URL(new URL(url).searchParams.get('redirect_to'));
    return new Response('{}', { status: 400 });
  } }));
  assert.equal(redirect.origin, 'http://127.0.0.1:48190');
  assert.equal(redirect.pathname, '/install/callback');
});

test('authentication rejects nonmember, malformed membership and OTP failure without leaking responses', async () => {
  assert.equal(typeof auth.authenticate, 'function');
  for (const overrides of [{ member: null }, { member: { id: 'm06' } }, { member: 'm06', memberStatus: 403 }, { otpError: true }]) {
    const f = flow(overrides);
    await assert.rejects(auth.authenticate(config, 'member@example.invalid', f.options), error => {
      assert.ok(!error.message.includes('sensitive-server-content')); assert.ok(!error.message.includes('in-memory-access-token')); return true;
    });
    const redirect = new URL(f.calls[0].url).searchParams.get('redirect_to');
    await assert.rejects(localRequest(redirect));
  }
});

test('unsupported platform, invalid email and occupied callback port never send OTP', async () => {
  assert.equal(typeof auth.authenticate, 'function');
  let requests = 0;
  await assert.rejects(auth.authenticate(config, 'member@example.invalid', { platform: 'linux', fetch: () => { requests++; } }));
  await assert.rejects(auth.authenticate(config, 'invalid-email', { platform: 'win32', fetch: () => { requests++; } }));
  const server = http.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try { await assert.rejects(auth.authenticate(config, 'member@example.invalid', { platform: 'win32', callbackPort: server.address().port, fetch: () => { requests++; } })); }
  finally { await new Promise(resolve => server.close(resolve)); }
  assert.equal(requests, 0);
});
