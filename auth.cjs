const http = require('node:http');
const { randomBytes, createHash } = require('node:crypto');
const { validateReleaseConfig } = require('./update-security.cjs');
const { InstallerError, requestJson } = require('./http.cjs');

function createPKCE() {
  const state = randomBytes(32).toString('base64url');
  const verifier = randomBytes(48).toString('base64url');
  return { state, verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
}

async function startCallback(state, options = {}) {
  options.signal?.throwIfAborted();
  let resolve, settled = false, closed = false, timer, callbackUrl;
  const result = new Promise(done => { resolve = done; });
  const server = http.createServer({ maxHeaderSize: 8192, requestTimeout: 5000, headersTimeout: 5000 }, (req, res) => {
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store'); res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
    res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Connection', 'close');
    let url;
    try { url = new URL(req.url, callbackUrl); } catch {}
    const valid = !settled && req.method === 'GET' && req.headers.host === new URL(callbackUrl).host
      && typeof req.url === 'string' && req.url.startsWith('/install/callback?') && req.url.length <= 8192
      && url?.pathname === '/install/callback' && url.origin === new URL(callbackUrl).origin
      && url.searchParams.getAll('state').length === 1 && url.searchParams.get('state') === state
      && url.searchParams.getAll('code').length === 1 && /^[^\s\x00-\x1f\x7f]{1,4096}$/.test(url.searchParams.get('code'))
      && !url.searchParams.has('error');
    if (!valid) { res.statusCode = 400; res.end('유효하지 않은 설치 인증 요청입니다.'); return; }
    settled = true; clearTimeout(timer);
    const complete = () => resolve({ code: url.searchParams.get('code') });
    res.once('finish', complete); res.once('close', complete);
    res.end('설치 인증을 확인했습니다. 이 창을 닫고 설치 터미널로 돌아가 주세요.');
  });
  server.maxConnections = 32; server.keepAliveTimeout = 1000;
  const close = async () => {
    if (closed) return;
    closed = true; clearTimeout(timer); options.signal?.removeEventListener('abort', abort);
    if (!settled) { settled = true; resolve({ error: new InstallerError('CANCELLED') }); }
    await new Promise(done => { server.close(done); server.closeAllConnections(); });
  };
  const abort = () => { if (!settled) { settled = true; resolve({ error: new InstallerError('CANCELLED') }); } void close(); };
  try {
    await new Promise((yes, no) => {
      server.once('error', no);
      server.listen(options.port ?? 48190, '127.0.0.1', () => { server.removeListener('error', no); yes(); });
    });
    callbackUrl = `http://127.0.0.1:${server.address().port}/install/callback`;
    timer = setTimeout(() => {
      if (!settled) { settled = true; resolve({ error: new InstallerError('AUTH_TIMEOUT') }); }
      void close();
    }, options.timeoutMs ?? 300000);
    options.signal?.addEventListener('abort', abort, { once: true });
    if (options.signal?.aborted) abort();
    return { url: callbackUrl, result, close };
  } catch { await close(); throw new InstallerError('CALLBACK'); }
}

async function authenticate(config, email, options = {}) {
  if ((options.platform || process.platform) !== 'win32') throw new InstallerError('PLATFORM');
  if (typeof email !== 'string' || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new InstallerError('EMAIL');
  try { validateReleaseConfig(config); } catch { throw new InstallerError('CONFIG'); }
  const { state, verifier, challenge } = createPKCE();
  const controller = new AbortController();
  const signal = options.signal ? AbortSignal.any([options.signal, controller.signal]) : controller.signal;
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 300000);
  let pending;
  const base = new URL(config.url).origin;
  const requestOptions = { fetch: options.fetch, signal, timeoutMs: options.requestTimeoutMs };
  const headers = { apikey: config.publishableKey, 'Content-Type': 'application/json' };
  try {
    pending = await startCallback(state, { port: options.callbackPort, timeoutMs: options.timeoutMs, signal });
    const redirect = new URL(pending.url); redirect.searchParams.set('state', state);
    const otp = new URL('/auth/v1/otp', base); otp.searchParams.set('redirect_to', redirect.href);
    try {
      await requestJson(otp.href, { method: 'POST', headers, body: JSON.stringify({ email, create_user: false, code_challenge: challenge, code_challenge_method: 's256' }) }, requestOptions);
    } catch (error) {
      if (options.signal?.aborted) throw new InstallerError('CANCELLED');
      throw new InstallerError(error.status === 429 ? 'RATE_LIMIT' : 'OTP');
    }
    options.onWaiting?.();
    const callback = await pending.result;
    if (callback.error) throw callback.error;
    await pending.close();
    let session;
    try {
      session = await requestJson(base + '/auth/v1/token?grant_type=pkce', { method: 'POST', headers, body: JSON.stringify({ auth_code: callback.code, code_verifier: verifier }) }, requestOptions);
      if (typeof session?.access_token !== 'string' || !/^[^\s\x00-\x1f\x7f]{1,16384}$/.test(session.access_token)
        || (session.user?.email !== undefined && (typeof session.user.email !== 'string' || session.user.email.toLowerCase() !== email.toLowerCase()))) throw new Error();
    } catch { throw new InstallerError(options.signal?.aborted ? 'CANCELLED' : 'AUTH'); }
    try {
      const member = await requestJson(base + '/rest/v1/rpc/claim_membership', { method: 'POST', headers: { ...headers, Authorization: 'Bearer ' + session.access_token }, body: '{}' }, requestOptions);
      if (typeof member !== 'string' || !/^[^\s\x00-\x1f\x7f]{1,128}$/.test(member)) throw new Error();
    } catch { throw new InstallerError(options.signal?.aborted ? 'CANCELLED' : 'MEMBERSHIP'); }
    return session.access_token;
  } catch (error) {
    if (options.signal?.aborted) throw new InstallerError('CANCELLED');
    if (controller.signal.aborted) throw new InstallerError('AUTH_TIMEOUT');
    throw error;
  } finally { clearTimeout(timer); await pending?.close(); }
}

module.exports = { authenticate, createPKCE, startCallback };
