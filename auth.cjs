const { validateReleaseConfig } = require('./update-security.cjs');
const { InstallerError, requestJson } = require('./http.cjs');

// Temporary (2026-10-19): a registered, active member email is enough to install; no mail is sent. The email-login
// function checks the member list and returns a one-time token hash, which /auth/v1/verify turns into a session
// that lives only in memory for the download. Anyone who knows a teammate's address can do the same.
async function authenticate(config, email, options = {}) {
  if ((options.platform || process.platform) !== 'win32') throw new InstallerError('PLATFORM');
  if (typeof email !== 'string' || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new InstallerError('EMAIL');
  try { validateReleaseConfig(config); } catch { throw new InstallerError('CONFIG'); }
  const controller = new AbortController();
  const signal = options.signal ? AbortSignal.any([options.signal, controller.signal]) : controller.signal;
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 60000);
  const base = new URL(config.url).origin;
  const requestOptions = { fetch: options.fetch, signal, timeoutMs: options.requestTimeoutMs };
  const headers = { apikey: config.publishableKey, 'Content-Type': 'application/json' };
  try {
    let login;
    try { login = await requestJson(base + '/functions/v1/email-login', { method: 'POST', headers, body: JSON.stringify({ email: email.toLowerCase() }) }, requestOptions); }
    catch (error) {
      if (options.signal?.aborted) throw new InstallerError('CANCELLED');
      throw new InstallerError(error.status === 403 ? 'NOT_REGISTERED' : 'AUTH');
    }
    if (typeof login?.token_hash !== 'string' || !/^[^\s\x00-\x1f\x7f]{1,1024}$/.test(login.token_hash)) throw new InstallerError('AUTH');
    let session;
    try {
      session = await requestJson(base + '/auth/v1/verify', { method: 'POST', headers, body: JSON.stringify({ type: 'magiclink', token_hash: login.token_hash }) }, requestOptions);
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
  } finally { clearTimeout(timer); }
}

module.exports = { authenticate };
