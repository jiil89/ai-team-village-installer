const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { spawn } = require('node:child_process');
const { validateReleaseConfig, verifyManifest, verifyInstaller } = require('./update-security.cjs');
const { InstallerError, requestJson, downloadFile } = require('./http.cjs');

function runInstaller(file, destination, options) {
  return new Promise((resolve, reject) => {
    let failed = false;
    const finish = (code) => {
      if (failed || code !== 0) reject(new InstallerError('INSTALL'));
      else resolve();
    };
    try {
      options.signal?.throwIfAborted();
      options.onInstalling?.();
      options.signal?.throwIfAborted();
      // NSIS can remove old files before copying new ones; never terminate it during replacement.
      const child = (options.spawn || spawn)(file, ['/S', '/currentuser', '/D=' + destination], {
        shell: false, windowsHide: true, windowsVerbatimArguments: true, stdio: 'ignore',
      });
      child.once('error', () => { failed = true; }); child.once('close', finish);
    } catch { reject(new InstallerError(options.signal?.aborted ? 'CANCELLED' : 'INSTALL')); }
  });
}

async function launchApp(file, options) {
  try {
    options.signal?.throwIfAborted();
    const stat = await fs.lstat(file);
    if (!stat.isFile()) throw new Error();
    await new Promise((resolve, reject) => {
      const child = (options.spawn || spawn)(file, [], { shell: false, detached: true, stdio: 'ignore', windowsHide: false });
      child.once('error', () => reject(new InstallerError('LAUNCH')));
      child.once('spawn', () => { child.unref(); resolve(); });
    });
  } catch { throw new InstallerError(options.signal?.aborted ? 'CANCELLED' : 'LAUNCH'); }
}

async function install(config, accessToken, options = {}) {
  if ((options.platform || process.platform) !== 'win32') throw new InstallerError('PLATFORM');
  const localAppData = options.localAppData || process.env.LOCALAPPDATA;
  try {
    validateReleaseConfig(config);
    if (typeof accessToken !== 'string' || !/^[^\s\x00-\x1f\x7f]{1,16384}$/.test(accessToken)
      || typeof localAppData !== 'string' || !/^[A-Za-z]:\\/.test(localAppData) || /["\x00-\x1f\x7f]/.test(localAppData)) throw new Error();
  } catch { throw new InstallerError('CONFIG'); }
  options.signal?.throwIfAborted();
  let manifest;
  try {
    const envelope = await requestJson(config.url + 'manifest.json', { headers: { apikey: config.publishableKey } }, { fetch: options.fetch, signal: options.signal, timeoutMs: options.requestTimeoutMs });
    manifest = verifyManifest(envelope, config.publicKey);
  } catch (error) { if (error instanceof InstallerError) throw error; throw new InstallerError('VERIFY'); }
  const tempRoot = path.resolve(options.tempRoot || os.tmpdir());
  const directory = await fs.mkdtemp(path.join(tempRoot, 'ai-team-village-install-'));
  if (!path.resolve(directory).startsWith(tempRoot + path.sep)) throw new InstallerError('CONFIG');
  try {
    const file = path.join(directory, manifest.filename);
    await downloadFile(config.url + manifest.filename, file, manifest.size, { headers: { apikey: config.publishableKey, Authorization: 'Bearer ' + accessToken } }, { fetch: options.fetch, signal: options.signal, timeoutMs: options.downloadTimeoutMs ?? 300000 });
    try { await verifyInstaller(file, manifest, options.signal); }
    catch { throw new InstallerError(options.signal?.aborted ? 'CANCELLED' : 'VERIFY'); }
    const destination = path.win32.join(localAppData, 'Programs', 'AI Team Village');
    await runInstaller(file, destination, options);
    const installedPath = path.win32.join(destination, 'AI Team Village.exe');
    await launchApp(installedPath, { spawn: options.spawn });
    return { version: manifest.version, path: installedPath };
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
}

module.exports = { install };
