const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const syncFs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { EventEmitter } = require('node:events');
const { generateKeyPairSync, sign, createHash } = require('node:crypto');
const installer = syncFs.existsSync(__dirname + '/installer.cjs') ? require('./installer.cjs') : {};

async function fixture(t, change = {}) {
  const keys = generateKeyPairSync('ed25519');
  const bytes = Buffer.from('verified executable fixture');
  const manifest = { format: 1, version: '1.2.3', filename: 'AI-Team-Village-1.2.3-Setup.exe', sha512: createHash('sha512').update(bytes).digest('base64'), size: bytes.length, parts: [{ path: 'releases/1.2.3/AI-Team-Village-1.2.3-Setup.exe.part-0', size: bytes.length }], ...change.manifest };
  const payload = Buffer.from(JSON.stringify(manifest));
  const envelope = { payload: payload.toString('base64'), signature: sign(null, payload, keys.privateKey).toString('base64') };
  const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'village-installer-test-'));
  t.after(() => fs.rm(tempRoot, { recursive: true, force: true }));
  const config = { provider: 'generic', url: 'https://abcdefghijklmnopqrst.supabase.co/functions/v1/desktop-update/', publisherName: ['AI Team Village release'], publicKey: keys.publicKey.export({ type: 'spki', format: 'pem' }), publishableKey: 'sb_publishable_test_public_key' };
  const requests = [], children = [];
  const localAppData = path.join(tempRoot, 'User With Spaces', 'AppData', 'Local');
  const options = { platform: 'win32', tempRoot, localAppData, requestTimeoutMs: 100, downloadTimeoutMs: 100,
    fetch: async (url, init) => {
      requests.push({ url: String(url), init });
      if (String(url).endsWith('/manifest.json')) return Response.json(change.envelope || envelope);
      if (change.location && String(url) === change.location) return new Response(bytes, { headers: { 'content-length': String(bytes.length) } });
      assert.equal(String(url), config.url + manifest.filename);
      if (change.location) return new Response(null, { status: 302, headers: { location: change.location } });
      return new Response(change.bytes || bytes, { headers: { 'content-length': String(change.contentLength ?? bytes.length) }, status: change.status || 200 });
    },
    spawn: (file, args, spawnOptions) => {
      children.push({ file, args, options: spawnOptions });
      const child = new EventEmitter(); child.pid = 123; child.unref = () => {}; child.kill = () => { setImmediate(() => child.emit('close', null, 'SIGTERM')); return true; };
      if (args.length) {
        setImmediate(async () => {
          if (change.spawnError) { child.emit('error', new Error('private-process-error')); child.emit('close', -1); return; }
          await fs.mkdir(args[2].slice(3), { recursive: true });
          await fs.writeFile(path.win32.join(args[2].slice(3), 'AI Team Village.exe'), 'installed fixture');
          child.emit('close', change.exitCode || 0);
        });
      } else setImmediate(() => child.emit('spawn'));
      return child;
    } };
  return { config, options, bytes, manifest, envelope, requests, children, tempRoot };
}

test('authoritative verifier and public configuration are copied without changes', async () => {
  for (const filename of ['update-security.cjs', 'release-config.json']) {
    assert.ok(syncFs.existsSync(path.join(__dirname, filename)));
    const authority = path.resolve(__dirname, '../../apps/desktop', filename);
    if (syncFs.existsSync(authority)) assert.deepEqual(await fs.readFile(path.join(__dirname, filename)), await fs.readFile(authority));
  }
  const { validateReleaseConfig } = require('./update-security.cjs');
  validateReleaseConfig(require('./release-config.json'));
});

test('only signed exact installer is run current-user with raw /D last, then app launches and temp is removed', async t => {
  assert.equal(typeof installer.install, 'function');
  const f = await fixture(t);
  const result = await installer.install(f.config, 'test-access-token', f.options);
  assert.equal(result.version, '1.2.3');
  assert.equal(result.path, path.win32.join(f.options.localAppData, 'Programs', 'AI Team Village', 'AI Team Village.exe'));
  assert.equal(f.requests.length, 2);
  assert.equal(f.requests[1].init.headers.Authorization, 'Bearer test-access-token');
  assert.equal(f.requests[0].init.redirect, 'error'); assert.equal(f.requests[1].init.redirect, 'manual');
  assert.equal(f.children.length, 2);
  const install = f.children[0];
  assert.equal(path.basename(install.file), 'AI-Team-Village-1.2.3-Setup.exe');
  assert.deepEqual(install.args, ['/S', '/currentuser', '/D=' + path.win32.dirname(result.path)]);
  assert.equal(install.options.shell, false); assert.equal(install.options.windowsVerbatimArguments, true);
  assert.equal(f.children[1].file, result.path); assert.deepEqual(f.children[1].args, []);
  assert.equal(f.children[1].options.shell, false);
  assert.ok(!(await fs.readdir(f.tempRoot)).some(name => name.startsWith('ai-team-village-install-')));
});

test('forged signature, path traversal, bad whole hash, redirect, short and oversized downloads never execute', async t => {
  assert.equal(typeof installer.install, 'function');
  for (const change of [
    { envelope: { payload: Buffer.from('{}').toString('base64'), signature: Buffer.alloc(64).toString('base64') } },
    { manifest: { filename: '../other.exe' } },
    { bytes: Buffer.from('xerified executable fixture') },
    { bytes: Buffer.from('short'), contentLength: 5 },
    { bytes: Buffer.alloc(200), contentLength: 200 },
    { bytes: Buffer.alloc(200), contentLength: 27 },
    { status: 302 },
  ]) {
    const f = await fixture(t, change);
    await assert.rejects(installer.install(f.config, 'test-access-token', f.options));
    assert.equal(f.children.length, 0);
    assert.deepEqual(await fs.readdir(f.tempRoot), []);
  }
});

const signedPath = '/storage/v1/object/sign/desktop-updates/releases/1.2.3/AI-Team-Village-1.2.3-Setup.exe?token=';
test('the short-lived Storage link from the update function is followed without the session token', async t => {
  const location = 'https://abcdefghijklmnopqrst.supabase.co' + signedPath + 'fake.signed-token_1';
  const f = await fixture(t, { location });
  assert.equal((await installer.install(f.config, 'test-access-token', f.options)).version, '1.2.3');
  assert.equal(f.requests.length, 3);
  assert.equal(f.requests[2].url, location);
  assert.equal(f.requests[2].init.redirect, 'error'); assert.equal(f.requests[2].init.headers, undefined);
  assert.equal(f.children.length, 2);
});

test('a redirect anywhere but that Storage link never downloads or executes', async t => {
  for (const location of [
    'https://evil.example.invalid' + signedPath + 'abc',
    'https://abcdefghijklmnopqrst.supabase.co' + signedPath.replace('1.2.3/', '1.2.2/') + 'abc',
    'https://abcdefghijklmnopqrst.supabase.co' + signedPath + 'abc&download=x',
    'https://abcdefghijklmnopqrst.supabase.co' + signedPath,
  ]) {
    const f = await fixture(t, { location });
    await assert.rejects(installer.install(f.config, 'test-access-token', f.options));
    assert.equal(f.requests.length, 2);
    assert.equal(f.children.length, 0);
    assert.deepEqual(await fs.readdir(f.tempRoot), []);
  }
});

test('abort during critical installation never kills NSIS and waits for success before cleanup and launch', async t => {
  const f = await fixture(t), controller = new AbortController();
  f.options.signal = controller.signal;
  const spawn = f.options.spawn;
  let child, executable, killed = false, finish, spawnCount = 0;
  const spawned = new Promise(resolve => { finish = resolve; });
  f.options.spawn = (file, args) => {
    spawnCount++;
    if (!args.length) return spawn(file, args, { shell: false });
    assert.equal(args[0], '/S'); executable = file;
    child = new EventEmitter(); child.pid = 123;
    child.kill = () => { killed = true; setImmediate(() => child.emit('close', null, 'SIGTERM')); return true; };
    setImmediate(finish); return child;
  };
  const installing = installer.install(f.config, 'test-access-token', f.options);
  installing.catch(() => {});
  await spawned; controller.abort();
  assert.equal(killed, false); assert.ok((await fs.stat(executable)).isFile());
  const destination = path.win32.join(f.options.localAppData, 'Programs', 'AI Team Village');
  await fs.mkdir(destination, { recursive: true });
  await fs.writeFile(path.win32.join(destination, 'AI Team Village.exe'), 'installed fixture');
  child.emit('close', 0);
  assert.equal((await installing).version, '1.2.3');
  assert.equal(spawnCount, 2);
  assert.ok(!(await fs.readdir(f.tempRoot)).some(name => name.startsWith('ai-team-village-install-')));
});

test('cancellation immediately before installer spawn leaves the installed app untouched', async t => {
  const f = await fixture(t), controller = new AbortController();
  f.options.signal = controller.signal; f.options.onInstalling = () => controller.abort();
  await assert.rejects(installer.install(f.config, 'test-access-token', f.options), error => error.code === 'CANCELLED');
  assert.equal(f.children.length, 0); assert.deepEqual(await fs.readdir(f.tempRoot), []);
});

test('manifest download has a size/time bound before any binary can be fetched', async t => {
  for (const failure of ['oversize', 'timeout']) {
    const f = await fixture(t); f.options.requestTimeoutMs = 20;
    f.options.fetch = async () => failure === 'oversize' ? new Response('x'.repeat(65537)) : new Promise(() => {});
    await assert.rejects(installer.install(f.config, 'test-access-token', f.options));
    assert.equal(f.children.length, 0); assert.deepEqual(await fs.readdir(f.tempRoot), []);
  }
});

test('interrupted body and download timeout cancel streaming, remove partial files and never spawn', async t => {
  assert.equal(typeof installer.install, 'function');
  for (const failure of ['interrupted', 'timeout', 'abort']) {
    const f = await fixture(t);
    const original = f.options.fetch, controller = new AbortController(); let cancelled = false;
    f.options.signal = controller.signal; f.options.downloadTimeoutMs = 25;
    f.options.fetch = async (url, init) => {
      if (String(url).endsWith('manifest.json')) return original(url, init);
      return new Response(new ReadableStream({
        start(stream) { stream.enqueue(f.bytes.subarray(0, 5)); if (failure === 'interrupted') stream.error(new Error('private-stream-error')); if (failure === 'abort') setImmediate(() => controller.abort()); },
        cancel() { cancelled = true; },
      }));
    };
    await assert.rejects(installer.install(f.config, 'test-access-token', f.options), error => !error.message.includes('private-stream-error'));
    if (failure !== 'interrupted') assert.ok(cancelled);
    assert.equal(f.children.length, 0); assert.deepEqual(await fs.readdir(f.tempRoot), []);
  }
});

test('installer process errors and failed exit clean temp and do not launch the app', async t => {
  assert.equal(typeof installer.install, 'function');
  for (const change of [{ spawnError: true }, { exitCode: 2 }]) {
    const f = await fixture(t, change);
    await assert.rejects(installer.install(f.config, 'test-access-token', f.options), error => !error.message.includes('private-process-error'));
    assert.equal(f.children.length, 1);
    assert.ok(!(await fs.readdir(f.tempRoot)).some(name => name.startsWith('ai-team-village-install-')));
  }
});
