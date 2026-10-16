const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const cli = fs.existsSync(__dirname + '/cli.cjs') ? require('./cli.cjs') : {};

test('help and version work offline and reject token/config overrides', () => {
  const file = path.join(__dirname, 'cli.cjs');
  assert.ok(fs.existsSync(file));
  const version = spawnSync(process.execPath, [file, '--version'], { encoding: 'utf8' });
  assert.equal(version.status, 0); assert.equal(version.stdout.trim(), '0.1.0');
  const help = spawnSync(process.execPath, [file, '--help'], { encoding: 'utf8' });
  assert.equal(help.status, 0); assert.match(help.stdout, /Node\.js 22/); assert.match(help.stdout, /Windows/);
  const invalid = spawnSync(process.execPath, [file, '--token', 'private-argument'], { encoding: 'utf8' });
  assert.equal(invalid.status, 1); assert.ok(!invalid.stderr.includes('private-argument'));
});

test('Ctrl+C shares cancellation with authentication, stops installation and restores signal handlers', async () => {
  let signal, notify;
  const waiting = new Promise(resolve => { notify = resolve; });
  const before = process.listenerCount('SIGINT'); let installed = false;
  const running = cli.main([], { platform: 'win32', output: { write() {} }, askEmail: async () => 'member@example.invalid',
    authenticate: async (config, email, options) => {
      signal = options.signal; notify();
      await new Promise((resolve, reject) => signal.addEventListener('abort', () => reject(new Error('private-cancellation-detail')), { once: true }));
    }, install: () => { installed = true; } });
  const rejected = assert.rejects(running, error => error.code === 'CANCELLED');
  await waiting; process.emit('SIGINT'); await rejected;
  assert.ok(signal.aborted); assert.equal(installed, false);
  assert.equal(process.listenerCount('SIGINT'), before);
});

test('Ctrl+C during critical file replacement lets installation complete and reports success', async () => {
  const messages = [];
  await cli.main([], { platform: 'win32', output: { write: value => messages.push(value) }, askEmail: async () => 'member@example.invalid',
    authenticate: async () => 'test-access-token',
    install: async (config, token, options) => {
      assert.equal(typeof options.onInstalling, 'function');
      options.onInstalling(); process.emit('SIGINT');
      assert.equal(options.signal.aborted, false);
      return { version: '1.2.3', path: 'C:\\Users\\Test\\App.exe' };
    } });
  assert.match(messages.join(''), /파일 교체/); assert.match(messages.join(''), /1\.2\.3/);
});

test('unsupported platform exits before prompting or authenticating', async () => {
  assert.equal(typeof cli.main, 'function');
  let called = false;
  await assert.rejects(cli.main([], { platform: 'linux', authenticate: () => { called = true; }, askEmail: () => { called = true; } }));
  assert.equal(called, false);
});
