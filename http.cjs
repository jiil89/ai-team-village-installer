const fs = require('node:fs/promises');

const messages = {
  PLATFORM: 'Windows에서 Node.js 22 이상으로 실행해 주세요.',
  ARGUMENTS: '지원하지 않는 인수입니다. --help에서 사용법을 확인해 주세요.',
  EMAIL: '등록된 이메일 주소를 입력해 주세요.',
  AUTH_TIMEOUT: '인증 응답이 늦어 중단했습니다. 네트워크를 확인하고 설치 명령을 다시 실행해 주세요.',
  CANCELLED: '설치를 취소했습니다.',
  AUTH: '설치 인증에 실패했습니다. 잠시 뒤 설치 명령을 다시 실행해 주세요.',
  NOT_REGISTERED: '등록된 팀원 이메일이 아닙니다. 관리자에게 등록을 요청해 주세요.',
  MEMBERSHIP: '활성 팀원 등록을 확인하지 못했습니다. 관리자에게 등록 상태를 확인해 주세요.',
  NETWORK: '서버 응답을 받지 못했습니다. 네트워크를 확인하고 다시 실행해 주세요.',
  CONFIG: '설치 설정 또는 현재 사용자 설치 경로를 확인하지 못했습니다.',
  VERIFY: '설치 파일의 서명 또는 무결성 검증에 실패했습니다.',
  DOWNLOAD: '설치 파일 다운로드가 중단되었거나 검증된 크기와 다릅니다.',
  INSTALL: '현재 사용자 설치를 완료하지 못했습니다. 실행 중인 앱을 닫고 다시 시도해 주세요.',
  LAUNCH: '설치는 완료되었지만 앱을 실행하지 못했습니다. 시작 메뉴에서 AI Team Village를 실행해 주세요.',
};
class InstallerError extends Error {
  constructor(code) { super(messages[code] || messages.INSTALL); this.code = code; }
}

function abortable(promise, signal) {
  signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    const abort = () => reject(new InstallerError('CANCELLED'));
    signal.addEventListener('abort', abort, { once: true });
    Promise.resolve(promise).then(resolve, reject).finally(() => signal.removeEventListener('abort', abort));
  });
}

async function request(url, init, maxBytes, consume, options) {
  const controller = new AbortController();
  const signal = options.signal ? AbortSignal.any([options.signal, controller.signal]) : controller.signal;
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 15000);
  let response, reader;
  const cancel = () => { if (reader) void reader.cancel().catch(() => {}); else if (response?.body) void response.body.cancel().catch(() => {}); };
  try {
    signal.throwIfAborted();
    const pending = (options.fetch || globalThis.fetch)(url, { redirect: 'error', ...init, signal, cache: 'no-store' });
    Promise.resolve(pending).then(value => { if (signal.aborted) void value.body?.cancel().catch(() => {}); }, () => {});
    response = await abortable(pending, signal);
    if (!response.ok || (options.exactSize !== undefined && response.status !== 200)) {
      const error = new InstallerError('NETWORK'); error.status = response.status; error.location = response.headers.get('location'); throw error;
    }
    const length = response.headers.get('content-length');
    if (length !== null && (!/^\d+$/.test(length) || Number(length) > maxBytes || (options.exactSize !== undefined && Number(length) !== options.exactSize))) throw new InstallerError('DOWNLOAD');
    if (!response.body) throw new InstallerError('NETWORK');
    reader = response.body.getReader();
    signal.addEventListener('abort', cancel, { once: true });
    let size = 0;
    for (;;) {
      const chunk = await abortable(reader.read(), signal);
      signal.throwIfAborted();
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > maxBytes) throw new InstallerError('DOWNLOAD');
      await consume(chunk.value);
    }
    if (options.exactSize !== undefined && size !== options.exactSize) throw new InstallerError('DOWNLOAD');
  } catch (error) {
    cancel();
    if (options.signal?.aborted) throw new InstallerError('CANCELLED');
    if (error instanceof InstallerError) throw error;
    throw new InstallerError('NETWORK');
  } finally {
    clearTimeout(timer); signal.removeEventListener('abort', cancel);
    try { reader?.releaseLock(); } catch {}
  }
}

async function requestJson(url, init, options = {}) {
  const chunks = [];
  await request(url, init, 65536, chunk => { chunks.push(Buffer.from(chunk)); }, options);
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw new InstallerError('NETWORK'); }
}

async function downloadFile(url, file, size, init, options = {}) {
  const handle = await fs.open(file, 'wx', 0o600);
  const write = chunk => handle.writeFile(chunk), sized = { ...options, exactSize: size };
  try {
    try { await request(url, init, size, write, sized); }
    catch (error) {
      // The update function hands the file to a short-lived Storage link. Only a link the caller accepts is followed,
      // without the session token; the signed whole-file hash is still checked before anything runs.
      if (error.status !== 302 || !options.acceptRedirect?.(error.location)) throw error;
      await request(error.location, {}, size, write, sized);
    }
  } finally { await handle.close(); }
}

module.exports = { InstallerError, abortable, requestJson, downloadFile };
