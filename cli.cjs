#!/usr/bin/env node
const readline = require('node:readline/promises');
const { authenticate } = require('./auth.cjs');
const { install } = require('./installer.cjs');
const { InstallerError } = require('./http.cjs');
const config = require('./release-config.json');
const { version } = require('./package.json');

const help = `AI Team Village 설치 실행기 ${version}

사용법: ai-team-village-install [--help | --version]
요구 환경: Windows, Node.js 22 이상. Git과 GitHub 계정은 필요하지 않습니다.

등록된 팀원 이메일을 입력하면 인증메일 없이 바로 확인합니다.
현재 사용자에게 설치한 뒤 앱을 실행합니다. 앱에서는 같은 이메일로 다시 입장합니다.
설치 시작 전까지 Ctrl+C로 취소할 수 있습니다.
설치 파일 교체가 시작되면 완료될 때까지 기다려 주세요.
`;

async function main(args = process.argv.slice(2), options = {}) {
  const output = options.output || process.stdout;
  if (args.length === 1 && args[0] === '--help') { output.write(help); return; }
  if (args.length === 1 && args[0] === '--version') { output.write(version + '\n'); return; }
  if (args.length) throw new InstallerError('ARGUMENTS');
  if ((options.platform || process.platform) !== 'win32' || Number(process.versions.node.split('.')[0]) < 22) throw new InstallerError('PLATFORM');
  const controller = new AbortController();
  let installing = false;
  const cancel = () => { if (!installing) controller.abort(); };
  process.on('SIGINT', cancel);
  let prompt;
  try {
    let email;
    if (options.askEmail) email = await options.askEmail(controller.signal);
    else {
      prompt = readline.createInterface({ input: process.stdin, output }); prompt.on('SIGINT', cancel);
      email = await prompt.question('등록된 이메일: ', { signal: controller.signal });
      prompt.close();
    }
    const accessToken = await (options.authenticate || authenticate)(config, email.trim(), {
      signal: controller.signal,
    });
    output.write('회원 인증을 확인했습니다. 검증된 설치 파일을 다운로드합니다.\n');
    const installed = await (options.install || install)(config, accessToken, {
      signal: controller.signal,
      onInstalling: () => { installing = true; output.write('설치 파일 교체를 시작합니다. 이 단계가 끝날 때까지 기다려 주세요.\n'); },
    });
    output.write(`AI Team Village ${installed.version} 설치를 마치고 앱을 실행했습니다.\n앱에서 같은 이메일로 입장해 주세요.\n`);
    return installed;
  } catch (error) { if (controller.signal.aborted) throw new InstallerError('CANCELLED'); throw error; }
  finally { prompt?.close(); process.removeListener('SIGINT', cancel); }
}

if (require.main === module) main().catch(error => {
  process.stderr.write((error instanceof InstallerError ? error.message : new InstallerError('INSTALL').message) + '\n');
  process.exitCode = error?.code === 'CANCELLED' ? 130 : 1;
});
module.exports = { main };
