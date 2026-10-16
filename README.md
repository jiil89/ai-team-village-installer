# AI Team Village 설치 실행기

Windows에서 Git이나 GitHub 계정 없이 AI Team Village를 설치합니다. Node.js 22 이상이 필요합니다. 설치 명령은 PowerShell에서 실행합니다.

```powershell
npx.cmd --yes https://github.com/jiil89/ai-team-village-installer/releases/latest/download/installer.tgz
```

등록된 이메일을 입력한 뒤 **설치 명령을 실행한 PC에서 최신 인증메일의 링크**를 열어 주세요. 인증 대기 시간은 5분입니다. 인증과 다운로드 중에는 `Ctrl+C`로 취소할 수 있습니다. 설치 파일 교체가 시작되면 기존 설치를 보호하기 위해 종료하지 않고 완료될 때까지 기다립니다. 이미 다른 설치 창이 인증을 기다리고 있다면 그 창을 닫고 다시 실행합니다.

설치 실행기는 회원 등록을 확인한 뒤 비공개 설치 파일을 받습니다. 고정된 Ed25519 공개키로 manifest의 서명을 확인하고 파일 크기와 전체 SHA512를 검증한 후, 현재 사용자에게 설치하고 앱을 실행합니다. 기본 설치 경로는 `%LOCALAPPDATA%\Programs\AI Team Village`입니다.

**앱의 첫 로그인은 설치 인증과 별도입니다.** 설치 실행기는 인증 토큰과 PKCE verifier를 파일에 저장하거나 앱에 전달하지 않습니다. 기존 앱의 프로필과 설정을 삭제하지 않습니다.

설치 이후 앱의 변경 사항은 기존 자동 업데이트로 받습니다. 앱 업데이트마다 이 설치 명령을 반복할 필요는 없습니다.

도움말과 버전은 인증 없이 확인할 수 있습니다.

```powershell
npx.cmd --yes https://github.com/jiil89/ai-team-village-installer/releases/latest/download/installer.tgz --help
npx.cmd --yes https://github.com/jiil89/ai-team-village-installer/releases/latest/download/installer.tgz --version
```

인증메일 요청이 제한되면 잠시 기다린 뒤 다시 실행합니다. 회원 확인이 거부되면 관리자에게 활성 팀원 등록 상태를 확인해 주세요. 다운로드·서명·해시 검증에 실패하면 설치 파일을 실행하지 않습니다. 설치 파일 다운로드의 제한 시간은 5분입니다.

인증 콜백은 `127.0.0.1:48190/install/callback`에서만 받습니다. 다른 PC에서 메일 링크를 열면 인증을 완료할 수 없습니다. 회사 네트워크가 다운로드를 차단하는 경우에는 관리자에게 네트워크 허용 여부를 확인합니다.

개발 검증은 Windows에서 패키지 폴더의 `npm.cmd test`로 실행합니다. 자동 테스트는 가상 인증 응답·서명된 테스트 데이터·가짜 설치 프로세스를 사용하며 실제 인증메일을 발송하지 않습니다. 실제 회원 인증과 Windows NSIS 설치는 이 테스트만으로 검증되지 않습니다.
