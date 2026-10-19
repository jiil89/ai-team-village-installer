# AI Team Village 설치 실행기

Windows에서 Git이나 GitHub 계정 없이 AI Team Village를 설치합니다. Node.js 22 이상이 필요합니다. 설치 명령은 PowerShell에서 실행합니다.

```powershell
npx.cmd --yes https://github.com/jiil89/ai-team-village-installer/releases/latest/download/installer.tgz
```

등록된 팀원 이메일을 입력하면 인증메일 없이 바로 회원을 확인합니다. 다운로드 중에는 `Ctrl+C`로 취소할 수 있습니다. 설치 파일 교체가 시작되면 기존 설치를 보호하기 위해 종료하지 않고 완료될 때까지 기다립니다.

**임시 운영 방식 (2026-10-19)**: 메일 발송 한도 때문에 이메일 인증을 잠시 끈 상태입니다. 등록된 이메일 주소를 아는 사람은 그 팀원으로 설치하고 입장할 수 있습니다. 보안 확인은 추후 다시 적용합니다.

설치 실행기는 회원 등록을 확인한 뒤 비공개 설치 파일을 받습니다. 고정된 Ed25519 공개키로 manifest의 서명을 확인하고 파일 크기와 전체 SHA512를 검증한 후, 현재 사용자에게 설치하고 앱을 실행합니다. 기본 설치 경로는 `%LOCALAPPDATA%\Programs\AI Team Village`입니다.

설치가 끝나면 앱에서 같은 이메일로 다시 입장합니다. 설치 실행기는 인증 토큰을 파일에 저장하거나 앱에 전달하지 않습니다. 기존 앱의 프로필과 설정을 삭제하지 않습니다.

설치 이후 앱의 변경 사항은 기존 자동 업데이트로 받습니다. 앱 업데이트마다 이 설치 명령을 반복할 필요는 없습니다.

도움말과 버전은 인증 없이 확인할 수 있습니다.

```powershell
npx.cmd --yes https://github.com/jiil89/ai-team-village-installer/releases/latest/download/installer.tgz --help
npx.cmd --yes https://github.com/jiil89/ai-team-village-installer/releases/latest/download/installer.tgz --version
```

등록되지 않은 이메일이라고 나오면 관리자에게 활성 팀원 등록 상태를 확인해 주세요. 다운로드·서명·해시 검증에 실패하면 설치 파일을 실행하지 않습니다. 설치 파일 다운로드의 제한 시간은 5분입니다.

회사 네트워크가 다운로드를 차단하는 경우에는 관리자에게 네트워크 허용 여부를 확인합니다.

개발 검증은 Windows에서 패키지 폴더의 `npm.cmd test`로 실행합니다. 자동 테스트는 가상 인증 응답·서명된 테스트 데이터·가짜 설치 프로세스를 사용합니다. 실제 회원 인증과 Windows NSIS 설치는 이 테스트만으로 검증되지 않습니다.
