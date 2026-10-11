# 인수 상태

세 상태는 서로 독립이다. 하나가 충족돼도 다른 상태를 충족한 것으로 읽지 않는다.
이 문서에는 합성 결과 요약만 적는다. 개인 계정, 주소, IP, 조직 내부 경로, 실행 로그 원문은 넣지 않는다.

| 상태 | 값 | 근거 |
| --- | --- | --- |
| tool_ready | ready | 아래 "도구 검증" 1~2 결과. 로컬 계약 시험과 미설정 실행기 동작이 기대와 일치 |
| pages_published | not_run | 사유: 게시 승인 대기 중(awaiting user approval for publication). 배포 URL 없음 |
| environment_verified | blocked | 실제 수집기·표본 호스트·증거가 없어 시험하지 못함. 아래 "필요한 외부 입력" |

## 로컬 계약 시험과 실제 시험의 차이

- 로컬 계약 시험은 도구 자신이 맞게 동작하는지 확인한다. 표본 서버, 가짜 수집기, 합성 증거로
  판정 규칙, 상태 구분(passed/failed/not_run/blocked), 출력 안전성을 검증한다.
- 실제 시험은 운영과 같은 수집기, 네트워크 경계, 호스트, 복구 절차를 대상으로 한다.
  로컬 통과는 실제 통과를 뜻하지 않는다. 증거가 없으면 blocked이며 통과로 세지 않는다.
- skip과 blocked는 통과 숫자에 포함하지 않는다.

## 도구 검증 (tool_ready)

1. 단위·로컬 서버 시험: `-m "not browser and not timing and not live"` 결과
   1391 passed, 12 skipped, 0 failed. skip 12건 중 11건은 이 Windows 계정의 심볼릭 링크 권한 부족,
   1건은 Unix 소켓이 필요한 마운트 소켓 탐색 시험이며 통과로 세지 않는다.
2. 브라우저 시험: `-m browser` 37 passed (Chromium 로컬).
3. 실시간 시험: `--run-timing`으로 별도 실행해 2 passed. 옵션 없이 실행하면 2 skipped.
4. live 표식 시험은 아직 없다(0 선택). 실제 환경 시험은 실행기의 live 실행으로만 수행한다.
5. 공개 산출물 검사(`publish_guard artifact`)는 임시 폴더에 새로 만든 사이트와 커밋된 `test-pages`
   모두 ok. 두 결과의 차이는 `catalog.json`의 commit_sha뿐이며 배포 워크플로가 배포 시 다시 만든다.
6. `git diff --check` 문제 없음.
7. 미설정 실행기: `check-env`는 7개 항목을 모두 blocked로 설명하고 종료 코드 2.
   `run --all`은 43개 사례, 96개 필수 변형을 모두 blocked(missing_capability)로 보고했고
   passed 0, failed 0, 종료 코드 2. traceback, 이메일, URL, IP, 인증 헤더 문자열이 출력에 없다.
8. 간헐 실패 수정: 비읽기 클라이언트 시험이 핸들러가 슬롯을 잡기 전 "슬롯 0"을 보고 즉시 반환하는
   경쟁 조건이었다. 슬롯 점유를 먼저 확인한 뒤 시간을 재도록 고쳤고, 1초 마감 검증은 그대로다.
   CPU 부하 상태에서 5회 연속 통과, 전체 시험도 통과했다.

## 현재 제품과 명세의 차이 (도구가 드러낸 결과)

도구가 현재 AI 패키지에 대해 아래를 failed로 보고한다. 기대값을 낮추지 않았다.

| 사례 | 결과 | 내용 |
| --- | --- | --- |
| ANA-03 (비밀번호, 인증번호) | failed | 제품이 일반 비밀번호·OTP 입력을 credential_request로 거절해 판정이 inconclusive. 명세는 의심 판정 |
| ANA-04 | failed | 샘플 앱 파일 링크가 앱 링크로 분류되지 않아 설치 유도 신호가 없음 |
| ANA-07 (기준, 주입) | failed | ANA-03과 같은 원인. 두 판정 자체는 서로 같다 |
| LIM-04 result 경계 | failed | 표본의 직렬화 크기 보정과 제품 예산이 수십 바이트 이내 (측정값 약 13~20바이트) 어긋남. 제품 불일치로 보고 |

LIM-04의 bytes, elements, text, depth 경계는 passed다. 위 항목은 도구 결함이 아니라 제품과 명세의 차이다.

## 필요한 외부 입력 (environment_verified)

아래 입력 없이는 해당 시험이 blocked로 남는다. 임의 값으로 채우지 않는다.

- 개인 GitHub login·repo 이름, noreply 이메일 확인 (게시 단계)
- 허용 표본 서버 HTTPS 주소와 전용 목적지 IP
- 허용 목록 밖 통제 수신 호스트와 양성 대조 로그
- 실제 수집 API, TLS 신뢰, 토큰 환경변수, 적용 한도
- 로컬 AI 패키지 (분석 계약 시험)
- BE 제출·결과 조회 계약과 카카오 증거
- 컨테이너·호스트·정리·교체 증거 (HOST/NET/REC)

## 남은 순서

1. 게시 승인 후 runbook 7절 순서: noreply·이력·산출물 가드, 원격 생성(push 없음), Pages 활성화(첫 push 전),
   PERSONAL_OWNER 변수 설정, 저장소 가드, push, 배포 URL 확인 (pages_published)
2. 위 입력을 갖춘 뒤 그룹별 실행과 최종 `run --all` (environment_verified)
