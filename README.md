# isolation-test-pages

격리 수집 서버를 시험하기 위한 독립 도구입니다. 합성(가짜) 테스트 페이지를 만들고,
43개 사례의 실행 결과와 증거를 정확하게 보고합니다. 어떤 사례도 "아마 통과"로 처리하지
않으며, 환경이 없거나 증거가 없으면 `blocked`(선행조건 부족)로 보고합니다.

이 도구가 보여 주는 것은 지정한 사례의 결과뿐입니다. 모든 브라우저 취약점에 대한
안전을 증명하지 않습니다.

## 구성

| 위치 | 내용 |
| --- | --- |
| `tools/isolation-tests/cases.json` | 43개 사례와 변형의 유일한 원본 |
| `test-pages/` | 공개 합성 페이지. `isolation-build-pages` 출력이며 직접 고치지 않음 |
| `tools/isolation-tests/isolation_tests/` | 빌더, 표본 서버, 수신 기록, 실행기, 리포트, 공개 가드 |
| `tests/` | 계약 시험 |
| `docs/public-requirements.md` | 공개용 요구사항 요약 |
| `docs/runbook.md` | 실행 순서와 증거 채집 절차 |

## 설치와 로컬 시험

```
python -m venv .venv
.venv/bin/python -m pip install -e '.[test]'     # Windows: .venv\Scripts\python.exe
python -m pytest tests -q -m "not browser"
python -m playwright install chromium            # 선택: 브라우저 시험
python -m pytest tests -q -m browser
```

Python 3.11 이상이 필요합니다.

## 명령

```
isolation-build-pages --manifest tools/isolation-tests/cases.json --output test-pages --commit <sha>
isolation-fixtures ...                           # 별도 HTTP 표본 서버
isolation-tests list --manifest tools/isolation-tests/cases.json
isolation-tests check-env --config config.local.json
isolation-tests run --config config.local.json --output results
isolation-tests report --input results/<report>.json --output results --config config.local.json
isolation-tests host-probe --output host-probe.json --run-id <host_batch> --boundary container
```

종료 코드: 통과 0, 실패 1, 미완료(`blocked`/`not_run` 포함) 2. 일부 그룹만 통과한
리포트는 전체 검증 완료가 아닙니다. 전체 순서는 `docs/runbook.md`를 봅니다.

## 게시 순서

아직 게시하지 않았습니다. 게시 주소는 게시가 실제로 끝난 뒤에 이 문서에 적습니다.
`<login>`은 승인된 개인 GitHub 로그인, `<noreply-email>`은 그 계정의 noreply 주소이며,
아래는 `docs/runbook.md` 7절과 같은 순서입니다. 가드는 값을 출력하지 않고 통과/거부만 출력합니다.

1. 첫 커밋 전에 noreply 이메일을 설정합니다. 이어서 이력·산출물 가드를 실행합니다.

   ```
   git config user.email "<noreply-email>"
   isolation-build-pages --manifest tools/isolation-tests/cases.json --output test-pages --commit <sha>
   python -m isolation_tests.publish_guard history
   python -m isolation_tests.publish_guard artifact test-pages
   ```

2. 원격 저장소를 만듭니다. 자동 push 옵션(`--push`)은 붙이지 않습니다.

   ```
   gh repo create <login>/isolation-test-pages --public --source . --remote origin
   ```

3. 한 번만 수동으로 Pages를 켭니다(첫 push 전). 빌드 유형은 "workflow"(GitHub Actions)입니다.
   아래 명령 또는 Settings > Pages > Source: GitHub Actions 중 하나를 사용합니다. 켜지 않으면
   첫 배포가 404로 실패할 수 있습니다.

   ```
   gh api -X POST repos/<login>/isolation-test-pages/pages -f build_type=workflow
   ```

   읽기 전용으로 확인합니다(build_type이 workflow여야 함).

   ```
   gh api repos/<login>/isolation-test-pages/pages
   ```

4. 공개 owner 변수를 설정합니다. 값이 없거나 소유자가 다르면 build가 실행되지 않습니다.

   ```
   gh variable set PERSONAL_OWNER --body <login> --repo <login>/isolation-test-pages
   ```

5. 저장소 가드를 실행합니다. 인증된 계정이 User인지, 저장소 owner가 User이고 fork가
   아니며 공개인지, origin의 fetch URL과 모든 push URL(pushurl, 여러 push URL,
   pushInsteadOf 적용 후)이 owner/repo와 일치하는지, 전체 이력이 noreply인지 확인합니다.

   ```
   python -m isolation_tests.publish_guard repository --owner <login> --repo isolation-test-pages
   ```

6. 5단계를 통과한 뒤에만 push합니다. force-push는 하지 않습니다.

저장소가 이미 있으면 읽기 전용으로 owner, 공개 여부, Pages 상태(`gh api repos/<login>/isolation-test-pages/pages`)만
확인합니다. 기존 내용을 교체하거나 덮어쓰지 않습니다. Pages가 켜져 있지 않으면 중단하고
소유자에게 문의합니다. 가드가 거부해도 중단합니다.

## 하지 않는 것

- 설정(`config.local.json`), 결과(`results/`), 증거(`evidence/`), 인증서·키·로그는 Git과
  Pages에 올리지 않습니다(`.gitignore`와 공개 가드가 막습니다).
- 실제 개인정보, 실제 악성 파일, 자동 입력·제출·실행은 없습니다. APK는 실행할 수 없는
  고정 문자열 표본입니다.
