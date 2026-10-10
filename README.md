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

## 공개 전 검사

```
python -m isolation_tests.publish_guard artifact test-pages
python -m isolation_tests.publish_guard history
python -m isolation_tests.publish_guard repository --owner <login> --repo isolation-test-pages
```

가드는 실제 이메일·토큰·원격 주소 값을 출력하지 않고 통과/거부 상태와 종류만 출력합니다.

## 게시 상태

아직 게시하지 않았습니다. 게시 주소는 게시가 실제로 끝난 뒤에 이 문서에 적습니다.

## 하지 않는 것

- 설정(`config.local.json`), 결과(`results/`), 증거(`evidence/`), 인증서·키·로그는 Git과
  Pages에 올리지 않습니다(`.gitignore`와 공개 가드가 막습니다).
- 실제 개인정보, 실제 악성 파일, 자동 입력·제출·실행은 없습니다. APK는 실행할 수 없는
  고정 문자열 표본입니다.
