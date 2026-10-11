# 실행 안내 (runbook)

실제 운영 값(주소, 토큰 변수명, 인증서 경로, 증거 폴더)은 `config.local.json`과 증거
파일에만 적습니다. 이 저장소의 문서, 예시, 커밋에는 쓰지 않습니다.
`config.local.json`, `results/`, `evidence/`는 Git에서 제외되며 공개 가드가 거부합니다.

## 0. 준비

1. `python -m pip install -e '.[test]'` 후 `python -m pytest tests -q -m "not browser"`가 통과해야 합니다.
2. `tools/isolation-tests/config.example.json`을 `config.local.json`으로 복사해 채웁니다.
3. 토큰은 환경변수 이름만 설정에 쓰고, 값은 셸 환경에서 지정합니다.

## 1. 프로필

| 프로필 | 용도 | 조건 |
| --- | --- | --- |
| 로컬 | 도구 자체와 계약 시험 | loopback HTTP 허용(`allow_loopback_http: true`). 수집기 실제 검증으로 인정하지 않음 |
| HTTPS | 원격 시험 | 모든 대상이 HTTPS. 정상 인증서를 쓰며 검증을 전역으로 끄지 않음 |

잘못된 인증서 사례(INT-01 untrusted-ca)는 별도 `ca_file` 프로필이 있을 때만 시연합니다.

## 2. 통제 호스트 두 개

- 표본 서버 호스트: HTTP 응답 제어 사례(`isolation-fixtures`)를 제공합니다.
- 수신 관측 호스트: 허용 목록에 넣지 않는 별도 호스트이며, 금지 대상으로 요청이 도착하는지
  기록합니다. 실제 악성 호스트를 쓰지 않습니다.

두 호스트는 격리 서버와 같은 호스트에 두지 않습니다. 설정의 `bases`에 `pages`,
`http_fixture`, `forbidden_receiver`를 지정합니다.

수신 대조 요청(8-2)의 대상은 그 변형의 유출 요청이 가는 수신기입니다. NET-03·NET-04
변형은 변형 이름의 대상(`loopback`, `private`, `link_local`, `main_public`,
`isolation_public`, `shared_ip_host`, `same_host_path`), NET-07 initial-private는 `private`,
나머지는 `forbidden_receiver`입니다. 표본 서버의 `--target`과 실행기 설정의 `bases`에 같은
이름·주소를 적습니다. 실행기는 보내기 전에 표본 서버에 그 변형의 수신 주소를 물어 자기
`bases` 주소와 같은지 확인하고, 다르면 보내지 않습니다(blocked,
`receiver_log_coverage_unproven`). 격리 컨테이너 기준 주소인 `loopback`·`private`·`link_local`에는
실행기가 대조를 보내지 않습니다(8-2의 격리 측 대조).

## 3. 허용 목록 전환은 별도 작업

온라인 프로필로 전환하려면 격리 환경의 네트워크 허용 목록을 바꿔야 합니다. 이 도구는 그
변경을 수행하지 않습니다. 관리자가 별도 작업으로 수행하고 기록합니다.

- 방화벽을 전면 개방하지 않습니다. 임의 DNS 개방으로 복구하지 않습니다.
- Pages 주소는 정확한 HTTPS 호스트·포트·경로로 허용하고 `*.github.io` 전체는 허용하지 않습니다.
- IP를 고정했다면 DNS·인증서·목적지 일치와 변경 감지를 확인하고, IP가 바뀌면 실패로 두고 재검토합니다.

## 4. 양성 대조와 수신 증거

차단 사례를 통과로 보려면 같은 실행 구간에서 먼저 다음이 확인되어야 합니다.

1. 정상 대상(Pages 또는 COL-01)이 실제로 수집된다(양성 대조).
2. 수신 호스트의 기록 장치가 동작한다(실행기가 시험 구간 안에 수신기로 직접 보낸 대조
   요청 `/v1/control/<사례>`가 그 run_id로 기록됨. 이 요청은 격리 환경을 거치지 않으며 격리
   컨테이너의 허용 정책을 넓히지 않아야 함).
3. 금지 대상에는 같은 구간에 수신 기록이 없다.

타임아웃, 닫힌 포트, 콘솔·CORS 오류만으로는 차단 통과가 아닙니다. 증거는 run id와 시각으로
사례에 연결합니다. 3번(수신 기록 없음)은 관리자가 적지 않습니다. 수신 호스트의 기록 파일을
`evidence_dir/receiver-<호스트>.jsonl`로 복사하면 실행기가 직접 읽어 판정합니다(8-2).

## 5. 실행 (두 단계)

### 5-1. 관측: `run`

```
isolation-tests check-env --config config.local.json
isolation-tests run --config config.local.json --output results --group collection --group analysis
```

- 선택: `--case ID`(반복 가능), `--group 이름`(반복 가능), `--all`. 아무것도 고르지
  않으면 저부하 기본 사례만 실행합니다. `--all`과 `--group`은 함께 쓸 수 없습니다.
- 그룹: collection, navigation, analysis, network, session, download, http, limits,
  host, integration, recovery. 네트워크·부하·호스트·복구는 명시했을 때만 실행됩니다.
- `--pages-commit <sha>`: 배포된 Pages의 커밋을 리포트에 기록합니다.
- `--collector-limit N`: LIM-06(동시성)에 필요합니다. 수집기 운영 상한 N을 알려 주면
  N+1건을 동시에 보냅니다. 생략하면 `blocked`이며, N+1이 8을 넘으면 요청을 보내지 않습니다.
- HOST 사례를 선택하면 `host_batch<TAB><id>`가 출력됩니다. 다음 단계에서 씁니다.

### 5-2. 관리자 증거 채집

실행기는 SSH를 하지 않고 EC2를 만들거나 지우지 않습니다. 아래 증거는 관리자가 수집합니다.
증거 파일 형식은 `tools/isolation-tests/evidence.example.json`(합성 자리표시자)을 따르며,
승인된 사실 이름과 값만 받습니다. 비밀값, 인스턴스 ID, 파일 내용은 적지 않습니다.
사실마다 누가, 어떻게 만들고 어떤 run_id·구간에 묶는지는 8절의 표를 따릅니다.

권장 순서:

1. 직접 연결 (NET-05): 컨테이너 경계 안에서 TCP·외부 DNS·IPv6 시도와 drop 관측.
   관리 호스트의 결과로 대신하지 않습니다.
2. 다운로드 임시 영역 (DL-02): 작업 전후 임시 저장 영역과 프로세스 종료 뒤 잔존 자료.
3. 작업 정리 (HOST-03): 자식 프로세스, 작업 상태, 임시 자료 정리, 이미지 digest와 플랫폼.
4. 호스트 상태 (HOST-01/02): 대상 컨테이너 안에서

   ```
   isolation-tests host-probe --output host-probe.json --run-id <host_batch> --boundary container
   ```

   `--run-id`는 5-1에서 출력된 `host_batch` 값이어야 하며, 다른 실행의 probe나 시각이
   실행 구간 밖인 probe는 무시됩니다. HOST-03(이미지·작업 정리)은 `--boundary host`로 채집합니다.
   생성된 파일은 `evidence_dir`에 복사합니다. 이 명령은 기존 파일을 덮어쓰지 않습니다.
5. 허용/비허용 출발지 (INT-02): 각각의 관리 기록.
6. 카카오 수신 (INT-03 kakao-receipt): 담당자가 실제 수신을 확인한 기록.
7. 콜백 실패 (INT-04 callback-failure): 증거로만 판정합니다.
8. EC2 교체 (REC-01): 새 인스턴스 생성과 인증정보 교체, 이전 인증정보 거부, 재검증의
   후속 run id. 재부팅·재시작은 교체로 인정하지 않습니다.

### 5-3. 재판정: `report --config`

```
isolation-tests report --input results/isolation-report-<run_id>.json --output results --config config.local.json
```

저장된 관측을 `evidence_dir`의 증거와 다시 대조해 판정합니다. `--config`를 생략하면 저장된
결과를 다시 렌더링만 합니다. 증거가 실행 구간(±1초)과 맞지 않거나 실행기 관측과 충돌하면
`blocked`입니다.

`--manifest`는 기본값(패키지의 정규 `cases.json`)을 씁니다. 해시가 다른 명세로 `run`이나
`report --config`를 실행하면 모든 해당 시험이 `blocked manifest_mismatch`입니다.
`--non-canonical`을 명시하면 실행은 하지만 리포트에 기록되고 전체 결과는 0이 될 수 없습니다.

## 6. 결과 읽기

- 종료 코드 0: 선택 범위 전체 통과, 1: 실패 있음, 2: 실패는 없으나 미완료.
- 일부 그룹만 실행했다면 0이어도 전체 검증 완료가 아닙니다. 전체 완료는 43개 사례와 모든
  변형이 `passed`일 때뿐입니다.
- 리포트는 `results/`에만 저장됩니다. 게시하지 않습니다.

## 7. 공개 전 점검과 게시 순서 (게시 담당자가 수행)

`<login>`은 승인된 개인 GitHub 로그인, `<noreply-email>`은 그 계정의 GitHub noreply 주소입니다.
실제 값은 이 문서에 쓰지 않습니다.

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

저장소 이름이 다르면 모든 명령, 가드 인자, 원격을 그 이름으로 함께 바꿉니다.

저장소가 이미 있으면 읽기 전용으로 owner, 공개 여부, Pages 상태(`gh api repos/<login>/isolation-test-pages/pages`)만
확인합니다. 기존 내용을 교체하거나 덮어쓰지 않습니다. Pages가 켜져 있지 않으면 중단하고
소유자에게 문의합니다. 가드가 거부해도 중단합니다.

- 저장소 소유자는 개인 User 계정이어야 합니다(조직 불가). 조직 저장소 원격을 재사용하지 않습니다.
- 게시 주소는 실제 게시가 끝난 뒤에 README에 적습니다.
- 가드는 값 자체를 출력하지 않고 통과/거부 상태만 출력합니다.

## 8. 증거 생산 안내

아래 표는 `cases.json`의 필수 사실 중 코드(실행기·AI 어댑터·`host-probe`)가 만들지 않는
사실 전부입니다. 목록은 `isolation_tests.runner.admin_facts()`로 생성하며, 시험
(`tests/test_runbook_guide.py`)이 표에 빠진 사실이 없는지 확인합니다. 사례 정의가 바뀌면
표를 다시 생성합니다.

코드가 직접 만드는 사실(관리자가 적지 않음):

코드가 만든 사실은 그 사실을 실제로 만드는 사례에서만 코드 몫입니다
(`isolation_tests.runner.code_facts(사례, 변형)`). 같은 이름이라도 다른 사례에서는 아래 표의
관리자 기록이 필요합니다.

- 실행기, 일반 수집 경로: `positive_control_ok`(COL-01 대조), `collection`,
  `collector_deadline_s`, `deadline_grace_s`. NET-07은 `page_opened`, ANA-07은 `paired_verdict_equal`
- 실행기, 수신 사례(NAV-04, NET-01~07): `receiver_observed`, `receiver_control_ok`(수신 기록에서 읽음, 8-2)
- 실행기, INT-01: `positive_control_ok`, `collection`, `page_opened`, `tls_rejected`,
  `authentication_ok`, `authentication_rejected`
- 실행기, INT-03: `backend_result_ok`, `first_response_deadline_ok`
- 실행기, INT-04: `lookup_fallback_ok`(callback-failure), `positive_control_ok`(llm-timeout,
  collection-failure)
- 실행기, LIM-06만: `positive_control_ok`, `concurrency_limit`, `limit_plus_one_sent`,
  `limit_exceeded_confirmed`, `concurrency_limit_ok`
- AI 어댑터: `analysis`(ANA-01~08, LIM-04, INT-04 llm-timeout·collection-failure),
  `fabricated_evidence_rejected`(ANA-08), `fallback_ok`(INT-04), `boundary_offsets`,
  `boundary_limit`, `boundary_results_ok`(LIM-04)
- `host-probe`(HOST-01/02/03): 프로세스·마운트·읽기 전용·자원 프로필 사실

관리자가 적은 값이 코드의 관측과 다르면 `evidence_conflict`(blocked)입니다. 관리자 값이
코드 관측을 덮어쓰지 못합니다.

### 8-1. 기록 형식과 결합

증거는 `evidence_dir` 안의 `*.jsonl` 파일에 한 줄당 한 기록으로 적습니다. 형식은
`tools/isolation-tests/evidence.example.json`과 같습니다.

```
{"run_id": "<리포트 items[].details.run_id>", "case_id": "NET-01", "started_at": "<UTC>", "ended_at": "<UTC>", "facts": {"variant": "img", ...}, "references": []}
```

- run_id: (사례, 변형)마다 따로 발급되는 값입니다. `run` 리포트의 `items[].details.run_id`를
  그대로 씁니다. 다른 변형·다른 실행의 run_id로 적은 기록은 무시됩니다.
- variant: `facts.variant`는 그 변형 이름과 정확히 같아야 합니다.
- 시각: ISO 8601 UTC(`Z` 또는 `+00:00`). 호스트 간 시계 차이가 1초를 넘으면
  `clock_offset_seconds`를 적고, 1초를 넘는 값은 blocked입니다.
- 구간(실행기가 행동한 사례): 관리자 구간이 리포트의 `details.started_at`~`details.ended_at`과
  ±1초 안에서 겹쳐야 합니다.
- 구간(증거 전용 사례: NET-05, HOST, INT-02, REC-01): 관리자 구간의 시작이 그 시험의
  `details.started_at`보다 1초 넘게 앞서면 안 됩니다(실행 전 기록 재사용 방지). NET-05는
  관리자가 그 구간 안에 대조 요청을 보내야 합니다(8-2).
- 값: 승인된 이름과 정확한 타입만 받습니다(`true` 대신 `1`·`"true"` 불가). 목록 사실은 표의
  허용 항목만 받습니다. 비밀값·인스턴스 ID·파일 내용은 적지 않습니다.
- `fixture_max_active`(LIM-06): 표본 서버의 동시 처리 상한(1~4)을 적습니다. 상한+1이 이
  값보다 크면 표본 부하가 부족해 blocked입니다.

### 8-2. 실행기가 읽는 파일

- 수신 기록: 수신 호스트의 표본 서버(`--log`)가 쓴 JSONL을 `evidence_dir/receiver-<호스트>.jsonl`로
  복사합니다. `receiver_observed`가 필요한 사례(NAV-04, NET-01~07)는 실행기가 이 파일을 직접
  읽어 그 변형의 run_id와 시험 구간(±1초)에 묶습니다.
  - 기록이 살아 있었다는 증명(대조): 실행기는 시험 구간 안에 그 변형의 수신 주소(2절)로
    `GET /v1/control/<사례>?run_id=<run_id>`를 직접 보냅니다(수집기·격리 환경을 거치지 않음).
    NAV-04·NET-01~04·NET-06은 먼저 표본 서버의 `GET /v1/receiver-target/<사례>/<변형>?run_id=`가
    돌려준 유출 수신 주소와 대조 주소가 같은 수신기인지 확인합니다. 다르거나 확인할 수 없으면
    보내지 않습니다. 수신기는 대조를 `path: "/v1/control/<사례>"`로 같은 JSONL에 기록하고, 기록한
    뒤에만 200으로 답합니다. 이 대조 기록이 그 run_id·사례로 시험 구간 안에 있어야 수신 기록을
    판정에 씁니다. 대조 기록은 관측된 요청으로 세지 않습니다.
  - 대조는 그 순간 기록 장치가 동작했음을 보일 뿐, 구간 전체에 걸쳐 계속 동작했음을 보이지는
    않습니다.
  - 격리 측 대조(NET-03 loopback·private·link-local, NET-07 initial-private): 실행기 호스트는
    이 수신기에 격리 컨테이너와 같은 주소로 닿지 못하므로 실행기는 대조를 보내지 않습니다.
    관리자가 `run`이 끝난 뒤 리포트의 그 변형 `details.run_id`로, 격리 컨테이너 안에서
    관리자 기록 구간 안에 다음 주소를 요청합니다.
    `curl -fsS "<표본 서버 --target의 그 이름 주소>/v1/control/<사례>?run_id=<run_id>"`
    정확한 주소는 표본 서버의 `/v1/receiver-target/<사례>/<변형>?run_id=<run_id>` 응답에서
    `/v1/receive/`를 `/v1/control/`로 바꾼 값입니다(NET-07 initial-private는 설정의 `private`
    주소). 그 run_id의 대조 기록이 모두 실행 종료(`details.ended_at`) 뒤, 관리자 구간 안에
    있어야 합니다. 관리자 기록이 없거나 이 대조가 없으면 `receiver_log_coverage_unproven`입니다.
  - `receiver_control_ok`는 실행기가 이 대조 기록에서 만듭니다. 관리자가 `true`를 적어도 대조
    기록이 없으면 통과하지 못하고, 관리자 값이 실행기 값과 다르면 `evidence_conflict`입니다.
  - 대조 기록이 없으면(빈 기록, 오래된 기록, 다른 run_id·사례의 기록, 수신기 중단, 수신 주소
    미설정, 표본 서버와 다른 수신기) `receiver_log_coverage_unproven`입니다. 파일이 없으면
    `receiver_log_unavailable`,
    형식이 틀리거나 `evidence_dir`가 실제 폴더가 아니면 `receiver_log_unreadable`, 구간 밖·다른
    사례의 요청 기록이 있으면
    `receiver_evidence_inconclusive`입니다(모두 blocked).
  - 증거 전용 NET-05: 실행기가 행동하지 않으므로 관리자가 관리자 기록 구간 안에 같은 요청을
    보냅니다. 예: `curl -fsS "https://<수신 호스트>/v1/control/NET-05?run_id=<리포트 run_id>"`.
    이 대조 기록도 그 구간·run_id로 수신 기록에 있어야 합니다.
  - 기록 파일이 가득 차면(1 MiB) 새 파일로 바꿉니다.
- host probe: `host-probe --run-id <host_batch>` 출력(`host-probe-v1`)을 `evidence_dir`에 복사합니다.
- REC-01 후속 실행: 교체 뒤 새로 실행한 `run`의 리포트를 원래 이름
  (`isolation-report-<run_id>.json`) 그대로 `evidence_dir`에 복사하고, 그 run_id를
  `followup_run_id`에 적습니다. 실행기는 리포트가 있는지, run_id가 같은지, 정규 명세로
  실행됐는지, 교체 기록 구간이 끝난 뒤(`ended_at` 이후)와 원래 시험 이후에 시작했는지,
  COL-01·INT-01·HOST-01·HOST-02·HOST-03의 모든 변형이 통과했는지 확인합니다. 하나라도
  아니면 blocked입니다.
- REC-01 순서: REC-01은 증거 전용이라 실행기가 아무것도 하지 않고, 판정은 나중에
  `report --config`로 다시 합니다.
  1. 교체 전에 REC-01을 포함한 `run`을 실행합니다. 리포트의 REC-01 `details.run_id`와
     `details.started_at`을 적어 둡니다.
  2. 새 EC2로 교체하고 인증정보를 바꿉니다. 이 작업 구간을 REC-01 관리자 기록의
     `started_at`~`ended_at`으로 적습니다(시작은 1번의 `started_at` 이후).
  3. 교체 구간이 끝난 뒤 COL-01·INT-01·HOST-01·HOST-02·HOST-03을 다시 `run`합니다. 이
     후속 리포트를 2절 이름 그대로 `evidence_dir`에 복사하고 그 run_id를 `followup_run_id`에
     적습니다. 교체 구간 안에 시작한 후속 실행은 `followup_not_later`(blocked)입니다.
  4. 1번 리포트를 `report --input <1번 리포트> --config config.local.json --output <새 폴더>`로
     다시 판정합니다.
- LIM-06: 실행기는 상한+1 결과를 직접 판정합니다. 모두 수집되면 `concurrency_limit_ok=false`
  (failed). 과부하 응답이 있고 수집 건수가 상한 이하이면 true입니다. 과부하 응답은 HTTP 429
  (`collector_rate_limited`)와 본문 코드 `collector_busy`, `concurrency_limit_exceeded`,
  `queue_full`입니다. 일반 5xx(`collector_unavailable`)는 한도 적용 증거가 아닙니다. 그 밖의
  결과(시간 초과, 5xx, 다른 오류)로 판정할 수 없으면 관리자 `concurrency_limit_ok`와 무관하게
  `limit_observation_inconclusive`(blocked)입니다.

### 8-3. 관리자 기록이 필요한 사실

생산자 설명: "수집기 작업 로그"는 수집기 서버의 해당 run_id 작업 기록, "격리 컨테이너
브라우저 관찰"은 같은 작업의 브라우저 이벤트 기록, "대상 호스트·컨테이너 관리자"는 SSH로
대상 경계에서 직접 확인한 값, "담당자"는 사람이 직접 확인한 기록(`evidence_source: "observed"`)입니다.

| 사실 | 사례 (변형) | 생산자 | 확인 방법 | 값 |
| --- | --- | --- | --- | --- |
| `actual_byte_limit_ok` | LIM-03 (large length-small length-large gzip) | 수집기 작업 로그 | 실제로 읽은 응답 바이트가 8 MiB 상한 안에서 끊겼는지(Content-Length 주장과 무관) | bool |
| `callback_failure_observed` | INT-04 (callback-failure) | 담당자 | 카카오 콜백 전송 실패를 BE 로그에서 확인 | bool |
| `children_remaining` | LIM-01 (delay-15s), LIM-02 (slow-stream), LIM-03 (large length-small length-large gzip), LIM-05 (dom-growth cpu-bursts), LIM-06 (concurrency), HOST-03 (process-cleanup) | 대상 호스트·컨테이너 관리자 | 작업 종료 후 수집 작업의 자식 프로세스 수(`ps --ppid`) | 0 이상 정수 |
| `collector_deadline_ok` | INT-03 (pipeline) | 수집기 작업 로그 | BE→수집 요청이 12초 마감 안에 끝났는지 | bool |
| `concurrency_limit_known` | LIM-06 (concurrency) | 대상 호스트·컨테이너 관리자 | 수집기 운영 동시 처리 상한 설정을 확인했는지(`--collector-limit`과 같은 값) | bool |
| `context_cleanup_ok` | HOST-03 (context-cleanup) | 대상 호스트·컨테이너 관리자 | 작업 후 브라우저 컨텍스트·프로필 디렉터리가 지워졌는지 | bool |
| `context_fresh` | SES-01 (read) | 격리 컨테이너 브라우저 관찰(수집기 작업 기록) | SES-01 read 시험이 새 컨텍스트에서 시작했는지 | bool |
| `credentials_rotated` | REC-01 (replacement) | 대상 호스트·컨테이너 관리자 | 교체된 새 EC2에 새 인증정보가 발급됐는지 | bool |
| `deadline_met` | LIM-01 (delay-15s), LIM-02 (slow-stream), LIM-05 (dom-growth cpu-bursts) | 수집기 작업 로그 | 원격 작업이 마감(12초)+여유(1초) 안에 종료됐는지 | bool |
| `digest_ok` | HOST-03 (digest), REC-01 (replacement) | 대상 호스트·컨테이너 관리자 | 실행 중 이미지 digest가 승인값과 같은지(HOST-03 digest는 observed/approved_digest* 함께) | bool |
| `disabled_readonly_ok` | COL-02 (default) | 격리 컨테이너 브라우저 관찰(수집기 작업 기록) | disabled·readonly 입력이 수집 결과에 그 상태로 남았는지 | bool |
| `download_attempt_observed` | DL-02 (attachment) | 격리 컨테이너 브라우저 관찰(수집기 작업 기록) | attachment 응답에 다운로드 시도가 실제로 있었는지 | bool |
| `download_clicked` | ANA-04 (default), DL-01 (default) | 격리 컨테이너 브라우저 관찰(수집기 작업 기록) | 다운로드 링크를 클릭했는지(기대값 false) | bool |
| `download_link_recorded` | DL-01 (default) | 격리 컨테이너 브라우저 관찰(수집기 작업 기록) | sample.apk 링크가 결과에 기록됐는지 | bool |
| `download_remaining_bytes` | DL-02 (attachment) | 대상 호스트·컨테이너 관리자 | 프로세스 종료 뒤 남은 다운로드 바이트 | 0 이상 정수 |
| `download_temporary_bytes` | DL-02 (attachment) | 대상 호스트·컨테이너 관리자 | 작업 중 임시 영역에 저장된 다운로드 바이트 | 0 이상 정수 |
| `false_success_reported` | INT-04 (callback-failure) | 담당자 | 콜백 실패에도 사용자에게 성공으로 보였는지(기대값 false) | bool |
| `file_executed` | ANA-04 (default), DL-01 (default), DL-02 (attachment) | 대상 호스트·컨테이너 관리자 | 내려받은 파일이 실행됐는지(기대값 false) | bool |
| `firewall_drop_observed` | NET-05 (tcp dns ipv6), INT-02 (denied-source) | 대상 호스트·컨테이너 관리자 | 격리 컨테이너 경계의 방화벽 drop 카운터·로그 증가 | bool |
| `form_associations_ok` | COL-02 (default) | 격리 컨테이너 브라우저 관찰(수집기 작업 기록) | label/aria/fieldset/폼 밖 입력의 연결이 결과에 보존됐는지 | bool |
| `form_destination_ok` | NET-02 (action formaction) | 격리 컨테이너 브라우저 관찰(수집기 작업 기록) | action/formaction 목적지가 기록만 되고 이동하지 않았는지 | bool |
| `forms_submitted` | COL-03 (default), NET-02 (action formaction) | 격리 컨테이너 브라우저 관찰(수집기 작업 기록) | 어떤 폼이라도 제출됐는지(기대값 false) | bool |
| `http_page_state` | HTTP-01 (403 404 500 block-page captcha-page) | 수집기 작업 로그 | HTTP-01 변형의 페이지 상태 분류 | 403\|404\|500\|block_page\|captcha_page |
| `initial_url_rejected` | NET-07 (initial-private scheme userinfo normalized-host) | 수집기 작업 로그 | 최초 입력 URL이 방문 전에 거부됐는지(실패 코드와 별도로 기록) | bool |
| `inspected_regions` | COL-04 (delayed), COL-05 (iframe open-shadow) | 격리 컨테이너 브라우저 관찰(수집기 작업 기록) | 실제 검사한 영역 이름 목록 | 영역 이름 목록 |
| `limit_exceeded_confirmed` | LIM-03 (large length-small length-large gzip) | 수집기 작업 로그 | 표본이 그 run_id 작업에 수집기 응답 바이트 상한보다 많은 바이트를 실제로 제공했고 수집기가 상한 초과로 읽기를 멈췄다고 기록했는지(Content-Length 주장과 무관) | bool |
| `kakao_received` | INT-03 (kakao-receipt) | 담당자 | 실제 카카오 수신을 담당자가 확인(evidence_source=observed) | bool |
| `navigation_chain_ok` | NAV-01 (js meta), NAV-02 (hops-1 hops-5) | 수집기 작업 로그 | 이동 체인의 각 홉이 허용 표본 서버 안에 있었는지 | bool |
| `navigation_kind` | NAV-01 (js meta) | 수집기 작업 로그 | NAV-01 이동 종류 | js\|meta |
| `old_credentials_rejected` | REC-01 (replacement) | 대상 호스트·컨테이너 관리자 | 이전 인증정보가 거부되는지 시험한 결과 | bool |
| `payment_amount_krw` | ANA-05 (default) | 격리 컨테이너 브라우저 관찰(수집기 작업 기록) | 페이지에서 관찰한 결제 요청 금액 | 숫자 |
| `payment_request_observed` | ANA-05 (default) | 격리 컨테이너 브라우저 관찰(수집기 작업 기록) | 결제 요청 문구·폼을 관찰했는지 | bool |
| `positive_control_ok` | NET-05 (tcp dns ipv6), INT-02 (allowed-source denied-source), INT-03 (pipeline kakao-receipt), INT-04 (callback-failure), REC-01 (replacement) | 대상 호스트·컨테이너 관리자(INT-03·INT-04는 담당자) | 실행기가 COL-01 대조를 하지 않는 사례에서 같은 경계·구간의 정상 경로 대조가 성공했는지(INT-03·INT-04는 같은 구간의 정상 BE 처리·콜백) | bool |
| `probe_in_container` | NET-05 (tcp dns ipv6) | 대상 호스트·컨테이너 관리자 | 직접 연결 시도를 격리 컨테이너 안에서 했는지 | bool |
| `queue_limit_ok` | LIM-06 (concurrency) | 수집기 작업 로그 | 앱 대기열 없이 초과 요청이 즉시 거절됐는지 | bool |
| `recovery_ok` | LIM-01 (delay-15s), LIM-02 (slow-stream), LIM-03 (large length-small length-large gzip), LIM-05 (dom-growth cpu-bursts), LIM-06 (concurrency), REC-01 (replacement) | 수집기 작업 로그 | 제한 시험 직후 다음 정상 요청이 성공했는지(실행기 COL-01 재요청과 별도 기록) | bool |
| `redirect_limit_ok` | NAV-03 (hops-6 loop) | 수집기 작업 로그 | 6번째 홉·반복 경로에서 이동이 멈췄는지 | bool |
| `relative_targets_ok` | COL-03 (default) | 격리 컨테이너 브라우저 관찰(수집기 작업 기록) | 상대 링크·base·action·formaction이 올바른 절대 주소로 기록됐는지 | bool |
| `remote_job_terminated` | DL-02 (attachment), LIM-01 (delay-15s), LIM-02 (slow-stream), LIM-03 (large length-small length-large gzip), LIM-05 (dom-growth cpu-bursts), LIM-06 (concurrency), HOST-03 (process-cleanup) | 대상 호스트·컨테이너 관리자 | 실행기 시간 초과와 별도로 원격 수집 작업이 실제로 끝났는지 | bool |
| `replacement_ok` | REC-01 (replacement) | 대상 호스트·컨테이너 관리자 | 새 EC2 생성으로 교체했는지(replacement_kind=new_instance) | bool |
| `request_blocked` | NAV-04 (http js), NET-01 (img script iframe fetch), NET-03 (loopback private link-local main-public isolation-public), NET-04 (shared-ip-host same-host-path), NET-05 (tcp dns ipv6), NET-06 (websocket worker service-worker), NET-07 (initial-private scheme userinfo normalized-host) | 격리 컨테이너 브라우저 관찰(수집기 작업 기록) | 금지 대상 요청이 격리 정책에 의해 차단됐는지(차단 기록) | bool |
| `resource_limits_ok` | LIM-05 (dom-growth cpu-bursts) | 대상 호스트·컨테이너 관리자 | LIM-05 동안 CPU·메모리·PIDs가 기준 프로필 안이었는지 | bool |
| `resource_profile_recorded` | LIM-05 (dom-growth cpu-bursts) | 대상 호스트·컨테이너 관리자 | LIM-05 시점의 자원 프로필을 기록했는지(host-probe 값 사용 가능) | bool |
| `safe_claimed` | HTTP-01 (403 404 500 block-page captcha-page), HTTP-02 (wrong-mime invalid-utf8 truncated) | 수집기 작업 로그 | 오류·차단 페이지를 안전하다고 판정했는지(기대값 false) | bool |
| `same_host_verified` | NET-04 (same-host-path) | 대상 호스트·컨테이너 관리자 | 같은 호스트의 다른 경로 대상임을 확인했는지 | bool |
| `sandbox_ok` | HOST-01 (sandbox) | 대상 호스트·컨테이너 관리자 | Chromium 샌드박스 활성 관찰(evidence_source=observed) | bool |
| `service_worker_registered` | NET-06 (service-worker) | 격리 컨테이너 브라우저 관찰(수집기 작업 기록) | service worker가 등록됐는지(기대값 false) | bool |
| `session_markers_present` | SES-01 (read) | 격리 컨테이너 브라우저 관찰(수집기 작업 기록) | read 시 남아 있던 저장소 표식 | cookie\|local_storage\|indexed_db\|session_storage 목록 |
| `session_stores_seeded` | SES-01 (seed) | 격리 컨테이너 브라우저 관찰(수집기 작업 기록) | seed 시 표식을 쓴 저장소 | cookie\|local_storage\|indexed_db\|session_storage 목록 |
| `shared_ip_verified` | NET-04 (shared-ip-host) | 대상 호스트·컨테이너 관리자 | 같은 IP의 다른 호스트 대상임을 확인했는지 | bool |
| `source_allowed` | INT-02 (allowed-source) | 대상 호스트·컨테이너 관리자 | 허용 출발지 요청이 수락됐는지 | bool |
| `source_denied` | INT-02 (denied-source) | 대상 호스트·컨테이너 관리자 | 비허용 출발지 요청이 거부됐는지 | bool |
| `stream_bounds_ok` | LIM-02 (slow-stream) | 수집기 작업 로그 | 느린 스트림이 20초 수명 안에서 끊겼는지 | bool |
| `unknown_regions` | COL-05 (closed-shadow) | 격리 컨테이너 브라우저 관찰(수집기 작업 기록) | 검사하지 못한 영역 이름 목록(closed shadow 등) | 영역 이름 목록 |
