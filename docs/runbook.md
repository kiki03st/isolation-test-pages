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

## 3. 허용 목록 전환은 별도 작업

온라인 프로필로 전환하려면 격리 환경의 네트워크 허용 목록을 바꿔야 합니다. 이 도구는 그
변경을 수행하지 않습니다. 관리자가 별도 작업으로 수행하고 기록합니다.

- 방화벽을 전면 개방하지 않습니다. 임의 DNS 개방으로 복구하지 않습니다.
- Pages 주소는 정확한 HTTPS 호스트·포트·경로로 허용하고 `*.github.io` 전체는 허용하지 않습니다.
- IP를 고정했다면 DNS·인증서·목적지 일치와 변경 감지를 확인하고, IP가 바뀌면 실패로 두고 재검토합니다.

## 4. 양성 대조와 수신 증거

차단 사례를 통과로 보려면 같은 실행 구간에서 먼저 다음이 확인되어야 합니다.

1. 정상 대상(Pages 또는 COL-01)이 실제로 수집된다(양성 대조).
2. 수신 호스트의 기록 장치가 동작한다(관리자가 보낸 대조 요청이 기록됨. 이 요청이 격리
   컨테이너의 허용 정책을 넓히지 않아야 함).
3. 금지 대상에는 같은 구간에 수신 기록이 없다.

타임아웃, 닫힌 포트, 콘솔·CORS 오류만으로는 차단 통과가 아닙니다. 증거는 run id와 시각으로
사례에 연결합니다.

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

## 6. 결과 읽기

- 종료 코드 0: 선택 범위 전체 통과, 1: 실패 있음, 2: 실패는 없으나 미완료.
- 일부 그룹만 실행했다면 0이어도 전체 검증 완료가 아닙니다. 전체 완료는 43개 사례와 모든
  변형이 `passed`일 때뿐입니다.
- 리포트는 `results/`에만 저장됩니다. 게시하지 않습니다.

## 7. 공개 전 점검 (게시 담당자가 수행)

```
isolation-build-pages --manifest tools/isolation-tests/cases.json --output test-pages --commit <sha>
python -m isolation_tests.publish_guard artifact test-pages
python -m isolation_tests.publish_guard history
python -m isolation_tests.publish_guard repository --owner <login> --repo isolation-test-pages
```

- 모든 점검이 통과한 뒤에만 원격 저장소를 만들고 push합니다. 게시 주소는 실제 게시가 끝난 뒤
  README에 적습니다.
- 저장소 소유자는 개인 User 계정이어야 합니다(조직 불가). 원격이 이미 있으면 읽기 전용으로
  소유자·공개 여부·Pages 상태를 확인하고, 기존 내용을 교체하거나 force-push하지 않습니다.
- Pages 워크플로는 저장소 변수 `PERSONAL_OWNER`가 저장소 소유자와 같을 때만 build를 실행합니다.
- 커밋은 GitHub noreply 이메일로만 만듭니다. history 가드가 모든 작성자·커밋자 값을 확인하되
  값 자체는 출력하지 않습니다.
