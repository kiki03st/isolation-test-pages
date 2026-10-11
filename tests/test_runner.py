"""Run order, routing, recovery, interruption and the administrator CLI.

No real network: collector, AI and backend adapters are replaced by in-process
fakes (or an httpx MockTransport), and evidence is written to a temp directory.
"""

import asyncio
import json
from dataclasses import replace
from pathlib import Path

import pytest

from isolation_tests.model import CollectedPage, Evidence, Outcome, RuntimeConfig


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tools" / "isolation-tests" / "cases.json"


def _around_now(seconds=3600):
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    return ((now - timedelta(seconds=seconds)).strftime(fmt),
            (now + timedelta(seconds=seconds)).strftime(fmt))


@pytest.fixture(scope="module")
def cases():
    from isolation_tests.manifest import load_cases

    return {case.id: case for case in load_cases(MANIFEST)}


@pytest.fixture
def limit_case(cases):
    return cases["LIM-01"]


@pytest.fixture
def recovered_facts():
    return Evidence("run-test", "LIM-01", "2026-10-10T00:00:00Z", "2026-10-10T00:00:01Z", {
        "variant": "delay-15s", "positive_control_ok": True, "remote_job_terminated": True,
        "children_remaining": 0, "recovery_ok": True,
    })


ALL_CAPS = frozenset({
    "collector", "rendering", "fixture_server", "receiver_logs", "controlled_targets", "ai",
    "host_evidence", "collector_limit_profile", "backend", "authentication", "tls",
    "iframe_collection", "open_shadow_collection",
})


@pytest.fixture
def evidence_dir(tmp_path):
    path = tmp_path / "evidence"
    path.mkdir()
    return path


@pytest.fixture
def config(evidence_dir, monkeypatch):
    from isolation_tests.config import DEFAULT_LIMITS

    monkeypatch.setenv("TEST_ONLY_TOKEN", "synthetic-runner-token")
    return RuntimeConfig(
        bases={"pages": "https://pages.example.invalid/project/",
               "http_fixture": "https://fixture.example.invalid/",
               "forbidden_receiver": "https://receiver.example.invalid/"},
        collector_url="https://collector.example.invalid/collect",
        token_env="TEST_ONLY_TOKEN", ca_file=None, limits=dict(DEFAULT_LIMITS),
        capabilities=ALL_CAPS, evidence_dir=evidence_dir, backend_contract=None,
    )


def _page(url, html="<title>수집 기준</title>배송 상태: 배송 중 📦", *, title="수집 기준",
          failures=(), elapsed_ms=100, status=200):
    return CollectedPage(url, url, (), status, "text/html", html, title, elapsed_ms, tuple(failures))


class FakeCollector:
    """Records requested URLs; answers COL-01 normally and other URLs via ``answers``."""

    def __init__(self, answers=None):
        self.calls = []
        self.answers = answers or {}

    async def __call__(self, config, url, token_mode="valid"):
        self.calls.append((url, token_mode))
        for marker, answer in self.answers.items():
            if marker in url:
                result = answer(url) if callable(answer) else answer
                if isinstance(result, BaseException):
                    raise result
                return result
        if "col-01" in url:
            return _page(url)
        from isolation_tests.adapters.collector import CollectionError
        raise CollectionError("collector_unavailable")


def _from_now(seconds=3600):
    """A window that starts one whole second after now (UTC, second precision)."""
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc).replace(microsecond=0)
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    return ((now + timedelta(seconds=1)).strftime(fmt), (now + timedelta(seconds=seconds)).strftime(fmt))


def _write_evidence(directory, run_id, case_id, variant, facts, window=None):
    window = window or _from_now()
    record = {"run_id": run_id, "case_id": case_id, "started_at": window[0], "ended_at": window[1],
              "facts": {"variant": variant, **facts}, "references": []}
    with (directory / "admin.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record) + "\n")


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def receiver_controls(monkeypatch):
    """No test reaches a real receiver: control sends are recorded and never logged."""
    from isolation_tests import runner

    sent = []

    async def unsent(config, case_id, variant, run_id):
        sent.append((case_id, variant, run_id))
        return "receiver_control_failed"

    monkeypatch.setattr(runner, "SEND_CONTROL", unsent, raising=False)
    return sent


def _control_event(directory, case_id, run_id, at, name="receiver-forbidden.jsonl"):
    """A control event as the receiver logs it for GET /v1/control/<case>."""
    from isolation_tests.receiver import write_receiver_event

    write_receiver_event(directory / name, case_id=case_id, run_id=run_id, method="GET",
                         fixed_path=f"/v1/control/{case_id}", bytes_sent=2, at=at)


def _live_receiver(monkeypatch, directory):
    """A reachable receiver: every control the runner sends is logged at once."""
    from isolation_tests import runner

    sent = []

    async def live(config, case_id, variant, run_id):
        sent.append((case_id, variant, run_id))
        _control_event(directory, case_id, run_id, _utc())
        return "sent"

    monkeypatch.setattr(runner, "SEND_CONTROL", live, raising=False)
    return sent


# --- evaluate: recovery -----------------------------------------------------------

def test_recovery_failure_prevents_limit_pass(limit_case, recovered_facts):
    from dataclasses import replace
    from isolation_tests.evaluate import evaluate
    recovered_facts = replace(recovered_facts,
        facts={**recovered_facts.facts, 'remote_job_terminated': True, 'recovery_ok': False})
    assert evaluate(limit_case, 'delay-15s', None, recovered_facts,
                    frozenset({'collector', 'host_evidence'})).status == 'failed'


def test_merge_recovery_never_lets_a_limit_pass_without_a_passing_follow_up():
    from isolation_tests.evaluate import merge_recovery

    base = Outcome("LIM-01", "delay-15s", "passed", "observed_expectations_met", {})
    assert merge_recovery(base, None).status == "blocked"
    assert merge_recovery(base, None).reason == "recovery_not_run"
    failed = merge_recovery(base, Outcome("COL-01", "default", "failed", "required_text_missing"))
    assert (failed.status, failed.reason) == ("failed", "recovery_failed")
    blocked = merge_recovery(base, Outcome("COL-01", "default", "blocked", "collector_unavailable"))
    assert (blocked.status, blocked.reason) == ("blocked", "recovery_blocked")
    ok = merge_recovery(base, Outcome("COL-01", "default", "passed", "observed_expectations_met"))
    assert ok.status == "passed" and ok.details["recovery"]["status"] == "passed"
    worse = Outcome("LIM-01", "delay-15s", "failed", "deadline_exceeded", {})
    assert merge_recovery(worse, ok and Outcome("COL-01", "default", "passed", "x")).status == "failed"


# --- run_case routing ----------------------------------------------------------------

def test_collection_case_passes_from_actual_collected_page(cases, config, monkeypatch):
    from isolation_tests import runner

    fake = FakeCollector()
    monkeypatch.setattr(runner, "COLLECT", fake)
    outcome = _run(runner.run_case(cases["COL-01"], "default", config, "run-col01"))
    assert outcome.status == "passed", outcome
    assert fake.calls == [("https://pages.example.invalid/project/v1/cases/col-01/index.html?run_id=run-col01", "valid")]
    assert outcome.details["run_id"] == "run-col01"
    assert "collect" in outcome.details["stages_ms"]
    assert outcome.details["started_at"].endswith("Z")


def test_expected_analysis_is_never_an_observation_input(cases, config, monkeypatch):
    from isolation_tests import runner

    # The page lacks the required text: expectations must not fill it in.
    fake = FakeCollector({"col-01": lambda url: _page(url, "<p>다른 내용</p>")})
    monkeypatch.setattr(runner, "COLLECT", fake)
    outcome = _run(runner.run_case(cases["COL-01"], "default", config, "run-col01"))
    assert outcome.status == "failed"


@pytest.mark.parametrize("code", ["stub_not_collected", "token_missing", "collector_not_configured"])
def test_stub_and_preparation_codes_are_blocked(cases, config, monkeypatch, code):
    from isolation_tests import runner
    from isolation_tests.adapters.collector import CollectionError

    monkeypatch.setattr(runner, "COLLECT", FakeCollector({"col-01": CollectionError(code)}))
    outcome = _run(runner.run_case(cases["COL-01"], "default", config, "run-x"))
    assert (outcome.status, outcome.reason) == ("blocked", code)


def test_missing_capability_is_blocked_without_any_request(cases, config, monkeypatch):
    from isolation_tests import runner

    fake = FakeCollector()
    monkeypatch.setattr(runner, "COLLECT", fake)
    outcome = _run(runner.run_case(cases["COL-01"], "default",
                                   replace(config, capabilities=frozenset()), "run-x"))
    assert (outcome.status, outcome.reason) == ("blocked", "missing_capability")
    assert fake.calls == []


def test_unconfigured_target_is_blocked_without_any_request(cases, config, monkeypatch):
    from isolation_tests import runner

    fake = FakeCollector()
    monkeypatch.setattr(runner, "COLLECT", fake)
    outcome = _run(runner.run_case(cases["NAV-02"], "hops-1", replace(config, bases={}), "run-x"))
    assert (outcome.status, outcome.reason) == ("blocked", "target_not_configured")
    assert fake.calls == []


def test_network_block_needs_runner_positive_control_and_admin_evidence(cases, config, evidence_dir, monkeypatch):
    from isolation_tests import runner

    fake = FakeCollector({"NET-01": lambda url: _page(url, "<p>net</p>", title=None)})
    monkeypatch.setattr(runner, "COLLECT", fake)
    blocked = _run(runner.run_case(cases["NET-01"], "img", config, "run-net-a"))
    assert blocked.status == "blocked"  # receiver evidence absent
    assert blocked.details["positive_control"]["ok"] is True
    assert any("col-01" in url for url, _ in fake.calls)

    _write_evidence(evidence_dir, "run-net-b", "NET-01", "img", {
        "receiver_control_ok": True, "request_blocked": True, "receiver_observed": False})
    no_log = _run(runner.run_case(cases["NET-01"], "img", config, "run-net-b"))
    assert (no_log.status, no_log.reason) == ("blocked", "receiver_log_unavailable")
    _receiver_log(evidence_dir)
    # An empty log proves nothing: the runner's control never reached it.
    empty = _run(runner.run_case(cases["NET-01"], "img", config, "run-net-b"))
    assert (empty.status, empty.reason) == ("blocked", "receiver_log_coverage_unproven")
    _live_receiver(monkeypatch, evidence_dir)
    passed = _run(runner.run_case(cases["NET-01"], "img", config, "run-net-b"))
    assert passed.status == "passed", passed
    assert passed.details["observed_facts"]["receiver_observed"] is False
    assert passed.details["observed_facts"]["receiver_control_ok"] is True


def test_failed_positive_control_blocks_a_network_pass(cases, config, evidence_dir, monkeypatch):
    from isolation_tests import runner
    from isolation_tests.adapters.collector import CollectionError

    fake = FakeCollector({"col-01": CollectionError("collector_unreachable"),
                          "NET-01": lambda url: _page(url, "<p>net</p>", title=None)})
    monkeypatch.setattr(runner, "COLLECT", fake)
    _write_evidence(evidence_dir, "run-net-c", "NET-01", "img", {
        "receiver_control_ok": True, "request_blocked": True, "receiver_observed": False})
    outcome = _run(runner.run_case(cases["NET-01"], "img", config, "run-net-c"))
    assert outcome.status == "blocked"
    assert outcome.details["positive_control"]["ok"] is False


def test_admin_evidence_from_another_time_window_is_blocked(cases, config, evidence_dir, monkeypatch):
    from isolation_tests import runner

    monkeypatch.setattr(runner, "COLLECT", FakeCollector({"NET-01": lambda url: _page(url, "<p>net</p>", title=None)}))
    _write_evidence(evidence_dir, "run-net-old", "NET-01", "img", {
        "receiver_control_ok": True, "request_blocked": True, "receiver_observed": False},
        window=("2020-01-01T00:00:00Z", "2020-01-01T00:00:30Z"))
    outcome = _run(runner.run_case(cases["NET-01"], "img", config, "run-net-old"))
    assert (outcome.status, outcome.reason) == ("blocked", "evidence_window_mismatch")


def test_admin_evidence_contradicting_runner_observation_is_blocked(cases, config, evidence_dir, monkeypatch):
    from isolation_tests import runner
    from isolation_tests.adapters.collector import CollectionError

    fake = FakeCollector({"col-01": CollectionError("collector_unreachable"),
                          "NET-01": lambda url: _page(url, "<p>net</p>", title=None)})
    monkeypatch.setattr(runner, "COLLECT", fake)
    _write_evidence(evidence_dir, "run-net-d", "NET-01", "img", {
        "positive_control_ok": True, "receiver_control_ok": True, "request_blocked": True,
        "receiver_observed": False})
    _live_receiver(monkeypatch, evidence_dir)
    outcome = _run(runner.run_case(cases["NET-01"], "img", config, "run-net-d"))
    assert (outcome.status, outcome.reason) == ("blocked", "evidence_conflict")


def _limit_page(url):
    return _page(url, "", title=None, failures=("timeout",), elapsed_ms=12500, status=None)


def _limit_admin(evidence_dir, run_id):
    _write_evidence(evidence_dir, run_id, "LIM-01", "delay-15s", {
        "remote_job_terminated": True, "children_remaining": 0, "recovery_ok": True,
        "deadline_met": True})


def test_limit_trial_runs_recovery_and_passes_only_with_remote_evidence(cases, config, evidence_dir, monkeypatch):
    from isolation_tests import runner

    fake = FakeCollector({"LIM-01": _limit_page})
    monkeypatch.setattr(runner, "COLLECT", fake)
    _limit_admin(evidence_dir, "run-lim-a")
    outcome = _run(runner.run_case(cases["LIM-01"], "delay-15s", config, "run-lim-a"))
    assert outcome.status == "passed", outcome
    urls = [url for url, _ in fake.calls]
    # positive control, the limit trial, then the recovery request
    assert "LIM-01" in urls[1] and "col-01" in urls[-1]
    assert outcome.details["recovery"]["status"] == "passed"


def test_failed_next_normal_request_prevents_limit_compliance(cases, config, evidence_dir, monkeypatch):
    from isolation_tests import runner

    state = {"n": 0}

    def col01(url):
        state["n"] += 1
        # The control succeeds; the follow-up normal request after the limit fails.
        return _page(url) if state["n"] == 1 else _page(url, "<p>broken</p>")

    monkeypatch.setattr(runner, "COLLECT", FakeCollector({"LIM-01": _limit_page, "col-01": col01}))
    _limit_admin(evidence_dir, "run-lim-b")
    outcome = _run(runner.run_case(cases["LIM-01"], "delay-15s", config, "run-lim-b"))
    assert (outcome.status, outcome.reason) == ("failed", "recovery_failed")


def test_runner_only_timeout_is_not_limit_compliance(cases, config, evidence_dir, monkeypatch):
    from isolation_tests import runner
    from isolation_tests.adapters.collector import CollectionError

    monkeypatch.setattr(runner, "COLLECT", FakeCollector({"LIM-01": CollectionError("runner_timeout")}))
    outcome = _run(runner.run_case(cases["LIM-01"], "delay-15s", config, "run-lim-c"))
    assert outcome.status == "blocked"
    assert outcome.details["collection_error"] == "runner_timeout"


def test_concurrency_trial_sends_collector_limit_plus_one_concurrently(cases, config, monkeypatch):
    from isolation_tests import runner

    active = {"now": 0, "peak": 0}

    async def slow(url):
        active["now"] += 1
        active["peak"] = max(active["peak"], active["now"])
        await asyncio.sleep(0.05)
        active["now"] -= 1
        return _page(url, "", title=None, failures=("collector_busy",))

    class Concurrent(FakeCollector):
        async def __call__(self, config, url, token_mode="valid"):
            if "LIM-02" in url:
                self.calls.append((url, token_mode))
                return await slow(url)
            return await super().__call__(config, url, token_mode)

    fake = Concurrent()
    monkeypatch.setattr(runner, "COLLECT", fake)
    limited = replace(config, limits={**config.limits, "collector_concurrency": 3})
    outcome = _run(runner.run_case(cases["LIM-06"], "concurrency", limited, "run-lim6"))
    assert active["peak"] == 4
    assert sum("LIM-02" in url for url, _ in fake.calls) == 4
    assert outcome.details["observed_facts"]["limit_plus_one_sent"] is True
    assert outcome.details["observed_facts"]["concurrency_limit"] == 3
    assert outcome.status == "blocked"  # admin termination/limit evidence still missing


@pytest.mark.parametrize("limit", [None, 8])
def test_concurrency_trial_without_known_limit_or_over_eight_is_not_sent(cases, config, monkeypatch, limit):
    from isolation_tests import runner

    fake = FakeCollector()
    monkeypatch.setattr(runner, "COLLECT", fake)
    limits = dict(config.limits)
    if limit is not None:
        limits["collector_concurrency"] = limit
    outcome = _run(runner.run_case(cases["LIM-06"], "concurrency", replace(config, limits=limits), "run-x"))
    assert outcome.status == "blocked"
    assert outcome.reason in {"collector_limit_unknown", "concurrency_trial_exceeds_cap"}
    assert not any("LIM-02" in url for url, _ in fake.calls)


def test_analysis_case_collects_then_merges_ai_result(cases, config, monkeypatch):
    from isolation_tests import runner

    page_html = "<p>배송 상태: 배송 중</p>"
    monkeypatch.setattr(runner, "COLLECT", FakeCollector({"ana-01": lambda url: _page(url, page_html, title=None)}))
    seen = []

    async def analyze(case, variant, page, **_):
        seen.append(page.html)
        return Outcome(case.id, variant, "failed", "analysis_mismatch", {"facts": {"analysis": True}})

    monkeypatch.setattr(runner, "ANALYZE", analyze)
    outcome = _run(runner.run_case(cases["ANA-01"], "default", config, "run-ana"))
    assert seen == [page_html]
    assert (outcome.status, outcome.reason) == ("failed", "analysis_mismatch")


def test_absent_ai_blocks_analysis(cases, config, monkeypatch):
    from isolation_tests import runner

    monkeypatch.setattr(runner, "COLLECT", FakeCollector({"ana-01": lambda url: _page(url, "<p>배송 상태: 배송 중</p>")}))

    async def analyze(case, variant, page, **_):
        return Outcome(case.id, variant, "blocked", "ai_unavailable", {})

    monkeypatch.setattr(runner, "ANALYZE", analyze)
    outcome = _run(runner.run_case(cases["ANA-01"], "default", config, "run-ana"))
    assert outcome.status == "blocked"


def test_paired_injection_case_records_paired_verdict_fact(cases, config, monkeypatch):
    from isolation_tests import runner

    html = "<p>인증번호를 입력해 주세요</p>"
    fake = FakeCollector({"ana-07": lambda url: _page(url, html, title=None)})
    monkeypatch.setattr(runner, "COLLECT", fake)

    async def analyze(case, variant, page, **_):
        return Outcome(case.id, variant, "passed", "analysis_expectations_met",
                       {"verdict": {"final_state": "x"}, "accepted_codes": ["c"], "facts": {"analysis": True}})

    monkeypatch.setattr(runner, "ANALYZE", analyze)
    outcome = _run(runner.run_case(cases["ANA-07"], "injection", config, "run-ana7"))
    assert outcome.details["observed_facts"]["paired_verdict_equal"] is True
    assert sorted(url.split("/")[-1].split("?")[0] for url, _ in fake.calls) == ["baseline.html", "injection.html"]
    assert outcome.status == "passed", outcome


@pytest.mark.parametrize("blocked_side", ["both", "pair", "main"])
def test_paired_case_with_unavailable_ai_is_blocked_not_failed(cases, config, monkeypatch, blocked_side):
    from isolation_tests import runner

    html = "<p>인증번호를 입력해 주세요</p>"
    monkeypatch.setattr(runner, "COLLECT", FakeCollector({"ana-07": lambda url: _page(url, html, title=None)}))
    calls = []

    async def analyze(case, variant, page, **_):
        calls.append(variant)
        main = len(calls) == 1
        if blocked_side == "both" or (blocked_side == "pair") != main:
            return Outcome(case.id, variant, "blocked", "ai_unavailable", {})
        return Outcome(case.id, variant, "passed", "analysis_expectations_met",
                       {"verdict": {"final_state": "x"}, "accepted_codes": ["c"], "facts": {"analysis": True}})

    monkeypatch.setattr(runner, "ANALYZE", analyze)
    outcome = _run(runner.run_case(cases["ANA-07"], "baseline", config, "run-ana7b"))
    assert (outcome.status, outcome.reason) == ("blocked", "ai_unavailable"), outcome
    assert "paired_verdict_equal" not in outcome.details["observed_facts"]


def test_run_with_ai_absent_for_ana07_exits_2_not_1(config_file, tmp_path, monkeypatch):
    from isolation_tests import runner

    monkeypatch.setenv("TEST_ONLY_TOKEN", "synthetic-runner-token")
    html = "<p>인증번호를 입력해 주세요</p>"
    monkeypatch.setattr(runner, "COLLECT", FakeCollector({"ana-07": lambda url: _page(url, html, title=None)}))

    async def analyze(case, variant, page, **_):
        return Outcome(case.id, variant, "blocked", "ai_unavailable", {})

    monkeypatch.setattr(runner, "ANALYZE", analyze)
    out = tmp_path / "results"
    code = runner.main(["run", "--config", str(config_file), "--output", str(out), "--case", "ANA-07"])
    items = [i for i in _report(out)["items"] if i["case_id"] == "ANA-07"]
    assert [(i["status"], i["reason"]) for i in items] == [("blocked", "ai_unavailable")] * 2
    assert code == 2


def test_fabricated_evidence_case_uses_no_network(cases, config, monkeypatch):
    from isolation_tests import runner

    fake = FakeCollector()
    monkeypatch.setattr(runner, "COLLECT", fake)

    async def analyze(case, variant, page, **_):
        assert page is None
        return Outcome(case.id, variant, "passed", "analysis_expectations_met",
                       {"facts": {"analysis": True, "fabricated_evidence_rejected": True}})

    monkeypatch.setattr(runner, "ANALYZE", analyze)
    outcome = _run(runner.run_case(cases["ANA-08"], "absent-evidence", config, "run-ana8"))
    assert fake.calls == []
    assert outcome.status == "passed", outcome


@pytest.mark.parametrize("variant,code", [("llm-timeout", "llm_timeout"),
                                          ("collection-failure", "collection_failed")])
def test_fallback_cases_use_fixed_ai_and_ai_reported_failure_codes(cases, config, monkeypatch, variant, code):
    from isolation_tests import runner

    fake = FakeCollector()
    monkeypatch.setattr(runner, "COLLECT", fake)
    calls = []

    async def analyze(case, variant_, page, **kwargs):
        calls.append((case.id, variant_, page is None, "client" in kwargs))
        if case.id == "ANA-01":
            return Outcome(case.id, variant_, "passed", "analysis_expectations_met", {})
        return Outcome(case.id, variant_, "passed", "analysis_expectations_met",
                       {"failure_codes": [code], "facts": {"analysis": True, "fallback_ok": True}})

    monkeypatch.setattr(runner, "ANALYZE", analyze)
    outcome = _run(runner.run_case(cases["INT-04"], variant, config, "run-int4"))
    assert fake.calls == []
    assert calls[0][:2] == ("ANA-01", "default")
    assert calls[1] == ("INT-04", variant, variant == "collection-failure", variant == "llm-timeout")
    assert outcome.status == "passed", outcome


def test_backend_pipeline_combines_backend_and_admin_evidence(cases, config, evidence_dir, monkeypatch):
    from isolation_tests import runner

    async def probe(case, config, **_):
        return Outcome(case.id, "pipeline", "passed", "backend_result_linked",
                       {"run_id": "beabc", "first_response_deadline_ok": True})

    monkeypatch.setattr(runner, "PROBE_BACKEND", probe)
    _write_evidence(evidence_dir, "run-be", "INT-03", "pipeline",
                    {"collector_deadline_ok": True, "positive_control_ok": True})
    outcome = _run(runner.run_case(cases["INT-03"], "pipeline", config, "run-be"))
    assert outcome.status == "passed", outcome

    async def failing(case, config, **_):
        return Outcome(case.id, "pipeline", "failed", "first_response_too_slow", {})

    monkeypatch.setattr(runner, "PROBE_BACKEND", failing)
    _write_evidence(evidence_dir, "run-be2", "INT-03", "pipeline",
                    {"collector_deadline_ok": True, "positive_control_ok": True})
    assert _run(runner.run_case(cases["INT-03"], "pipeline", config, "run-be2")).status == "failed"


BATCH = "r" + "b" * 32


def _iso(offset_seconds=0):
    from datetime import datetime, timedelta, timezone

    return (datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)).isoformat()


def _probe_file(evidence_dir, name="host-probe-container.json", *, run_id=BATCH, collected_at=None,
                boundary="container", **facts):
    base = {"environment_names_ok": True, "platform": "linux", "unsupported_boundary": False,
            "boundary": boundary, "positive_control_ok": True, "uid_ok": True, "caps_ok": True,
            "seccomp_ok": True, "no_new_privileges_ok": True, "mounts_ok": True,
            "write_probe_applicable": True, "readonly_ok": True, "cpu_limit": 1.5,
            "memory_limit_mib": 1536, "pids_limit": 256, "shm_mib": 256, "tmpfs_mib": 256,
            "resource_profile_recorded": True, "resource_limits_ok": True}
    document = {"schema": "host-probe-v1", "facts": {**base, **facts},
                "collected_at": collected_at if collected_at is not None else _iso(2)}
    if run_id is not None:
        document["run_id"] = run_id
    path = evidence_dir / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _host(case_id, variant):
    from isolation_tests.runner import host_run_id

    return host_run_id(BATCH, case_id, variant)


def test_host_run_ids_share_an_unguessable_batch_and_stay_unique():
    from isolation_tests.receiver import RUN_ID
    from isolation_tests.runner import host_run_id, probe_batch_id

    pairs = [("HOST-01", "process"), ("HOST-01", "sandbox"), ("HOST-03", "context-cleanup")]
    ids = {host_run_id(BATCH, c, v) for c, v in pairs}
    assert len(ids) == 3 and all(RUN_ID.fullmatch(i) for i in ids)
    assert {probe_batch_id(c, v, host_run_id(BATCH, c, v)) for c, v in pairs} == {BATCH}
    assert probe_batch_id("HOST-01", "process", "run-host") is None


def test_host_probe_bound_to_the_run_becomes_evidence_with_resource_profile(cases, config, evidence_dir, monkeypatch):
    from isolation_tests import runner

    fake = FakeCollector()
    monkeypatch.setattr(runner, "COLLECT", fake)
    _probe_file(evidence_dir)
    outcome = _run(runner.run_case(cases["HOST-01"], "process", config, _host("HOST-01", "process")))
    assert outcome.status == "passed", outcome
    assert outcome.details["resource_profile"] == {
        "cpu_limit": 1.5, "memory_limit_mib": 1536, "pids_limit": 256, "shm_mib": 256, "tmpfs_mib": 256}
    assert fake.calls == []


@pytest.mark.parametrize("probe", [
    {"run_id": "r" + "c" * 32},                     # another run
    {"run_id": None},                               # legacy probe without a run id
    {"collected_at": "2020-01-01T00:00:00+00:00"},  # before this run issued its id
    {"collected_at": "2026-10-10T00:00:00"},        # naive timestamp
    {"collected_at": "far-future"},                 # long after the run: not this run's state
])
def test_stale_or_foreign_host_probe_never_passes(cases, config, evidence_dir, monkeypatch, probe):
    from isolation_tests import runner

    monkeypatch.setattr(runner, "COLLECT", FakeCollector())
    if probe.get("collected_at") == "far-future":
        probe = {"collected_at": _iso(3 * 86400)}
    _probe_file(evidence_dir, **probe)
    outcome = _run(runner.run_case(cases["HOST-01"], "process", config, _host("HOST-01", "process")))
    assert outcome.status == "blocked"


def test_probe_is_not_used_for_a_run_id_without_the_batch(cases, config, evidence_dir):
    from isolation_tests import runner

    _probe_file(evidence_dir)
    outcome = _run(runner.run_case(cases["HOST-01"], "process", config, "run-host"))
    assert outcome.status == "blocked"


def test_each_host_case_uses_the_probe_of_its_required_boundary(cases, config, evidence_dir):
    from isolation_tests import runner

    _probe_file(evidence_dir, "host-probe-container.json", boundary="container")
    outcome = _run(runner.run_case(cases["HOST-03"], "context-cleanup", config,
                                   _host("HOST-03", "context-cleanup")))
    assert outcome.details["notes"].get("host_probe") is None  # container probe not used for host
    _probe_file(evidence_dir, "host-probe-host.json", boundary="host", write_probe_applicable=False)
    outcome = _run(runner.run_case(cases["HOST-03"], "context-cleanup", config,
                                   _host("HOST-03", "context-cleanup")))
    assert outcome.details["notes"]["host_probe"] == "host-probe-host.json"
    outcome = _run(runner.run_case(cases["HOST-01"], "process", config, _host("HOST-01", "process")))
    assert outcome.details["notes"]["host_probe"] == "host-probe-container.json"
    assert outcome.status == "passed", outcome


def test_windows_or_mismatched_host_probe_is_blocked(cases, config, evidence_dir):
    from isolation_tests import runner

    _probe_file(evidence_dir, boundary_declared="host")
    outcome = _run(runner.run_case(cases["HOST-01"], "process", config, _host("HOST-01", "process")))
    assert (outcome.status, outcome.reason) == ("blocked", "boundary_mismatch")


def test_kakao_receipt_requires_this_runs_be_submission_and_bound_receipt(cases, config, evidence_dir, monkeypatch):
    from isolation_tests import runner

    seen = []

    async def probe(case, config, **kwargs):
        seen.append(kwargs.get("run_id"))
        return Outcome(case.id, "pipeline", "passed", "backend_result_linked",
                       {"run_id": kwargs.get("run_id"), "first_response_deadline_ok": True})

    monkeypatch.setattr(runner, "PROBE_BACKEND", probe)
    caps = replace(config, capabilities=config.capabilities | {"kakao_receipt"})
    receipt = {"kakao_received": True, "evidence_source": "observed", "positive_control_ok": True}
    _write_evidence(evidence_dir, "run-kakao-a", "INT-03", "kakao-receipt", receipt)
    outcome = _run(runner.run_case(cases["INT-03"], "kakao-receipt", caps, "run-kakao-a"))
    assert seen == ["run-kakao-a"]
    assert outcome.status == "passed", outcome

    # A receipt from another time window is not linked to this submission.
    _write_evidence(evidence_dir, "run-kakao-b", "INT-03", "kakao-receipt", receipt,
                    window=("2020-01-01T00:00:00Z", "2020-01-01T00:00:30Z"))
    outcome = _run(runner.run_case(cases["INT-03"], "kakao-receipt", caps, "run-kakao-b"))
    assert (outcome.status, outcome.reason) == ("blocked", "evidence_window_mismatch")

    # Without a successful submission in this run the receipt proves nothing.
    async def failing(case, config, **kwargs):
        return Outcome(case.id, "pipeline", "blocked", "backend_contract_missing", {})

    monkeypatch.setattr(runner, "PROBE_BACKEND", failing)
    _write_evidence(evidence_dir, "run-kakao-c", "INT-03", "kakao-receipt", receipt)
    outcome = _run(runner.run_case(cases["INT-03"], "kakao-receipt", caps, "run-kakao-c"))
    assert outcome.status == "blocked"


CALLBACK_RECORD = {"callback_failure_observed": True, "false_success_reported": False,
                   "positive_control_ok": True}


def test_callback_failure_contract_is_run_bound_submission_lookup_and_admin_record(cases):
    from isolation_tests.evidence import validate_facts

    contract = cases["INT-04"].expected_observations["variants"]["callback-failure"]
    assert "failure_codes" not in contract["assertions"]
    assert contract["assertions"]["required_facts"] == {
        "callback_failure_observed": True, "lookup_fallback_ok": True,
        "false_success_reported": False, "positive_control_ok": True}
    assert {"callback_failure_observed", "lookup_fallback_ok"} <= set(contract["required_evidence"])
    validate_facts({"variant": "callback-failure", "callback_failure_observed": True,
                    "lookup_fallback_ok": True})


def _backend(status, reason, seen=None):
    async def probe(case, config, **kwargs):
        if seen is not None:
            seen.append((case.id, kwargs.get("run_id")))
        return Outcome(case.id, "pipeline", status, reason,
                       {"run_id": kwargs.get("run_id"), "callback_deferred": True})
    return probe


def test_callback_failure_passes_with_linked_lookup_and_bound_admin_record(cases, config, evidence_dir, monkeypatch):
    from isolation_tests import runner

    seen = []
    monkeypatch.setattr(runner, "PROBE_BACKEND", _backend("passed", "backend_result_linked", seen))
    monkeypatch.setattr(runner, "COLLECT", FakeCollector())
    _write_evidence(evidence_dir, "run-cb-a", "INT-04", "callback-failure", CALLBACK_RECORD)
    outcome = _run(runner.run_case(cases["INT-04"], "callback-failure", config, "run-cb-a"))
    assert seen == [("INT-04", "run-cb-a")]
    assert outcome.details["observed_facts"]["lookup_fallback_ok"] is True
    assert outcome.details["backend"]["reason"] == "backend_result_linked"
    assert outcome.status == "passed", outcome


@pytest.mark.parametrize("status,reason,expected", [
    ("blocked", "backend_contract_missing", ("blocked", "backend_contract_missing")),
    ("blocked", "backend_result_contract_missing", ("blocked", "backend_result_contract_missing")),
    ("blocked", "echo_response_not_result", ("blocked", "echo_response_not_result")),
    ("failed", "backend_result_not_linked", ("failed", "backend_result_not_linked")),
])
def test_callback_failure_admin_record_alone_never_passes(cases, config, evidence_dir, monkeypatch,
                                                           status, reason, expected):
    from isolation_tests import runner

    monkeypatch.setattr(runner, "PROBE_BACKEND", _backend(status, reason))
    _write_evidence(evidence_dir, "run-cb-b", "INT-04", "callback-failure", CALLBACK_RECORD)
    outcome = _run(runner.run_case(cases["INT-04"], "callback-failure", config, "run-cb-b"))
    assert (outcome.status, outcome.reason) == expected


def test_callback_failure_lookup_without_admin_record_is_blocked(cases, config, monkeypatch):
    from isolation_tests import runner

    monkeypatch.setattr(runner, "PROBE_BACKEND", _backend("passed", "backend_result_linked"))
    outcome = _run(runner.run_case(cases["INT-04"], "callback-failure", config, "run-cb-c"))
    assert outcome.status == "blocked"


def test_callback_failure_record_from_another_window_is_blocked(cases, config, evidence_dir, monkeypatch):
    from isolation_tests import runner

    monkeypatch.setattr(runner, "PROBE_BACKEND", _backend("passed", "backend_result_linked"))
    _write_evidence(evidence_dir, "run-cb-d", "INT-04", "callback-failure", CALLBACK_RECORD,
                    window=("2020-01-01T00:00:00Z", "2020-01-01T00:00:30Z"))
    outcome = _run(runner.run_case(cases["INT-04"], "callback-failure", config, "run-cb-d"))
    assert (outcome.status, outcome.reason) == ("blocked", "evidence_window_mismatch")


def test_runner_transport_failure_is_not_overridden_by_admin_facts(cases, config, evidence_dir, monkeypatch):
    from isolation_tests import runner
    from isolation_tests.adapters.collector import CollectionError

    class ModeCollector(FakeCollector):
        async def __call__(self, config, url, token_mode="valid"):
            if token_mode != "valid":
                raise CollectionError("collector_unavailable")
            return await super().__call__(config, url, token_mode)

    monkeypatch.setattr(runner, "COLLECT", ModeCollector())
    _write_evidence(evidence_dir, "run-int1-x", "INT-01", "missing",
                    {"authentication_rejected": True, "page_opened": False})
    outcome = _run(runner.run_case(cases["INT-01"], "missing", config, "run-int1-x"))
    assert (outcome.status, outcome.reason) == ("blocked", "runner_observation_inconclusive")

    monkeypatch.setattr(runner, "COLLECT", FakeCollector({"NET-01": CollectionError("runner_timeout")}))
    _write_evidence(evidence_dir, "run-net-t", "NET-01", "img", {
        "receiver_control_ok": True, "request_blocked": True, "receiver_observed": False})
    outcome = _run(runner.run_case(cases["NET-01"], "img", config, "run-net-t"))
    assert (outcome.status, outcome.reason) == ("blocked", "runner_observation_inconclusive")


def test_failed_recovery_request_is_failed(cases, config, evidence_dir, monkeypatch):
    from isolation_tests import runner
    from isolation_tests.adapters.collector import CollectionError

    state = {"n": 0}

    def col01(url):
        state["n"] += 1
        return _page(url) if state["n"] == 1 else CollectionError("collector_unavailable")

    monkeypatch.setattr(runner, "COLLECT", FakeCollector({"LIM-01": _limit_page, "col-01": col01}))
    _limit_admin(evidence_dir, "run-lim-r")
    outcome = _run(runner.run_case(cases["LIM-01"], "delay-15s", config, "run-lim-r"))
    assert (outcome.status, outcome.reason) == ("failed", "recovery_failed")


def test_recovery_case_uses_evidence_only(cases, config, monkeypatch):
    from isolation_tests import runner

    fake = FakeCollector()
    monkeypatch.setattr(runner, "COLLECT", fake)
    outcome = _run(runner.run_case(cases["REC-01"], "replacement", config, "run-rec"))
    assert outcome.status == "blocked"
    assert fake.calls == []


def test_initial_url_variants_reach_the_collector(cases, config, monkeypatch):
    from isolation_tests import runner
    from isolation_tests.adapters.collector import CollectionError

    fake = FakeCollector({"receiver.example.invalid": CollectionError("collector_unavailable")})
    monkeypatch.setattr(runner, "COLLECT", fake)
    _run(runner.run_case(cases["NET-07"], "userinfo", config, "run-n7"))
    assert any(url.startswith("https://isolation-test@receiver.example.invalid") for url, _ in fake.calls)


def test_authentication_variant_uses_token_mode_and_records_rejection(cases, config, monkeypatch):
    from isolation_tests import runner
    from isolation_tests.adapters.collector import CollectionError

    def by_mode(url):
        return CollectionError("authentication_failed")

    class ModeCollector(FakeCollector):
        async def __call__(self, config, url, token_mode="valid"):
            if token_mode != "valid":
                self.calls.append((url, token_mode))
                raise CollectionError("authentication_failed")
            return await super().__call__(config, url, token_mode)

    fake = ModeCollector()
    monkeypatch.setattr(runner, "COLLECT", fake)
    outcome = _run(runner.run_case(cases["INT-01"], "wrong-token", config, "run-int1"))
    assert ("wrong" in {mode for _, mode in fake.calls})
    assert outcome.details["observed_facts"]["authentication_rejected"] is True
    assert outcome.details["observed_facts"]["page_opened"] is False
    assert outcome.status == "passed", outcome


# --- CLI -------------------------------------------------------------------------

@pytest.fixture
def config_file(tmp_path, evidence_dir):
    path = tmp_path / "config.local.json"
    path.write_text(json.dumps({
        "bases": {"pages": "https://pages.example.invalid/project/",
                  "http_fixture": "https://fixture.example.invalid/"},
        "collector_url": "https://collector.example.invalid/collect",
        "token_env": "TEST_ONLY_TOKEN", "capabilities": sorted(ALL_CAPS),
        "evidence_dir": str(evidence_dir),
    }), encoding="utf-8")
    return path


def _report(out):
    files = sorted(out.glob("isolation-report-*.json"))
    assert len(files) == 1
    return json.loads(files[0].read_text(encoding="utf-8"))


def test_default_run_executes_only_basic_cases_and_reports_every_case(config_file, tmp_path, monkeypatch, cases):
    from isolation_tests import runner
    from isolation_tests.adapters.collector import CollectionError

    monkeypatch.setenv("TEST_ONLY_TOKEN", "synthetic-runner-token")
    fake = FakeCollector({"": CollectionError("stub_not_collected")})
    monkeypatch.setattr(runner, "COLLECT", fake)

    async def analyze(case, variant, page, **_):
        return Outcome(case.id, variant, "blocked", "ai_unavailable", {})

    monkeypatch.setattr(runner, "ANALYZE", analyze)
    out = tmp_path / "results"
    code = runner.main(["run", "--manifest", str(MANIFEST), "--config", str(config_file), "--output", str(out)])
    assert code == 2
    data = _report(out)
    items = {(i["case_id"], i["variant"]): i for i in data["items"]}
    assert len(items) == sum(len(c.variants) for c in cases.values())
    assert {i["case_id"] for i in data["items"]} == set(cases)
    for (case_id, _variant), item in items.items():
        if cases[case_id].risk_level == "explicit":
            assert (item["status"], item["reason"]) == ("not_run", "not_selected")
        else:
            assert item["status"] != "passed"
    assert items[("COL-01", "default")]["reason"] == "stub_not_collected"
    assert not any("NET-" in url or "LIM-" in url for url, _ in fake.calls)
    assert data["metadata"]["scope"] == "subset"
    assert len(data["metadata"]["case_hashes"]) == 43
    assert "synthetic-runner-token" not in json.dumps(data)
    run_ids = [i["details"].get("run_id") for i in data["items"] if i["status"] != "not_run"]
    assert len(run_ids) == len(set(run_ids))


def test_run_single_case_and_group_selection(config_file, tmp_path, monkeypatch):
    from isolation_tests import runner

    monkeypatch.setenv("TEST_ONLY_TOKEN", "synthetic-runner-token")
    monkeypatch.setattr(runner, "COLLECT", FakeCollector())
    out = tmp_path / "one"
    code = runner.main(["run", "--manifest", str(MANIFEST), "--config", str(config_file),
                        "--output", str(out), "--case", "COL-01"])
    assert code == 2  # one passed case is never overall completion
    data = _report(out)
    ran = [i for i in data["items"] if i["status"] != "not_run"]
    assert [(i["case_id"], i["status"]) for i in ran] == [("COL-01", "passed")]

    out = tmp_path / "group"
    runner.main(["run", "--manifest", str(MANIFEST), "--config", str(config_file),
                 "--output", str(out), "--group", "host"])
    ran = {i["case_id"] for i in _report(out)["items"] if i["status"] != "not_run"}
    assert ran == {"HOST-01", "HOST-02", "HOST-03"}


def test_interrupt_records_unfinished_items_as_not_run(config_file, tmp_path, monkeypatch):
    from isolation_tests import runner

    monkeypatch.setenv("TEST_ONLY_TOKEN", "synthetic-runner-token")
    calls = {"n": 0}

    def interrupt(url):
        calls["n"] += 1
        if calls["n"] >= 2:
            return KeyboardInterrupt()
        return _page(url)

    monkeypatch.setattr(runner, "COLLECT", FakeCollector({"": interrupt}))
    out = tmp_path / "int"
    code = runner.main(["run", "--manifest", str(MANIFEST), "--config", str(config_file),
                        "--output", str(out), "--group", "collection"])
    assert code == 2
    items = {(i["case_id"], i["variant"]): i for i in _report(out)["items"]}
    assert items[("COL-01", "default")]["status"] == "passed"
    assert (items[("COL-02", "default")]["status"], items[("COL-02", "default")]["reason"]) == ("not_run", "interrupted")
    assert items[("COL-02", "default")]["details"]["remote_job_unconfirmed"] is True
    assert items[("COL-03", "default")]["reason"] == "interrupted"


def test_report_subcommand_rejudges_with_evidence_added_after_the_run(config_file, tmp_path, monkeypatch, evidence_dir):
    from isolation_tests import runner

    monkeypatch.setenv("TEST_ONLY_TOKEN", "synthetic-runner-token")
    monkeypatch.setattr(runner, "COLLECT", FakeCollector({"NET-01": lambda url: _page(url, "<p>n</p>", title=None)}))
    _live_receiver(monkeypatch, evidence_dir)  # its log is copied from the receiver host after the run
    first = tmp_path / "first"
    runner.main(["run", "--manifest", str(MANIFEST), "--config", str(config_file),
                 "--output", str(first), "--case", "NET-01"])
    data = _report(first)
    item = next(i for i in data["items"] if (i["case_id"], i["variant"]) == ("NET-01", "img"))
    assert item["status"] == "blocked"
    _write_evidence(evidence_dir, item["details"]["run_id"], "NET-01", "img", {
        "receiver_control_ok": True, "request_blocked": True, "receiver_observed": False},
        window=(item["details"]["started_at"], _from_now()[1]))
    source = next(first.glob("isolation-report-*.json"))
    second = tmp_path / "second"
    code = runner.main(["report", "--input", str(source), "--config", str(config_file),
                        "--manifest", str(MANIFEST), "--output", str(second)])
    assert code == 2
    items = {(i["case_id"], i["variant"]): i for i in _report(second)["items"]}
    assert items[("NET-01", "img")]["status"] == "passed"
    assert items[("NET-01", "script")]["status"] == "blocked"


def test_host_variants_in_one_run_share_a_batch_prefix(config_file, tmp_path, monkeypatch, capsys):
    from isolation_tests import runner
    from isolation_tests.runner import probe_batch_id

    monkeypatch.setattr(runner, "COLLECT", FakeCollector())
    out = tmp_path / "host"
    runner.main(["run", "--manifest", str(MANIFEST), "--config", str(config_file),
                 "--output", str(out), "--group", "host"])
    items = [i for i in _report(out)["items"] if i["status"] != "not_run"]
    batches = {probe_batch_id(i["case_id"], i["variant"], i["details"]["run_id"]) for i in items}
    assert len(batches) == 1 and None not in batches
    assert f"host_batch\t{batches.pop()}" in capsys.readouterr().out
    assert len({i["details"]["run_id"] for i in items}) == len(items)


def test_collector_limit_over_eight_blocks_only_the_concurrency_trial(config_file, tmp_path, monkeypatch):
    from isolation_tests import runner

    monkeypatch.setenv("TEST_ONLY_TOKEN", "synthetic-runner-token")
    fake = FakeCollector()
    monkeypatch.setattr(runner, "COLLECT", fake)
    out = tmp_path / "lim6"
    code = runner.main(["run", "--manifest", str(MANIFEST), "--config", str(config_file),
                        "--output", str(out), "--case", "LIM-06", "--collector-limit", "9"])
    assert code == 2
    items = {(i["case_id"], i["variant"]): i for i in _report(out)["items"]}
    assert (items[("LIM-06", "concurrency")]["status"],
            items[("LIM-06", "concurrency")]["reason"]) == ("blocked", "concurrency_trial_exceeds_cap")
    assert fake.calls == []


def test_unexpected_exception_blocks_only_that_trial(config_file, tmp_path, monkeypatch):
    from isolation_tests import runner

    monkeypatch.setenv("TEST_ONLY_TOKEN", "synthetic-runner-token")

    def boom(url):
        return RuntimeError("internal detail synthetic-runner-token")

    monkeypatch.setattr(runner, "COLLECT", FakeCollector({"col-02": boom}))
    out = tmp_path / "boom"
    runner.main(["run", "--manifest", str(MANIFEST), "--config", str(config_file),
                 "--output", str(out), "--group", "collection"])
    data = _report(out)
    items = {(i["case_id"], i["variant"]): i for i in data["items"]}
    assert (items[("COL-02", "default")]["status"], items[("COL-02", "default")]["reason"]) == (
        "blocked", "runner_internal_error")
    assert items[("COL-01", "default")]["status"] == "passed"
    assert items[("COL-03", "default")]["status"] != "not_run"
    assert "internal detail" not in json.dumps(data)


def test_check_env_reports_stub_as_blocked_collection(config_file, monkeypatch, capsys):
    from isolation_tests import runner
    from isolation_tests.adapters.collector import CollectionError

    monkeypatch.setenv("TEST_ONLY_TOKEN", "synthetic-runner-token")
    monkeypatch.setattr(runner, "COLLECT", FakeCollector({"": CollectionError("stub_not_collected")}))
    assert runner.main(["check-env", "--manifest", str(MANIFEST), "--config", str(config_file)]) == 2
    out = capsys.readouterr().out
    assert "stub_not_collected" in out and "blocked" in out
    assert "synthetic-runner-token" not in out


def test_check_env_with_real_collector_adapter_and_mock_transport(config_file, monkeypatch, capsys):
    import functools
    import httpx

    from isolation_tests import runner
    from isolation_tests.adapters.collector import collect

    monkeypatch.setenv("TEST_ONLY_TOKEN", "synthetic-runner-token")
    seen = []

    class RawStream(httpx.AsyncByteStream):
        def __init__(self, data):
            self.data = data

        async def __aiter__(self):
            yield self.data

    def handler(request):
        seen.append(json.loads(request.content)["url"])
        body = json.dumps({
            "input_url": seen[-1], "final_url": seen[-1], "redirect_chain": [], "status_code": 200,
            "content_type": "text/html", "html": "<title>수집 기준</title>배송 상태: 배송 중 📦",
            "title": "수집 기준", "elapsed_ms": 10, "failures": []}).encode("utf-8")
        # A streamed (not pre-read) body, as a real transport delivers it.
        return httpx.Response(200, headers={"content-type": "application/json"}, stream=RawStream(body))

    async def via_mock(config, url, token_mode="valid"):
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await collect(config, url, token_mode, client=client)

    monkeypatch.setattr(runner, "COLLECT", via_mock)
    code = runner.main(["check-env", "--manifest", str(MANIFEST), "--config", str(config_file)])
    out = capsys.readouterr().out
    assert seen and seen[0].startswith("https://pages.example.invalid/project/v1/cases/col-01/")
    assert "collection\tpassed" in out
    # forbidden_receiver base is not configured: still incomplete
    assert code == 2


def test_check_env_without_collector_is_incomplete(tmp_path, monkeypatch, capsys):
    from isolation_tests import runner

    path = tmp_path / "c.json"
    path.write_text("{}", encoding="utf-8")
    fake = FakeCollector()
    monkeypatch.setattr(runner, "COLLECT", fake)
    assert runner.main(["check-env", "--manifest", str(MANIFEST), "--config", str(path)]) == 2
    assert fake.calls == []
    assert "collector_not_configured" in capsys.readouterr().out


def test_list_and_host_probe_subcommands_still_work(tmp_path, capsys):
    from isolation_tests import runner

    assert runner.main(["list", "--manifest", str(MANIFEST)]) == 0
    assert "COL-01" in capsys.readouterr().out
    output = tmp_path / "probe.json"
    code = runner.main(["host-probe", "--output", str(output), "--run-id", "r" + "a" * 32])
    assert code in {0, 2}
    assert json.loads(output.read_text(encoding="utf-8"))["schema"] == "host-probe-v1"


# --- final review #5: manifest integrity for run and report --config ---------------

def _weakened_manifest(tmp_path):
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    for case in data["cases"]:
        if case["id"] == "NET-01":
            for contract in case["expected_observations"]["variants"].values():
                contract["assertions"]["required_facts"] = {"positive_control_ok": True}
                contract["required_evidence"] = ["positive_control_ok"]
            case["required_evidence"] = ["positive_control_ok"]
    path = tmp_path / "weakened-cases.json"
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return path


def test_run_with_a_non_canonical_manifest_is_blocked_manifest_mismatch(config_file, tmp_path, monkeypatch):
    from isolation_tests import runner

    fake = FakeCollector()
    monkeypatch.setattr(runner, "COLLECT", fake)
    out = tmp_path / "results"
    code = runner.main(["run", "--manifest", str(_weakened_manifest(tmp_path)), "--config", str(config_file),
                        "--output", str(out), "--case", "NET-01"])
    assert code == 2
    assert fake.calls == []
    data = _report(out)
    items = [i for i in data["items"] if i["case_id"] == "NET-01"]
    assert items and all((i["status"], i["reason"]) == ("blocked", "manifest_mismatch") for i in items)
    assert data["summary"]["manifest_canonical"] is False


def test_explicit_non_canonical_run_executes_but_cannot_exit_zero(config_file, tmp_path, monkeypatch):
    from isolation_tests import runner
    from isolation_tests.report import canonical_manifest_sha256

    fake = FakeCollector()
    monkeypatch.setattr(runner, "COLLECT", fake)
    out = tmp_path / "results"
    code = runner.main(["run", "--manifest", str(_weakened_manifest(tmp_path)), "--config", str(config_file),
                        "--output", str(out), "--case", "NET-01", "--non-canonical"])
    assert code != 0 and fake.calls
    data = _report(out)
    assert data["metadata"]["scope"] == "non_canonical"
    assert data["metadata"]["manifest_sha256"] != canonical_manifest_sha256()
    assert all(i["reason"] != "manifest_mismatch" for i in data["items"])


def test_canonical_run_records_the_manifest_hash(config_file, tmp_path, monkeypatch):
    from isolation_tests import runner
    from isolation_tests.report import canonical_manifest_sha256

    monkeypatch.setattr(runner, "COLLECT", FakeCollector())
    out = tmp_path / "results"
    runner.main(["run", "--config", str(config_file), "--output", str(out), "--case", "COL-01"])
    data = _report(out)
    assert data["metadata"]["manifest_sha256"] == canonical_manifest_sha256()
    assert data["summary"]["manifest_canonical"] is True


def test_report_rejudge_with_a_non_canonical_manifest_is_blocked(config_file, tmp_path, monkeypatch):
    from isolation_tests import runner

    monkeypatch.setattr(runner, "COLLECT", FakeCollector())
    first = tmp_path / "first"
    runner.main(["run", "--config", str(config_file), "--output", str(first), "--case", "NET-01"])
    source = next(first.glob("isolation-report-*.json"))
    second = tmp_path / "second"
    code = runner.main(["report", "--input", str(source), "--config", str(config_file),
                        "--manifest", str(_weakened_manifest(tmp_path)), "--output", str(second)])
    assert code == 2
    data = _report(second)
    items = [i for i in data["items"] if i["case_id"] == "NET-01"]
    assert all((i["status"], i["reason"]) == ("blocked", "manifest_mismatch") for i in items)
    assert data["summary"]["manifest_canonical"] is False


def test_report_rejudge_internal_error_is_blocked_per_trial(config_file, tmp_path, monkeypatch):
    from isolation_tests import runner

    monkeypatch.setattr(runner, "COLLECT", FakeCollector())
    first = tmp_path / "first"
    runner.main(["run", "--config", str(config_file), "--output", str(first), "--case", "COL-01"])
    source = next(first.glob("isolation-report-*.json"))

    def broken(*_args, **_kwargs):
        raise RecursionError("synthetic")

    monkeypatch.setattr(runner, "judge", broken)
    second = tmp_path / "second"
    code = runner.main(["report", "--input", str(source), "--config", str(config_file),
                        "--output", str(second)])
    assert code == 2
    item = next(i for i in _report(second)["items"] if i["case_id"] == "COL-01")
    assert (item["status"], item["reason"]) == ("blocked", "rejudge_internal_error")


def test_runner_source_has_no_literal_tab():
    source = (ROOT / "tools" / "isolation-tests" / "isolation_tests" / "runner.py").read_text(encoding="utf-8")
    assert chr(9) not in source


# --- final review #1: the runner reads the receiver log itself ---------------------

def _receiver_log(directory, *events, name="receiver-forbidden.jsonl"):
    """A receiver log as the fixture server writes it, copied into evidence_dir."""
    from isolation_tests.receiver import write_receiver_event

    path = directory / name
    path.touch()
    for event in events:
        write_receiver_event(path, method="GET", fixed_path=f"/v1/receive/{event['case_id']}",
                             bytes_sent=0, **event)
    return path


def _utc(offset_seconds=0.0):
    from datetime import datetime, timedelta, timezone

    return (datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)).isoformat()


def _net01_admin(evidence_dir, run_id, **facts):
    _write_evidence(evidence_dir, run_id, "NET-01", "img", {
        "receiver_control_ok": True, "request_blocked": True, **facts})


def _reaching_collector(evidence_dir, run_id):
    """The collected page makes its request reach the receiver during the trial."""
    def answer(url):
        _receiver_log(evidence_dir, {"case_id": "NET-01", "run_id": run_id, "at": _utc()})
        return _page(url, "<p>net</p>", title=None)

    return FakeCollector({"NET-01": answer})


def test_receiver_event_in_the_trial_window_fails_the_block(cases, config, evidence_dir, monkeypatch):
    from isolation_tests import runner

    monkeypatch.setattr(runner, "COLLECT", _reaching_collector(evidence_dir, "run-recv-a"))
    _live_receiver(monkeypatch, evidence_dir)
    _net01_admin(evidence_dir, "run-recv-a")
    outcome = _run(runner.run_case(cases["NET-01"], "img", config, "run-recv-a"))
    assert (outcome.status, outcome.reason) == ("failed", "fact_mismatch:receiver_observed"), outcome


def test_admin_cannot_override_a_receiver_event_the_runner_read(cases, config, evidence_dir, monkeypatch):
    from isolation_tests import runner

    monkeypatch.setattr(runner, "COLLECT", _reaching_collector(evidence_dir, "run-recv-b"))
    _live_receiver(monkeypatch, evidence_dir)
    _net01_admin(evidence_dir, "run-recv-b", receiver_observed=False)
    outcome = _run(runner.run_case(cases["NET-01"], "img", config, "run-recv-b"))
    assert (outcome.status, outcome.reason) == ("blocked", "evidence_conflict")
    assert outcome.details["conflict"] == "receiver_observed"


def test_late_or_foreign_receiver_event_is_inconclusive(cases, config, evidence_dir, monkeypatch):
    from isolation_tests import runner

    monkeypatch.setattr(runner, "COLLECT", FakeCollector({"NET-01": lambda url: _page(url, "<p>n</p>", title=None)}))
    _live_receiver(monkeypatch, evidence_dir)
    _net01_admin(evidence_dir, "run-recv-c", receiver_observed=False)
    _receiver_log(evidence_dir, {"case_id": "NET-01", "run_id": "run-recv-c", "at": _utc(120)})
    late = _run(runner.run_case(cases["NET-01"], "img", config, "run-recv-c"))
    assert (late.status, late.reason) == ("blocked", "receiver_evidence_inconclusive")

    _net01_admin(evidence_dir, "run-recv-d", receiver_observed=False)
    _receiver_log(evidence_dir, {"case_id": "NET-02", "run_id": "run-recv-d", "at": _utc()},
                  name="receiver-other.jsonl")
    foreign = _run(runner.run_case(cases["NET-01"], "img", config, "run-recv-d"))
    assert (foreign.status, foreign.reason) == ("blocked", "receiver_evidence_inconclusive")


def test_malformed_receiver_log_is_blocked(cases, config, evidence_dir, monkeypatch):
    from isolation_tests import runner

    monkeypatch.setattr(runner, "COLLECT", FakeCollector({"NET-01": lambda url: _page(url, "<p>n</p>", title=None)}))
    _net01_admin(evidence_dir, "run-recv-e", receiver_observed=False)
    (evidence_dir / "receiver-forbidden.jsonl").write_text('{"at": "x"}\n', encoding="utf-8")
    outcome = _run(runner.run_case(cases["NET-01"], "img", config, "run-recv-e"))
    assert (outcome.status, outcome.reason) == ("blocked", "receiver_log_unreadable")


def test_receiver_log_is_not_read_as_admin_evidence(cases, config, evidence_dir, monkeypatch):
    from isolation_tests.evidence import load_evidence

    _net01_admin(evidence_dir, "run-recv-f", receiver_observed=False)
    _receiver_log(evidence_dir, {"case_id": "NET-01", "run_id": "run-recv-f", "at": _utc()})
    assert load_evidence(evidence_dir, "run-recv-f", "NET-01", variant="img").facts["receiver_observed"] is False


@pytest.mark.parametrize("case_id,variant", [
    ("NAV-04", "http"), ("NET-02", "action"), ("NET-03", "private"), ("NET-04", "same-host-path"),
    ("NET-06", "websocket"), ("NET-07", "userinfo"),
])
def test_every_receiver_case_requires_the_runner_read_receiver_log(cases, config, evidence_dir, monkeypatch,
                                                                    case_id, variant, receiver_controls):
    from isolation_tests import runner

    monkeypatch.setattr(runner, "COLLECT", FakeCollector({"": lambda url: _page(url, "<p>n</p>", title=None)}))
    _write_evidence(evidence_dir, "run-recv-g", case_id, variant, {
        "receiver_control_ok": True, "request_blocked": True, "receiver_observed": False})
    contract = cases[case_id].expected_observations["variants"][variant]
    caps = ALL_CAPS | set(cases[case_id].required_capabilities) | set(contract["required_capabilities"])
    outcome = _run(runner.run_case(cases[case_id], variant, replace(config, capabilities=frozenset(caps)),
                                   "run-recv-g"))
    assert (outcome.status, outcome.reason) == ("blocked", "receiver_log_unavailable"), outcome
    # The runner tried to prove the log live with one control for exactly this trial,
    # except for a network-relative receiver, whose control must come from the isolation side.
    from isolation_tests.receiver import isolation_side_control

    expected = [] if isolation_side_control(case_id, variant) else [(case_id, variant, "run-recv-g")]
    assert receiver_controls == expected


def test_evidence_only_receiver_case_uses_the_admin_window(cases, config, evidence_dir):
    from isolation_tests import runner

    _receiver_log(evidence_dir, {"case_id": "NET-05", "run_id": "run-recv-h", "at": _utc(2)})
    _control_event(evidence_dir, "NET-05", "run-recv-h", _utc(2))  # sent by the administrator
    _write_evidence(evidence_dir, "run-recv-h", "NET-05", "tcp", {
        "receiver_control_ok": True, "request_blocked": True, "receiver_observed": False,
        "positive_control_ok": True, "firewall_drop_observed": True, "probe_in_container": True,
        "boundary": "container", "evidence_source": "observed"})
    outcome = _run(runner.run_case(cases["NET-05"], "tcp", replace(config, capabilities=ALL_CAPS | {"tcp_probe"}),
                                   "run-recv-h"))
    assert (outcome.status, outcome.reason) == ("blocked", "evidence_conflict"), outcome


def test_evidence_only_admin_window_must_not_start_before_the_run(cases, config, evidence_dir):
    from isolation_tests import runner

    _write_evidence(evidence_dir, "run-early", "INT-02", "allowed-source", {
        "positive_control_ok": True, "source_allowed": True, "evidence_source": "observed"},
        window=_around_now())
    caps = ALL_CAPS | {"source_evidence", "allowed_source_evidence"}
    outcome = _run(runner.run_case(cases["INT-02"], "allowed-source", replace(config, capabilities=caps),
                                   "run-early"))
    assert (outcome.status, outcome.reason) == ("blocked", "evidence_window_mismatch")


# --- final review #4: LIM-06 is judged on the runner's own limit+1 results ---------

def _lim06(cases, config, monkeypatch, answer, limit=3):
    from isolation_tests import runner

    def collect(url):
        return answer(url) if callable(answer) else answer

    monkeypatch.setattr(runner, "COLLECT", FakeCollector({"LIM-02": collect}))
    limited = replace(config, limits={**config.limits, "collector_concurrency": limit})
    return _run(runner.run_case(cases["LIM-06"], "concurrency", limited, "run-lim6-x"))


def _lim06_admin(evidence_dir, **facts):
    _write_evidence(evidence_dir, "run-lim6-x", "LIM-06", "concurrency", {
        "remote_job_terminated": True, "children_remaining": 0, "concurrency_limit_known": True,
        "queue_limit_ok": True, "fixture_max_active": 4, **facts})


def test_every_request_collected_contradicts_an_admin_limit_claim(cases, config, evidence_dir, monkeypatch):
    _lim06_admin(evidence_dir, concurrency_limit_ok=True)
    outcome = _lim06(cases, config, monkeypatch, lambda url: _page(url, "<p>s</p>", title=None))
    assert outcome.details["observed_facts"]["concurrency_limit_ok"] is False
    assert outcome.details["observed_facts"]["limit_exceeded_confirmed"] is False
    assert (outcome.status, outcome.reason) == ("blocked", "evidence_conflict")


def test_every_request_collected_without_admin_claim_fails(cases, config, evidence_dir, monkeypatch):
    _lim06_admin(evidence_dir)
    outcome = _lim06(cases, config, monkeypatch, lambda url: _page(url, "<p>s</p>", title=None))
    assert outcome.status == "failed" and "fact_mismatch:concurrency_limit_ok" in outcome.details["failures"]


def test_observed_overload_within_the_limit_confirms_enforcement(cases, config, evidence_dir, monkeypatch):
    from isolation_tests.adapters.collector import CollectionError

    seen = []

    def answer(url):
        seen.append(url)
        if len(seen) == 1:
            return CollectionError("collector_rate_limited")
        return _page(url, "<p>s</p>", title=None)

    _lim06_admin(evidence_dir, concurrency_limit_ok=True, recovery_ok=True)
    outcome = _lim06(cases, config, monkeypatch, answer)
    facts = outcome.details["observed_facts"]
    assert (facts["limit_exceeded_confirmed"], facts["concurrency_limit_ok"]) == (True, True)
    assert (outcome.status, outcome.reason) == ("passed", "observed_expectations_met"), outcome


def test_inconclusive_concurrency_results_record_no_limit_fact(cases, config, evidence_dir, monkeypatch):
    from isolation_tests.adapters.collector import CollectionError

    _lim06_admin(evidence_dir, concurrency_limit_ok=True)
    outcome = _lim06(cases, config, monkeypatch, CollectionError("runner_timeout"))
    facts = outcome.details["observed_facts"]
    assert facts["limit_exceeded_confirmed"] is False and "concurrency_limit_ok" not in facts
    # The administrator's concurrency_limit_ok: true cannot pass an inconclusive trial.
    assert (outcome.status, outcome.reason) == ("blocked", "limit_observation_inconclusive")


@pytest.mark.parametrize("first", ["collector_unavailable", "collector_timeout", "unexpected_status"])
def test_one_non_overload_error_with_the_rest_collected_is_inconclusive(cases, config, evidence_dir,
                                                                        monkeypatch, first):
    from isolation_tests.adapters.collector import CollectionError

    seen = []

    def answer(url):
        seen.append(url)
        return CollectionError(first) if len(seen) == 1 else _page(url, "<p>s</p>", title=None)

    _lim06_admin(evidence_dir, concurrency_limit_ok=True)
    outcome = _lim06(cases, config, monkeypatch, answer)
    assert outcome.details["observed_facts"]["limit_exceeded_confirmed"] is False
    assert (outcome.status, outcome.reason) == ("blocked", "limit_observation_inconclusive")


def test_overload_codes_count_429_but_not_a_bare_5xx():
    from isolation_tests.runner import OVERLOAD_CODES

    assert OVERLOAD_CODES == {"collector_rate_limited", "collector_busy", "concurrency_limit_exceeded",
                              "queue_full"}


# --- final review #3: REC-01 needs the stored, later, passing follow-up report ------

FOLLOWUP = "run-20261010T120000-abcd1234"


def _iso(offset_seconds):
    from datetime import datetime, timedelta, timezone

    return (datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)).isoformat(
        timespec="milliseconds").replace("+00:00", "Z")


def _followup_report(directory, *, run_id=FOLLOWUP, started=None, failing=None, digest=None,
                     name=None):
    from isolation_tests.evaluate import _canonical_variants
    from isolation_tests.report import canonical_manifest_sha256, write_reports

    items = []
    for case_id, variants in _canonical_variants().items():
        for variant in variants:
            status = "failed" if (case_id, variant) == failing else "passed"
            items.append(Outcome(case_id, variant, status, "observed_expectations_met"))
    staging = directory.parent / f"staging-{run_id}-{len(list(directory.parent.iterdir()))}"
    json_path, _ = write_reports(tuple(items), staging, {
        "run_id": run_id, "started_at": started or _iso(5), "ended_at": _iso(60),
        "manifest_sha256": digest or canonical_manifest_sha256(), "scope": "all"})
    target = directory / (name or f"isolation-report-{FOLLOWUP}.json")
    target.write_bytes(json_path.read_bytes())
    return target


def _rec01(cases, config, evidence_dir, window=None, **facts):
    from isolation_tests import runner

    # By default the replacement window ends (now+3 s) before the follow-up starts (now+5 s).
    _write_evidence(evidence_dir, "run-rec-f", "REC-01", "replacement", {
        "replacement_kind": "new_instance", "replacement_ok": True, "digest_ok": True,
        "credentials_rotated": True, "old_credentials_rejected": True, "recovery_ok": True,
        "positive_control_ok": True, "followup_run_id": FOLLOWUP, **facts}, window=window or _from_now(3))
    caps = replace(config, capabilities=ALL_CAPS | {"replacement_evidence"})
    return _run(runner.run_case(cases["REC-01"], "replacement", caps, "run-rec-f"))


def test_replacement_passes_with_a_stored_later_passing_followup(cases, config, evidence_dir):
    _followup_report(evidence_dir)
    outcome = _rec01(cases, config, evidence_dir)
    assert outcome.status == "passed", outcome
    assert outcome.details["followup"]["reason"] == "followup_verified"


@pytest.mark.parametrize("variant_kwargs,reason", [
    (None, "followup_report_missing"),
    ({"started": "2020-01-01T00:00:00.000Z"}, "followup_not_later"),
    ({"failing": ("INT-01", "wrong-token")}, "followup_retest_not_passed"),
    ({"failing": ("HOST-02", "mounts")}, "followup_retest_not_passed"),
    ({"run_id": "run-20261010T130000-ffff0000"}, "followup_run_mismatch"),
    ({"digest": "0" * 64}, "followup_not_canonical"),
])
def test_replacement_without_a_valid_followup_is_blocked(cases, config, evidence_dir, variant_kwargs, reason):
    if variant_kwargs is not None:
        _followup_report(evidence_dir, **variant_kwargs)
    outcome = _rec01(cases, config, evidence_dir)
    assert (outcome.status, outcome.reason) == ("blocked", reason), outcome


def test_followup_started_inside_the_replacement_window_is_not_accepted(cases, config, evidence_dir):
    _followup_report(evidence_dir)  # starts at now+5 s
    outcome = _rec01(cases, config, evidence_dir, window=_from_now(3600))
    assert (outcome.status, outcome.reason) == ("blocked", "followup_not_later"), outcome


def test_unreadable_followup_report_is_blocked(cases, config, evidence_dir):
    (evidence_dir / f"isolation-report-{FOLLOWUP}.json").write_text("{not json", encoding="utf-8")
    outcome = _rec01(cases, config, evidence_dir)
    assert (outcome.status, outcome.reason) == ("blocked", "followup_report_unreadable")


# --- residual #1: the receiver log must be proven live for this trial ---------------

def _net01_trial(cases, config, evidence_dir, monkeypatch, run_id, **facts):
    from isolation_tests import runner

    monkeypatch.setattr(runner, "COLLECT", FakeCollector({"NET-01": lambda url: _page(url, "<p>n</p>", title=None)}))
    _net01_admin(evidence_dir, run_id, receiver_observed=False, **facts)
    return _run(runner.run_case(cases["NET-01"], "img", config, run_id))


@pytest.mark.parametrize("log", ["empty", "stale", "foreign-run", "foreign-case"])
def test_receiver_log_without_this_trials_control_is_coverage_unproven(cases, config, evidence_dir,
                                                                       monkeypatch, log):
    (evidence_dir / "receiver-forbidden.jsonl").touch()
    if log == "stale":
        _control_event(evidence_dir, "NET-01", "run-cov-a", _utc(-120))
    elif log == "foreign-run":
        _control_event(evidence_dir, "NET-01", "run-cov-other", _utc())
    elif log == "foreign-case":
        _control_event(evidence_dir, "NET-02", "run-cov-a", _utc())
    # The administrator's receiver_control_ok: true cannot stand in for the logged control.
    outcome = _net01_trial(cases, config, evidence_dir, monkeypatch, "run-cov-a")
    assert (outcome.status, outcome.reason) == ("blocked", "receiver_log_coverage_unproven"), outcome


def test_admin_receiver_control_disagreeing_with_the_log_is_a_conflict(cases, config, evidence_dir, monkeypatch):
    _live_receiver(monkeypatch, evidence_dir)
    outcome = _net01_trial(cases, config, evidence_dir, monkeypatch, "run-cov-b", receiver_control_ok=False)
    assert (outcome.status, outcome.reason) == ("blocked", "evidence_conflict")
    assert outcome.details["conflict"] == "receiver_control_ok"


def test_logged_control_alone_is_never_an_observed_request(cases, config, evidence_dir, monkeypatch):
    sent = _live_receiver(monkeypatch, evidence_dir)
    outcome = _net01_trial(cases, config, evidence_dir, monkeypatch, "run-cov-c")
    assert outcome.status == "passed", outcome
    assert sent == [("NET-01", "img", "run-cov-c")]
    facts = outcome.details["observed_facts"]
    assert (facts["receiver_observed"], facts["receiver_control_ok"]) == (False, True)


def test_runner_sends_no_receiver_control_for_other_cases(cases, config, monkeypatch, receiver_controls):
    from isolation_tests import runner

    monkeypatch.setattr(runner, "COLLECT", FakeCollector({"NAV-02": lambda url: _page(url)}))
    _run(runner.run_case(cases["NAV-02"], "hops-1", config, "run-cov-d"))
    assert receiver_controls == []


def _net05(cases, config, evidence_dir, run_id):
    from isolation_tests import runner

    _write_evidence(evidence_dir, run_id, "NET-05", "tcp", {
        "request_blocked": True, "receiver_observed": False, "positive_control_ok": True,
        "firewall_drop_observed": True, "probe_in_container": True, "boundary": "container",
        "evidence_source": "observed"})
    return _run(runner.run_case(cases["NET-05"], "tcp", replace(config, capabilities=ALL_CAPS | {"tcp_probe"}),
                                run_id))


@pytest.mark.parametrize("control_at,expected", [
    (None, ("blocked", "receiver_log_coverage_unproven")),
    (-60, ("blocked", "receiver_log_coverage_unproven")),  # before the administrator's window
    (2, ("passed", None)),
])
def test_evidence_only_receiver_case_needs_the_control_in_the_admin_window(cases, config, evidence_dir,
                                                                           control_at, expected):
    (evidence_dir / "receiver-forbidden.jsonl").touch()
    if control_at is not None:
        _control_event(evidence_dir, "NET-05", "run-cov-e", _utc(control_at))
    outcome = _net05(cases, config, evidence_dir, "run-cov-e")
    assert outcome.status == expected[0], outcome
    if expected[1]:
        assert outcome.reason == expected[1]
    else:
        assert outcome.details["observed_facts"]["receiver_control_ok"] is True


# --- fix round 1: the control must reach the receiver the leak would reach ------------

def _net03_loopback(cases, config, evidence_dir, run_id):
    from isolation_tests import runner

    contract = cases["NET-03"].expected_observations["variants"]["loopback"]
    caps = ALL_CAPS | set(cases["NET-03"].required_capabilities) | set(contract["required_capabilities"])
    _write_evidence(evidence_dir, run_id, "NET-03", "loopback", {
        "receiver_control_ok": True, "request_blocked": True, "receiver_observed": False})
    return _run(runner.run_case(cases["NET-03"], "loopback",
                                replace(config, capabilities=frozenset(caps)), run_id))


@pytest.mark.parametrize("log", ["unrelated", "runner-window"])
def test_network_relative_receiver_needs_an_isolation_side_control(cases, config, evidence_dir, monkeypatch, log):
    from isolation_tests import runner

    monkeypatch.setattr(runner, "COLLECT", FakeCollector({"NET-03": lambda url: _page(url, "<p>n</p>", title=None)}))
    sent = _live_receiver(monkeypatch, evidence_dir)
    if log == "unrelated":  # a live log, but nothing sent for this trial from the isolation side
        _control_event(evidence_dir, "NET-01", "run-other", _utc())
        _control_event(evidence_dir, "NET-03", "run-other", _utc(2))
    else:  # a control logged during the run itself cannot come from the isolation side
        _control_event(evidence_dir, "NET-03", "run-rel-a", _utc())
    outcome = _net03_loopback(cases, config, evidence_dir, "run-rel-a")
    assert (outcome.status, outcome.reason) == ("blocked", "receiver_log_coverage_unproven"), outcome
    assert sent == []  # the runner never sends a control to a network-relative receiver


def test_network_relative_receiver_with_an_isolation_side_control_is_judged(cases, config, evidence_dir,
                                                                          monkeypatch, receiver_controls):
    from isolation_tests import runner

    monkeypatch.setattr(runner, "COLLECT", FakeCollector({"NET-03": lambda url: _page(url, "<p>n</p>", title=None)}))
    # Sent by the administrator from inside the isolation container after the run,
    # inside the administrator's record window.
    _control_event(evidence_dir, "NET-03", "run-rel-b", _utc(2))
    outcome = _net03_loopback(cases, config, evidence_dir, "run-rel-b")
    assert receiver_controls == []
    assert outcome.status == "passed", outcome
    facts = outcome.details["observed_facts"]
    assert (facts["receiver_observed"], facts["receiver_control_ok"]) == (False, True)


def test_network_relative_receiver_without_admin_record_is_coverage_unproven(cases, config, evidence_dir,
                                                                          monkeypatch):
    from isolation_tests import runner

    contract = cases["NET-03"].expected_observations["variants"]["loopback"]
    caps = ALL_CAPS | set(cases["NET-03"].required_capabilities) | set(contract["required_capabilities"])
    monkeypatch.setattr(runner, "COLLECT", FakeCollector({"NET-03": lambda url: _page(url, "<p>n</p>", title=None)}))
    _control_event(evidence_dir, "NET-03", "run-rel-c", _utc(2))
    outcome = _run(runner.run_case(cases["NET-03"], "loopback", replace(config, capabilities=frozenset(caps)),
                                   "run-rel-c"))
    assert (outcome.status, outcome.reason) == ("blocked", "receiver_log_coverage_unproven"), outcome
