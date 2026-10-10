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


def _write_evidence(directory, run_id, case_id, variant, facts, window=None):
    window = window or _around_now()
    record = {"run_id": run_id, "case_id": case_id, "started_at": window[0], "ended_at": window[1],
              "facts": {"variant": variant, **facts}, "references": []}
    with (directory / "admin.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record) + "\n")


def _run(coro):
    return asyncio.run(coro)


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
    passed = _run(runner.run_case(cases["NET-01"], "img", config, "run-net-b"))
    assert passed.status == "passed", passed


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


def _probe_file(evidence_dir, **facts):
    base = {"environment_names_ok": True, "platform": "linux", "unsupported_boundary": False,
            "boundary": "container", "positive_control_ok": True, "uid_ok": True, "caps_ok": True,
            "seccomp_ok": True, "no_new_privileges_ok": True, "mounts_ok": True,
            "write_probe_applicable": True, "readonly_ok": True, "cpu_limit": 1.5,
            "memory_limit_mib": 1536, "pids_limit": 256, "shm_mib": 256, "tmpfs_mib": 256,
            "resource_profile_recorded": True, "resource_limits_ok": True}
    path = evidence_dir / "host-probe-container.json"
    path.write_text(json.dumps({"schema": "host-probe-v1", "facts": {**base, **facts}}), encoding="utf-8")
    return path


def test_host_probe_output_becomes_evidence_with_resource_profile(cases, config, evidence_dir, monkeypatch):
    from isolation_tests import runner

    fake = FakeCollector()
    monkeypatch.setattr(runner, "COLLECT", fake)
    _probe_file(evidence_dir)
    outcome = _run(runner.run_case(cases["HOST-01"], "process", config, "run-host"))
    assert outcome.status == "passed", outcome
    assert outcome.details["resource_profile"] == {
        "cpu_limit": 1.5, "memory_limit_mib": 1536, "pids_limit": 256, "shm_mib": 256, "tmpfs_mib": 256}
    assert fake.calls == []


def test_windows_or_mismatched_host_probe_is_blocked(cases, config, evidence_dir, monkeypatch):
    from isolation_tests import runner

    _probe_file(evidence_dir, boundary_declared="host")
    outcome = _run(runner.run_case(cases["HOST-01"], "process", config, "run-host"))
    assert (outcome.status, outcome.reason) == ("blocked", "boundary_mismatch")


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
    first = tmp_path / "first"
    runner.main(["run", "--manifest", str(MANIFEST), "--config", str(config_file),
                 "--output", str(first), "--case", "NET-01"])
    data = _report(first)
    item = next(i for i in data["items"] if (i["case_id"], i["variant"]) == ("NET-01", "img"))
    assert item["status"] == "blocked"
    _write_evidence(evidence_dir, item["details"]["run_id"], "NET-01", "img", {
        "receiver_control_ok": True, "request_blocked": True, "receiver_observed": False})
    source = next(first.glob("isolation-report-*.json"))
    second = tmp_path / "second"
    code = runner.main(["report", "--input", str(source), "--config", str(config_file),
                        "--manifest", str(MANIFEST), "--output", str(second)])
    assert code == 2
    items = {(i["case_id"], i["variant"]): i for i in _report(second)["items"]}
    assert items[("NET-01", "img")]["status"] == "passed"
    assert items[("NET-01", "script")]["status"] == "blocked"


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
    code = runner.main(["host-probe", "--output", str(output)])
    assert code in {0, 2}
    assert json.loads(output.read_text(encoding="utf-8"))["schema"] == "host-probe-v1"
