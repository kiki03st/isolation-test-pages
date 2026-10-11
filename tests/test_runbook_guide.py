"""Every required fact is produced by code or documented in the runbook evidence guide."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNBOOK = ROOT / "docs" / "runbook.md"
PACKAGE = ROOT / "tools" / "isolation-tests" / "isolation_tests"


def _guide_rows() -> dict[str, str]:
    text = RUNBOOK.read_text(encoding="utf-8")
    section = text.split("## 8. 증거 생산 안내", 1)[1]
    return {match.group(1): match.group(2)
            for match in re.finditer(r"^\| `([a-z][a-z0-9_]*)` \| ([^|]+) \|", section, re.MULTILINE)}


def test_every_required_fact_is_code_emitted_or_in_the_guide():
    from isolation_tests.manifest import load_cases
    from isolation_tests.runner import CANONICAL_MANIFEST, _required, code_facts

    rows = _guide_rows()
    missing = []
    for case in load_cases(CANONICAL_MANIFEST):
        for variant in case.variants:
            for name in _required(case, variant):
                if name not in code_facts(case.id, variant) and name not in rows:
                    missing.append(f"{case.id}/{variant}:{name}")
    assert missing == []


def test_guide_lists_every_admin_fact_with_each_case_it_serves():
    from isolation_tests.manifest import load_cases
    from isolation_tests.runner import CANONICAL_MANIFEST, admin_facts

    rows = _guide_rows()
    facts = admin_facts(load_cases(CANONICAL_MANIFEST))
    assert set(facts) <= set(rows)
    for name, entries in facts.items():
        for entry in entries:
            case_id, variant = entry.split("/")
            assert re.search(rf"{case_id} \([^)]*\b{re.escape(variant)}\b", rows[name]), entry


def test_guide_rows_name_only_approved_facts():
    from isolation_tests.evidence import APPROVED_FACTS

    assert set(_guide_rows()) <= APPROVED_FACTS


def test_declared_runner_facts_cover_what_the_runner_writes():
    from isolation_tests.runner import AI_FACTS, RUNNER_FACTS

    runner = (PACKAGE / "runner.py").read_text(encoding="utf-8")
    written = set(re.findall(r'obs\.facts\["([a-z_]+)"\]', runner))
    written |= set(re.findall(r'facts\["(limit_exceeded_confirmed|concurrency_limit_ok)"\]', runner))
    assert written <= RUNNER_FACTS
    ai = (PACKAGE / "adapters" / "ai.py").read_text(encoding="utf-8")
    assert set(re.findall(r'details\["facts"\]\["([a-z_]+)"\]', ai)) <= AI_FACTS


def test_declared_probe_facts_cover_what_the_probe_writes(monkeypatch):
    import os

    from isolation_tests import host_probes
    from isolation_tests.runner import PROBE_FACTS

    monkeypatch.setattr(host_probes, "_platform", lambda: "linux")
    monkeypatch.setattr(host_probes, "_detect_boundary", lambda: "container")
    status = "CapPrm:\t0\nCapEff:\t0\nNoNewPrivs:\t1\nSeccomp:\t2\n"
    mountinfo = "1 0 0:1 / / ro - overlay overlay ro\n"
    mounts = "tmpfs /dev/shm tmpfs rw,size=262144k 0 0\ntmpfs /tmp tmpfs rw,size=262144k 0 0\n"
    cgroup = {"memory.max": "1610612736\n", "pids.max": "256\n", "cpu.max": "150000 100000\n"}
    monkeypatch.setattr(host_probes, "_read_text", lambda p: {
        host_probes.PROC_STATUS: status, host_probes.PROC_MOUNTINFO: mountinfo,
        host_probes.PROC_MOUNTS: mounts}.get(p, cgroup.get(p.name)))
    monkeypatch.setattr(host_probes, "_socket_under", lambda path: False)
    monkeypatch.setattr(host_probes, "_write_probe", lambda: True)
    monkeypatch.setattr(os, "getuid", lambda: 1000, raising=False)
    facts = host_probes.collect_host_facts(boundary="container")
    assert set(facts) <= PROBE_FACTS


# --- residual #9: a fact is "code-made" for a case only if code really emits it there ----

_ALL_BASES = ("pages", "http_fixture", "forbidden_receiver", "private", "loopback", "link_local",
              "main_public", "isolation_public", "shared_ip_host", "same_host_path")


def _ai_facts(case_id):
    """What the AI adapter records per case (adapters/ai.py): analysis, plus per-case extras."""
    facts = {"analysis": True}
    if case_id == "ANA-08":
        facts["fabricated_evidence_rejected"] = True
    if case_id == "INT-04":
        facts["fallback_ok"] = True
    if case_id == "LIM-04":
        facts.update(boundary_offsets=[-1, 0, 1], boundary_limit=1, boundary_results_ok=True)
    return facts


def _emitted(case, variant, tmp_path, monkeypatch):
    """Every fact the runner path records for one variant when every adapter succeeds."""
    import asyncio
    from datetime import datetime, timedelta, timezone

    from isolation_tests import runner
    from isolation_tests.config import DEFAULT_LIMITS
    from isolation_tests.model import CollectedPage, Evidence, Outcome, RuntimeConfig
    from isolation_tests.receiver import RECEIVER_CASES, write_receiver_event

    evidence = tmp_path / f"evidence-{case.id}-{variant}"
    evidence.mkdir()
    ca = tmp_path / "ca.pem"
    ca.write_text("synthetic", encoding="utf-8")
    caps = {name for c in runner._canonical().values() for name in c.required_capabilities}
    for c in runner._canonical().values():
        for v in c.variants:
            caps |= set(runner._contract(c, v).get("required_capabilities", ()))
    monkeypatch.setenv("GUIDE_TOKEN", "synthetic-guide-token")
    config = RuntimeConfig(
        bases={key: f"https://{key.replace('_', '-')}.example.invalid/" for key in _ALL_BASES},
        collector_url="https://collector.example.invalid/collect", token_env="GUIDE_TOKEN",
        ca_file=ca, limits={**DEFAULT_LIMITS, "collector_concurrency": 3},
        capabilities=frozenset(caps), evidence_dir=evidence, backend_contract=None)

    def now(offset=0):
        return (datetime.now(timezone.utc) + timedelta(seconds=offset)).isoformat()

    def control(case_id, run_id):
        write_receiver_event(evidence / "receiver-guide.jsonl", case_id=case_id, run_id=run_id,
                             method="GET", fixed_path=f"/v1/control/{case_id}", bytes_sent=2, at=now())

    async def collect(config, url, token_mode="valid"):
        return CollectedPage(url, url, (), 200, "text/html", "<title>수집 기준</title>배송 상태: 배송 중",
                             "수집 기준", 10, ())

    async def analyze(case, variant, page, client=None):
        return Outcome(case.id, variant, "passed", "analysis_expectations_met",
                       {"verdict": "same", "accepted_codes": [], "failure_codes": ["llm_timeout"],
                        "facts": _ai_facts(case.id)})

    async def backend(case, config, run_id):
        return Outcome(case.id, "x", "passed", "backend_result_linked", {"first_response_deadline_ok": True})

    async def send(config, case_id, variant, run_id):
        control(case_id, run_id)
        return "sent"

    for name, fake in (("COLLECT", collect), ("ANALYZE", analyze), ("PROBE_BACKEND", backend),
                       ("SEND_CONTROL", send)):
        monkeypatch.setattr(runner, name, fake, raising=False)
    run_id = runner.new_run_id()
    obs = asyncio.run(runner.observe(case, variant, config, run_id))
    admin = None
    if not obs.actions:  # evidence-only: the administrator sends the control in their window
        admin = Evidence(run_id, case.id, now(-5).replace("+00:00", "Z"), now(60).replace("+00:00", "Z"),
                         {"variant": variant})
        if case.id in RECEIVER_CASES:
            control(case.id, run_id)
    receiver, _ = runner._receiver_facts(case, variant, obs, admin, config, {})
    return set(obs.facts) | set(receiver or {})


def test_code_made_facts_are_really_emitted_for_every_case_that_requires_them(tmp_path, monkeypatch):
    from isolation_tests.manifest import load_cases
    from isolation_tests.runner import CANONICAL_MANIFEST, PROBE_CASES, _required, code_facts

    missing = []
    for case in load_cases(CANONICAL_MANIFEST):
        if case.id in PROBE_CASES:  # host-probe output; see the probe test below
            continue
        for variant in case.variants:
            claimed = code_facts(case.id, variant) & _required(case, variant)
            for name in sorted(claimed - _emitted(case, variant, tmp_path, monkeypatch)):
                missing.append(f"{case.id}/{variant}:{name}")
    assert missing == []


def test_lim03_limit_exceeded_confirmed_is_an_admin_fact_in_the_guide():
    from isolation_tests.runner import code_facts

    assert "limit_exceeded_confirmed" not in code_facts("LIM-03")
    assert "limit_exceeded_confirmed" in code_facts("LIM-06")
    assert re.search(r"LIM-03 \(large length-small length-large gzip\)", _guide_rows()["limit_exceeded_confirmed"])


def test_guide_table_rows_have_exactly_five_cells():
    text = RUNBOOK.read_text(encoding="utf-8").split("### 8-3.", 1)[1]
    rows = [line for line in text.splitlines() if line.startswith("| `")]
    assert rows
    for row in rows:
        cells = re.split(r"(?<!\\)\|", row.strip())[1:-1]  # an escaped \| stays inside its cell
        assert len(cells) == 5, row
