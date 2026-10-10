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
                if name not in code_facts(case.id) and name not in rows:
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
