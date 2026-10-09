"""Host probe: names only, Linux only, and a strict administrator evidence contract."""

import json
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1] / "tools" / "isolation-tests"
SECRET = "synthetic-value-do-not-export"
DIGEST = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64


def test_environment_values_are_never_in_facts(monkeypatch):
    from isolation_tests.host_probes import collect_host_facts
    monkeypatch.setenv('SYNTHETIC_API_KEY', 'synthetic-value-do-not-export')
    facts = collect_host_facts()
    assert 'synthetic-value-do-not-export' not in str(facts)
    assert facts['environment_names_ok'] is False


@pytest.mark.parametrize("names,expected", [
    (["PATH", "HOME"], True),
    (["AWS_REGION"], False),
    (["OPENAI_API_KEY"], False),
    (["ISOLATION_TOKEN"], False),
    (["KAKAO_SKILL_SECRET"], False),
    (["MY_API_KEYS"], True),
])
def test_environment_names_ok(names, expected):
    from isolation_tests.host_probes import environment_names_ok
    assert environment_names_ok(names) is expected


def test_non_linux_is_unsupported_boundary_with_no_invented_facts(monkeypatch):
    from isolation_tests import host_probes
    monkeypatch.setattr(host_probes, "_platform", lambda: "win32")
    facts = host_probes.collect_host_facts()
    assert facts["unsupported_boundary"] is True
    for name in ("uid_ok", "caps_ok", "seccomp_ok", "no_new_privileges_ok", "readonly_ok", "mounts_ok"):
        assert name not in facts


STATUS_OK = "Name:\tx\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n"
MOUNTS_OK = "overlay / overlay ro,relatime 0 0\ntmpfs /tmp tmpfs rw 0 0\n"


def linux(monkeypatch, status=STATUS_OK, mounts=MOUNTS_OK, uid=1000, write=True):
    from isolation_tests import host_probes
    monkeypatch.setattr(host_probes, "_platform", lambda: "linux")
    monkeypatch.setattr(host_probes, "_detect_boundary", lambda: "container")
    monkeypatch.setattr(host_probes, "_read_text", lambda p: {
        host_probes.PROC_STATUS: status, host_probes.PROC_MOUNTS: mounts}.get(p))
    monkeypatch.setattr(os, "getuid", lambda: uid, raising=False)
    monkeypatch.setattr(host_probes, "_write_probe", lambda: write)
    return host_probes.collect_host_facts()


def test_linux_hardened_process_facts(monkeypatch):
    facts = linux(monkeypatch)
    assert facts["boundary"] == "container" and facts["unsupported_boundary"] is False
    for name in ("uid_ok", "caps_ok", "seccomp_ok", "no_new_privileges_ok", "mounts_ok",
                 "readonly_ok", "positive_control_ok"):
        assert facts[name] is True, name


def test_linux_weak_process_facts(monkeypatch):
    status = "CapPrm:\t00000000a80425fb\nCapEff:\t00000000a80425fb\nNoNewPrivs:\t0\nSeccomp:\t0\n"
    facts = linux(monkeypatch, status=status, mounts="overlay / overlay rw 0 0\n", uid=0, write=False)
    for name in ("uid_ok", "caps_ok", "seccomp_ok", "no_new_privileges_ok", "mounts_ok", "readonly_ok"):
        assert facts[name] is False, name


def test_runtime_socket_mount_fails_mounts(monkeypatch):
    facts = linux(monkeypatch, mounts=MOUNTS_OK + "tmpfs /var/run/docker.sock tmpfs rw 0 0\n")
    assert facts["mounts_ok"] is False


def test_unreadable_proc_omits_facts(monkeypatch):
    facts = linux(monkeypatch, status=None, mounts=None)
    for name in ("uid_ok", "caps_ok", "mounts_ok", "positive_control_ok"):
        assert name not in facts


def test_write_probe_touches_only_its_one_path(monkeypatch, tmp_path):
    from isolation_tests import host_probes
    probe = tmp_path / "isolation-test-write-probe"
    neighbour = tmp_path / "keep.txt"
    neighbour.write_text("keep")
    monkeypatch.setattr(host_probes, "WRITE_PROBE_PATH", probe)
    assert host_probes._write_probe() is False  # creation succeeded -> not read-only
    assert not probe.exists() and neighbour.read_text() == "keep"
    monkeypatch.setattr(host_probes, "WRITE_PROBE_PATH", tmp_path / "missing-dir" / "p")
    assert host_probes._write_probe() is None


def test_write_probe_never_removes_a_preexisting_file(monkeypatch, tmp_path):
    from isolation_tests import host_probes
    probe = tmp_path / "isolation-test-write-probe"
    probe.write_text("operator data")
    monkeypatch.setattr(host_probes, "WRITE_PROBE_PATH", probe)
    assert host_probes._write_probe() is None
    assert probe.read_text() == "operator data"


def test_cli_host_probe_writes_names_only_and_refuses_overwrite(tmp_path, monkeypatch, capsys):
    from isolation_tests.runner import main
    monkeypatch.setenv("SYNTHETIC_API_KEY", SECRET)
    out = tmp_path / "probe.json"
    code = main(["host-probe", "--output", str(out)])
    assert code in (0, 3)
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["schema"] == "host-probe-v1" and data["facts"]["environment_names_ok"] is False
    assert SECRET not in out.read_text(encoding="utf-8") and SECRET not in capsys.readouterr().out
    assert main(["host-probe", "--output", str(out)]) == 2


# --- evidence contract -------------------------------------------------------

def ev(case_id, **facts):
    from isolation_tests.model import Evidence
    return Evidence("example-run", case_id, "2026-01-01T00:00:00Z", "2026-01-01T00:00:05Z", facts, ())


def check(case_id, **facts):
    from isolation_tests.host_probes import validate_host_evidence
    return validate_host_evidence(case_id, ev(case_id, **facts))


def digest_facts(**over):
    base = dict(variant="digest", digest_ok=True, observed_digest=DIGEST, approved_digest=DIGEST,
                observed_digest_kind="image_manifest", approved_digest_kind="image_manifest",
                observed_digest_platform="linux/amd64", approved_digest_platform="linux/amd64")
    return base | over


def test_example_evidence_records_validate():
    data = json.loads((ROOT / "evidence.example.json").read_text(encoding="utf-8"))
    for record in data["records"]:
        result = check(record["case_id"], **record["facts"])
        assert result.status == "passed", (record["case_id"], result.reason)


def test_windows_probe_is_unsupported_boundary():
    result = check("HOST-01", variant="process", platform="windows", unsupported_boundary=True)
    assert (result.status, result.reason) == ("blocked", "unsupported_boundary")


def test_host_boundary_is_not_accepted_for_container_claims():
    result = check("HOST-02", variant="environment", boundary="host", environment_names_ok=True)
    assert (result.status, result.reason) == ("blocked", "wrong_boundary")
    assert check("HOST-02", variant="environment", boundary="container",
                 environment_names_ok=True).status == "passed"


def test_self_reported_sandbox_is_blocked():
    base = dict(variant="sandbox", boundary="container", sandbox_ok=True)
    assert check("HOST-01", **base, evidence_source="self_reported").reason == "self_reported_only"
    assert check("HOST-01", **base).reason == "self_reported_only"
    assert check("HOST-01", **base, evidence_source="observed").status == "passed"


def test_digest_match_passes_and_mismatch_fails():
    assert check("HOST-03", **digest_facts()).status == "passed"
    result = check("HOST-03", **digest_facts(observed_digest=OTHER))
    assert (result.status, result.reason) == ("failed", "digest_mismatch")


def test_digest_kind_or_platform_mismatch_is_not_comparable():
    for over in ({"observed_digest_kind": "image_index"},
                 {"observed_digest_platform": "linux/arm64"},
                 {"observed_digest_kind": "container_id"},
                 {"approved_digest_kind": "container_id"}):
        result = check("HOST-03", **digest_facts(**over))
        assert (result.status, result.reason) == ("blocked", "digest_kind_not_comparable"), over


def test_digest_evidence_missing_is_blocked():
    facts = digest_facts()
    del facts["approved_digest"]
    assert check("HOST-03", **facts).reason == "digest_evidence_missing"


def rec(**over):
    base = dict(variant="replacement", replacement_kind="new_instance", replacement_ok=True,
                credentials_rotated=True, old_credentials_rejected=True, recovery_ok=True,
                followup_run_id="example-followup-run")
    return base | over


def test_replacement_requires_a_new_instance():
    assert check("REC-01", **rec()).status == "passed"
    for kind in ("restart", "reboot"):
        result = check("REC-01", **rec(replacement_kind=kind))
        assert (result.status, result.reason) == ("blocked", "replacement_not_demonstrated")
    assert check("REC-01", variant="replacement", replacement_ok=True).status == "blocked"


def test_recovery_needs_followup_run_reference():
    facts = rec()
    del facts["followup_run_id"]
    assert check("REC-01", **facts).reason == "followup_run_missing"


def test_block_claims_need_positive_control_and_observation():
    base = dict(variant="tcp", boundary="container", request_blocked=True, probe_in_container=True)
    assert check("NET-05", **base).reason == "missing_positive_control"
    assert check("NET-05", **base, positive_control_ok=True).status == "passed"
    assert check("NET-05", **base, positive_control_ok=True,
                 evidence_source="self_reported").reason == "self_reported_only"
    denied = dict(variant="denied-source", source_denied=True)
    assert check("INT-02", **denied).reason == "missing_positive_control"


def test_kakao_receipt_needs_observed_admin_evidence():
    assert check("INT-03", variant="kakao-receipt").reason == "kakao_receipt_missing"
    assert check("INT-03", variant="kakao-receipt", kakao_received=True).reason == "self_reported_only"
    assert check("INT-03", variant="kakao-receipt", kakao_received=True,
                 evidence_source="observed").status == "passed"


def test_secret_values_and_unapproved_keys_are_rejected_without_echo():
    token = "Bearer " + SECRET
    for facts in (
        dict(variant="digest", observed_digest=token),
        dict(variant="digest", boundary=token),
        dict(variant="digest", api_token=SECRET),
        dict(variant="digest", environment_names_ok=SECRET),
        {"variant": "digest", "AWS_SECRET": SECRET},
    ):
        result = check("HOST-03", **facts)
        assert result.status == "blocked" and result.reason in {"unapproved_value", "unapproved_fact"}
        assert SECRET not in repr(result)


def test_unknown_case_variant_and_mismatched_case_are_blocked():
    assert check("COL-01", variant="default").reason == "unsupported_case"
    assert check("HOST-03", variant="nope").reason == "unknown_variant"
    from isolation_tests.host_probes import validate_host_evidence
    assert validate_host_evidence("HOST-03", ev("HOST-01", variant="digest")).reason == "unsupported_case"
