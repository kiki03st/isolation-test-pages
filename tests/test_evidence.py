"""Untrusted JSONL evidence must be bounded, typed, and correlated."""

import json

import pytest


def _record(**changes):
    record = {
        "run_id": "run-test", "case_id": "NET-01",
        "started_at": "2026-10-10T00:00:00Z",
        "ended_at": "2026-10-10T00:00:01Z",
        "facts": {"variant": "fetch", "positive_control_ok": True,
                  "receiver_control_ok": True, "request_blocked": True,
                  "receiver_observed": False},
        "references": [],
    }
    record.update(changes)
    return record


def _write(directory, *records):
    path = directory / "facts.jsonl"
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
    return path


def _assert_untrusted(directory, *, run_id="run-test", case_id="NET-01"):
    from isolation_tests.evidence import load_evidence

    # The interface does not prescribe exception versus empty evidence for a
    # rejected input. Either is safe; accepting the positive facts is not.
    try:
        evidence = load_evidence(directory, run_id, case_id)
    except (ValueError, OSError):
        return
    assert evidence.facts.get("positive_control_ok") is not True
    assert evidence.facts.get("request_blocked") is not True


def test_load_preserves_exact_identity_window_variant_and_actual_facts(tmp_path):
    from isolation_tests.evidence import load_evidence
    from isolation_tests.model import Evidence

    _write(tmp_path, _record())
    result = load_evidence(tmp_path, "run-test", "NET-01")
    assert isinstance(result, Evidence)
    assert (result.run_id, result.case_id) == ("run-test", "NET-01")
    assert result.started_at == "2026-10-10T00:00:00Z"
    assert result.ended_at == "2026-10-10T00:00:01Z"
    assert result.facts == _record()["facts"]


def test_utc_explicit_zero_offset_is_valid(tmp_path):
    from isolation_tests.evidence import load_evidence

    _write(tmp_path, _record(started_at="2026-10-10T00:00:00+00:00",
                             ended_at="2026-10-10T00:00:01+00:00"))
    assert load_evidence(tmp_path, "run-test", "NET-01").facts["variant"] == "fetch"


@pytest.mark.parametrize("changes", [
    {"run_id": "run-old"}, {"run_id": "run-test-extra"},
    {"case_id": "NET-02"}, {"case_id": "NET-010"},
])
def test_other_runs_and_cases_never_supply_positive_facts(tmp_path, changes):
    _write(tmp_path, _record(**changes))
    _assert_untrusted(tmp_path)


def test_stale_rows_cannot_override_matching_facts(tmp_path):
    from isolation_tests.evidence import load_evidence

    actual = _record(facts={"variant": "fetch", "receiver_observed": True})
    _write(tmp_path, actual, _record(run_id="run-old"), _record(case_id="NET-02"))
    result = load_evidence(tmp_path, "run-test", "NET-01")
    assert result.facts["receiver_observed"] is True
    assert "positive_control_ok" not in result.facts


def test_explicit_variant_selects_exact_matching_rows(tmp_path):
    from isolation_tests.evidence import load_evidence

    other = _record(facts={"variant": "img", "receiver_observed": True})
    _write(tmp_path, other, _record())
    result = load_evidence(tmp_path, "run-test", "NET-01", variant="fetch")
    assert result.facts == _record()["facts"]


def test_explicit_variant_cannot_use_a_different_variant(tmp_path):
    from isolation_tests.evidence import load_evidence

    _write(tmp_path, _record())
    try:
        result = load_evidence(tmp_path, "run-test", "NET-01", variant="img")
    except (ValueError, OSError):
        return
    assert result.facts.get("request_blocked") is not True


def test_three_argument_loader_rejects_ambiguous_variants(tmp_path):
    _write(tmp_path, _record(), _record(facts={**_record()["facts"], "variant": "img"}))
    _assert_untrusted(tmp_path)


@pytest.mark.parametrize("changes", [
    {"started_at": "2026-10-10T00:00:00"},
    {"started_at": "2026-10-10T09:00:00+09:00"},
    {"started_at": "not-a-time"}, {"started_at": None},
    {"ended_at": "2026-10-09T23:59:59Z"},
    {"ended_at": "2026-10-10T00:00:01"},
])
def test_invalid_or_non_utc_windows_cannot_supply_facts(tmp_path, changes):
    _write(tmp_path, _record(**changes))
    _assert_untrusted(tmp_path)


@pytest.mark.parametrize("facts", [
    {}, {"positive_control_ok": True},
    {"variant": "", "positive_control_ok": True},
    {"variant": 42, "positive_control_ok": True},
    {"variant": "../fetch", "positive_control_ok": True},
])
def test_missing_or_invalid_variant_is_not_correlated_evidence(tmp_path, facts):
    _write(tmp_path, _record(facts=facts))
    _assert_untrusted(tmp_path)


@pytest.mark.parametrize("key,value", [
    ("positive_control_ok", "true"), ("receiver_control_ok", 1),
    ("request_blocked", []), ("receiver_observed", "false"),
    ("remote_job_terminated", 1), ("children_remaining", False),
    ("children_remaining", -1), ("download_temporary_bytes", "0"),
    ("download_remaining_bytes", -1), ("inspected_regions", "document"),
    ("unknown_regions", [False]), ("sandbox_ok", {"ok": True}),
    ("clock_offset_seconds", True), ("clock_offset_seconds", "0.2"),
    ("clock_offset_seconds", float("inf")), ("clock_offset_seconds", float("nan")),
])
def test_malformed_authoritative_fact_types_are_untrusted(tmp_path, key, value):
    facts = {**_record()["facts"], key: value}
    _write(tmp_path, _record(facts=facts))
    _assert_untrusted(tmp_path)


@pytest.mark.parametrize("payload", [
    b'[]\n', b'null\n', b'{"run_id":', b'\xff\n',
    b'{"run_id":"run-test","run_id":"run-old"}\n',
])
def test_malformed_jsonl_and_duplicate_fields_never_supply_facts(tmp_path, payload):
    (tmp_path / "facts.jsonl").write_bytes(payload)
    _assert_untrusted(tmp_path)


def test_missing_directory_or_records_never_invent_facts(tmp_path):
    _assert_untrusted(tmp_path)
    _assert_untrusted(tmp_path / "missing")


def test_each_jsonl_file_is_limited_to_one_mib(tmp_path):
    path = _write(tmp_path, _record())
    with path.open("ab") as stream:
        stream.write(b" " * (1048577 - path.stat().st_size))
    assert path.stat().st_size == 1048577
    _assert_untrusted(tmp_path)


def test_one_mib_file_is_inside_the_limit(tmp_path):
    from isolation_tests.evidence import load_evidence

    path = _write(tmp_path, _record())
    # Whitespace is valid after the record; the limit is bytes, not line count.
    with path.open("ab") as stream:
        stream.write(b" " * (1048576 - path.stat().st_size))
    assert path.stat().st_size == 1048576
    assert load_evidence(tmp_path, "run-test", "NET-01").facts["request_blocked"] is True


@pytest.mark.parametrize("run_id,case_id", [
    ("../run-test", "NET-01"), ("run-test", "../NET-01"),
    ("run-test/../../outside", "NET-01"), ("run\nunsafe", "NET-01"),
])
def test_correlation_ids_cannot_escape_evidence_directory(tmp_path, run_id, case_id):
    _write(tmp_path, _record())
    _assert_untrusted(tmp_path, run_id=run_id, case_id=case_id)


@pytest.mark.parametrize("reference", ["../outside.jsonl", "/outside.jsonl", "C:/outside.jsonl"])
def test_evidence_references_cannot_escape_root(tmp_path, reference):
    _write(tmp_path, _record(references=[reference]))
    _assert_untrusted(tmp_path)


def test_jsonl_directory_is_not_treated_as_regular_evidence(tmp_path):
    (tmp_path / "facts.jsonl").mkdir()
    _assert_untrusted(tmp_path)


def test_loader_never_follows_symlink_outside_root(tmp_path):
    outside = tmp_path.parent / (tmp_path.name + "-outside.jsonl")
    outside.write_text(json.dumps(_record()) + "\n", encoding="utf-8")
    try:
        (tmp_path / "facts.jsonl").symlink_to(outside)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"Windows symlink privilege unavailable: {error}")
    _assert_untrusted(tmp_path)


# Implementer additions (Task 9): receiver events carry no variant and are
# forgeable by anyone knowing the run_id, so correlation is conservative.

def _event(at, *, run_id="run-test", case_id="NET-01"):
    return {"at": at, "case_id": case_id, "run_id": run_id, "method": "GET",
            "path": f"/v1/receive/{case_id}", "bytes_sent": 0}


def _trial(**facts):
    from isolation_tests.model import Evidence

    return Evidence("run-test", "NET-01", "2026-10-10T00:00:00Z", "2026-10-10T00:00:05Z",
                    {"variant": "fetch", **facts})


def test_no_receiver_event_is_only_absence_not_block_proof():
    from isolation_tests.evidence import receiver_observed

    assert receiver_observed(_trial(), ()) is False


@pytest.mark.parametrize("at", ["2026-10-10T00:00:02+00:00", "2026-10-10T09:00:06+09:00",
                                "2026-10-09T23:59:59+00:00"])
def test_receiver_event_inside_window_with_one_second_slack_is_observed(at):
    from isolation_tests.evidence import receiver_observed

    assert receiver_observed(_trial(), (_event(at),)) is True


@pytest.mark.parametrize("events", [
    (_event("2026-10-10T00:00:07+00:00"),),
    (_event("2026-10-09T23:59:58+00:00"),),
    (_event("2026-10-10T00:00:02+00:00"), _event("2026-10-10T01:00:00+00:00")),
    (_event("2026-10-10T00:00:02+00:00", run_id="run-other"),),
    (_event("2026-10-10T00:00:02+00:00", case_id="NET-02"),),
    (_event("2026-10-10T00:00:02"),),
])
def test_out_of_window_or_foreign_receiver_events_prove_nothing(events):
    from isolation_tests.evidence import receiver_observed

    assert receiver_observed(_trial(), events) is None


@pytest.mark.parametrize("offset", [1.5, -2, True, "0"])
def test_receiver_correlation_needs_aligned_clocks(offset):
    from isolation_tests.evidence import receiver_observed

    assert receiver_observed(_trial(clock_offset_seconds=offset), ()) is None


def test_unapproved_fact_names_and_host_fact_types_are_rejected():
    from isolation_tests.evidence import EvidenceUnavailable, validate_facts

    validate_facts({"variant": "fetch", "uid_ok": True, "boundary": "container"})
    for bad in ({"api_token": "x"}, {"uid_ok": 1}, {"boundary": "Bearer secret"},
                {"seccomp_ok": "true"}, {"memory_limit_mib": True}, {"evidence_source": "me"}):
        with pytest.raises(EvidenceUnavailable):
            validate_facts({"variant": "fetch", **bad})
