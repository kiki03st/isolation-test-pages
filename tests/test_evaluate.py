"""Actual observations, never expected defaults, determine each variant result."""

from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from isolation_tests.model import CollectedPage, Evidence, Outcome


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def cases():
    from isolation_tests.manifest import load_cases

    return {case.id: case for case in load_cases(ROOT / "tools/isolation-tests/cases.json")}


@pytest.fixture
def case_net01(cases):
    return cases["NET-01"]


@pytest.fixture
def limit_case(cases):
    return cases["LIM-01"]


@pytest.fixture
def recovered_facts():
    return _evidence("LIM-01", "delay-15s", {
        "positive_control_ok": True, "remote_job_terminated": True,
        "children_remaining": 0, "recovery_ok": True,
    })


def _caps(case, variant):
    # Capabilities are explicitly supplied declarations; facts are never filled
    # from the manifest's required_facts expectations.
    per_variant = case.expected_observations["variants"][variant]
    return frozenset((*case.required_capabilities, *per_variant["required_capabilities"]))


def _evidence(case_id, variant, facts, *, ended_at="2026-10-10T00:00:01Z"):
    return Evidence("run-test", case_id, "2026-10-10T00:00:00Z", ended_at,
                    {"variant": variant, **facts})


def _network_facts():
    return {"positive_control_ok": True, "receiver_control_ok": True,
            "request_blocked": True, "receiver_observed": False}


def _limit_facts():
    return {"positive_control_ok": True, "remote_job_terminated": True,
            "children_remaining": 0, "recovery_ok": True,
            "collector_deadline_s": 12, "deadline_grace_s": 1, "deadline_met": True}


def _page(**changes):
    page = CollectedPage("https://pages.example.invalid/project/col-01", None, (),
                         200, "text/html", "배송 상태: 배송 중 📦", "수집 기준", 100, ())
    return replace(page, **changes)


def _run(case, variant, facts, page=None, *, capabilities=None, ended_at="2026-10-10T00:00:01Z"):
    from isolation_tests.evaluate import evaluate

    result = evaluate(case, variant, page, _evidence(case.id, variant, facts, ended_at=ended_at),
                      _caps(case, variant) if capabilities is None else capabilities)
    assert (result.case_id, result.variant) == (case.id, variant)
    assert result.reason
    return result


def test_console_cors_is_not_network_block(case_net01):
    assert _run(case_net01, "fetch", {"console_error": "CORS"}).status == "blocked"


def test_actual_app_block_with_both_controls_and_no_receiver_request_passes(case_net01):
    # An application pre-send block does not require a firewall-drop counter.
    assert _run(case_net01, "fetch", _network_facts()).status == "passed"


@pytest.mark.parametrize("missing", [
    "positive_control_ok", "receiver_control_ok", "request_blocked", "receiver_observed",
])
def test_every_network_observation_is_required(case_net01, missing):
    facts = _network_facts()
    del facts[missing]
    assert _run(case_net01, "fetch", facts).status == "blocked"


@pytest.mark.parametrize("control", ["positive_control_ok", "receiver_control_ok"])
def test_failed_positive_controls_block_isolation_claim(case_net01, control):
    assert _run(case_net01, "fetch", {**_network_facts(), control: False}).status == "blocked"


def test_forbidden_request_observed_is_failure_even_with_cors_and_block_claim(case_net01):
    facts = {**_network_facts(), "receiver_observed": True, "console_error": "CORS"}
    assert _run(case_net01, "fetch", facts).status == "failed"


@pytest.mark.parametrize("key,value", [
    ("positive_control_ok", "true"), ("receiver_control_ok", 1),
    ("request_blocked", 1), ("receiver_observed", 0),
])
def test_truthy_values_do_not_substitute_for_actual_boolean_facts(case_net01, key, value):
    assert _run(case_net01, "fetch", {**_network_facts(), key: value}).status == "blocked"


@pytest.mark.parametrize("variant", [None, "img", "missing"])
def test_missing_or_other_variant_evidence_is_blocked(case_net01, variant):
    from isolation_tests.evaluate import evaluate

    facts = _network_facts()
    if variant is not None:
        facts["variant"] = variant
    evidence = Evidence("run-test", "NET-01", "2026-10-10T00:00:00Z",
                        "2026-10-10T00:00:01Z", facts)
    assert evaluate(case_net01, "fetch", None, evidence, _caps(case_net01, "fetch")).status == "blocked"


def test_wrong_case_evidence_is_blocked(case_net01):
    from isolation_tests.evaluate import evaluate

    evidence = _evidence("NET-02", "fetch", _network_facts())
    assert evaluate(case_net01, "fetch", None, evidence, _caps(case_net01, "fetch")).status == "blocked"


@pytest.mark.parametrize("offset", [-1.01, 1.01])
def test_clock_difference_over_one_second_blocks_timing_comparison(case_net01, offset):
    facts = {**_network_facts(), "clock_offset_seconds": offset}
    assert _run(case_net01, "fetch", facts).status == "blocked"


@pytest.mark.parametrize("offset", [-1.0, 0.0, 1.0])
def test_clock_difference_within_one_second_does_not_block_valid_evidence(case_net01, offset):
    facts = {**_network_facts(), "clock_offset_seconds": offset}
    assert _run(case_net01, "fetch", facts).status == "passed"


@pytest.mark.parametrize("offset", [True, "0.1", float("inf"), float("nan")])
def test_malformed_clock_offset_cannot_prove_aligned_observation(case_net01, offset):
    facts = {**_network_facts(), "clock_offset_seconds": offset}
    assert _run(case_net01, "fetch", facts).status == "blocked"


@pytest.mark.parametrize("started_at,ended_at", [
    ("2026-10-10T00:00:00", "2026-10-10T00:00:01Z"),
    ("2026-10-10T00:00:00Z", "2026-10-09T23:59:59Z"),
    ("invalid", "2026-10-10T00:00:01Z"),
])
def test_invalid_observation_windows_are_blocked(case_net01, started_at, ended_at):
    from isolation_tests.evaluate import evaluate

    evidence = replace(_evidence("NET-01", "fetch", _network_facts()),
                       started_at=started_at, ended_at=ended_at)
    assert evaluate(case_net01, "fetch", None, evidence, _caps(case_net01, "fetch")).status == "blocked"


@pytest.mark.parametrize("missing", ["firewall_drop_observed", "probe_in_container"])
def test_firewall_requires_drop_and_inside_boundary_evidence(cases, missing):
    facts = {**_network_facts(), "firewall_drop_observed": True, "probe_in_container": True}
    del facts[missing]
    assert _run(cases["NET-05"], "tcp", facts).status == "blocked"


def test_actual_inside_boundary_firewall_drop_passes(cases):
    facts = {**_network_facts(), "firewall_drop_observed": True, "probe_in_container": True}
    assert _run(cases["NET-05"], "tcp", facts).status == "passed"


def test_runner_timeout_without_remote_termination_is_blocked(limit_case):
    facts = {"positive_control_ok": True, "runner_timeout": True}
    assert _run(limit_case, "delay-15s", facts, _page(failures=("timeout",))).status == "blocked"


def test_recovered_facts_do_not_manufacture_missing_deadline_observations(limit_case, recovered_facts):
    from isolation_tests.evaluate import evaluate

    assert evaluate(limit_case, "delay-15s", _page(failures=("timeout",)), recovered_facts,
                    _caps(limit_case, "delay-15s")).status == "blocked"


@pytest.mark.parametrize("missing", [
    "remote_job_terminated", "children_remaining", "recovery_ok", "collector_deadline_s",
    "deadline_grace_s", "deadline_met",
])
def test_limit_requires_actual_remote_cleanup_deadline_and_recovery(limit_case, missing):
    facts = _limit_facts()
    del facts[missing]
    assert _run(limit_case, "delay-15s", facts, _page(failures=("timeout",))).status == "blocked"


@pytest.mark.parametrize("key,value", [
    ("remote_job_terminated", False), ("children_remaining", 1),
    ("recovery_ok", False), ("deadline_met", False),
])
def test_observed_termination_cleanup_recovery_or_deadline_failure_fails(limit_case, key, value):
    facts = {**_limit_facts(), key: value}
    assert _run(limit_case, "delay-15s", facts, _page(failures=("timeout",))).status == "failed"


def test_remote_deadline_cleanup_and_recovery_evidence_passes(limit_case):
    result = _run(limit_case, "delay-15s", _limit_facts(),
                  _page(elapsed_ms=13000, failures=("timeout",)),
                  ended_at="2026-10-10T00:00:13Z")
    assert result.status == "passed"


@pytest.mark.parametrize("value", [False, "0", -1])
def test_malformed_child_count_does_not_prove_cleanup(limit_case, value):
    assert _run(limit_case, "delay-15s", {**_limit_facts(), "children_remaining": value},
                _page(failures=("timeout",))).status == "blocked"


def _download_facts():
    return {"download_attempt_observed": True, "download_temporary_bytes": 0,
            "download_remaining_bytes": 0, "remote_job_terminated": True, "file_executed": False}


def test_download_attempt_with_no_temporary_or_remaining_bytes_passes(cases):
    assert _run(cases["DL-02"], "attachment", _download_facts(),
                _page(content_type="application/octet-stream")).status == "passed"


@pytest.mark.parametrize("field", ["download_temporary_bytes", "download_remaining_bytes"])
def test_any_download_storage_fails_even_if_later_deleted(cases, field):
    facts = {**_download_facts(), field: 1}
    assert _run(cases["DL-02"], "attachment", facts,
                _page(content_type="application/octet-stream")).status == "failed"


@pytest.mark.parametrize("field", ["download_temporary_bytes", "download_remaining_bytes"])
def test_missing_download_observation_is_not_assumed_zero(cases, field):
    facts = _download_facts()
    del facts[field]
    assert _run(cases["DL-02"], "attachment", facts,
                _page(content_type="application/octet-stream")).status == "blocked"


@pytest.mark.parametrize("field", ["download_temporary_bytes", "download_remaining_bytes"])
def test_boolean_false_cannot_prove_zero_download_bytes(cases, field):
    facts = {**_download_facts(), field: False}
    assert _run(cases["DL-02"], "attachment", facts,
                _page(content_type="application/octet-stream")).status == "blocked"


@pytest.mark.parametrize("missing", ["collector", "rendering", "open_shadow_collection"])
def test_case_and_variant_capability_union_is_required(cases, missing):
    case = cases["COL-05"]
    facts = {"collection": True, "inspected_regions": ["document", "open_shadow"]}
    assert _run(case, "open-shadow", facts, _page(html="open-shadow-marker"),
                capabilities=_caps(case, "open-shadow") - {missing}).status == "blocked"


@pytest.mark.parametrize("missing", ["positive_control_ok", "no_new_privileges_ok"])
def test_case_and_variant_evidence_union_is_required(cases, missing):
    facts = {"positive_control_ok": True, "uid_ok": True, "caps_ok": True,
             "seccomp_ok": True, "no_new_privileges_ok": True}
    del facts[missing]
    assert _run(cases["HOST-01"], "process", facts).status == "blocked"


@pytest.mark.parametrize("missing", ["caps_ok", "uid_ok"])
def test_evidence_names_are_required_even_without_matching_assertion(cases, missing):
    case = cases["HOST-01"]
    observations = deepcopy(case.expected_observations)
    observations["variants"]["sandbox"]["required_evidence"] = ["sandbox_ok", "uid_ok"]
    combined = replace(case, expected_observations=observations,
                       required_evidence=(*case.required_evidence, "caps_ok"))
    facts = {"positive_control_ok": True, "sandbox_ok": True, "caps_ok": True, "uid_ok": True}
    del facts[missing]
    assert _run(combined, "sandbox", facts).status == "blocked"


def test_no_new_privileges_observed_false_is_failure(cases):
    facts = {"positive_control_ok": True, "uid_ok": True, "caps_ok": True,
             "seccomp_ok": True, "no_new_privileges_ok": False}
    assert _run(cases["HOST-01"], "process", facts).status == "failed"


def test_missing_collection_fact_is_blocked_even_with_expected_html(cases):
    assert _run(cases["COL-01"], "default", {}, _page()).status == "blocked"


def test_actual_collection_fact_and_page_observations_pass(cases):
    assert _run(cases["COL-01"], "default", {"collection": True}, _page()).status == "passed"


@pytest.mark.parametrize("changes", [{"title": "wrong"}, {"html": "empty"}])
def test_actual_page_mismatches_are_failures(cases, changes):
    assert _run(cases["COL-01"], "default", {"collection": True}, _page(**changes)).status == "failed"


def test_missing_page_cannot_become_collection_success(cases):
    assert _run(cases["COL-01"], "default", {"collection": True}).status == "blocked"


def test_empty_legacy_expectations_do_not_manufacture_pass(cases):
    from isolation_tests.evaluate import evaluate

    legacy = replace(cases["COL-01"], expected_observations={}, required_evidence=())
    result = evaluate(legacy, "default", _page(), _evidence("COL-01", "default", {}),
                      frozenset({"collector"}))
    assert result.status == "blocked"


def test_unknown_regions_do_not_prove_forbidden_text_absent(cases):
    case = cases["COL-05"]
    observations = deepcopy(case.expected_observations)
    observations["variants"]["closed-shadow"]["assertions"]["forbidden_text"] = ["hidden-secret-marker"]
    absence_case = replace(case, expected_observations=observations)
    facts = {"collection": True, "unknown_regions": ["closed_shadow"]}
    assert _run(absence_case, "closed-shadow", facts, _page(html="document only")).status == "blocked"


def test_unknown_regions_are_preserved_as_unknown_in_result(cases):
    facts = {"collection": True, "unknown_regions": ["closed_shadow"]}
    result = _run(cases["COL-05"], "closed-shadow", facts, _page())
    # Collection may pass its explicit support-reporting contract; unknown scope
    # must still be present in the report, not changed into inspected/absent.
    assert "closed_shadow" in repr(result.details)


def test_missing_session_store_observations_are_blocked(cases):
    facts = {"collection": True, "context_fresh": True}
    assert _run(cases["SES-01"], "read", facts,
                _page(html="session-read-ready")).status == "blocked"


def test_observed_session_marker_leak_fails(cases):
    facts = {"collection": True, "context_fresh": True, "session_markers_present": ["cookie"]}
    assert _run(cases["SES-01"], "read", facts,
                _page(html="session-read-ready")).status == "failed"


def test_subset_cannot_be_full_pass():
    from isolation_tests.evaluate import summarize

    assert summarize((Outcome("COL-01", "default", "passed", "ok"),),
                     frozenset({"COL-01", "NET-01"})) == ("not_run", 2)


@pytest.mark.parametrize("statuses,expected", [
    (("failed", "blocked", "not_run", "passed"), ("failed", 1)),
    (("blocked", "not_run", "passed"), ("blocked", 2)),
    (("not_run", "passed"), ("not_run", 2)),
    (("passed",), ("passed", 0)),
])
def test_summary_status_precedence(statuses, expected):
    from isolation_tests.evaluate import summarize

    outcomes = tuple(Outcome("COL-01", "default", status, "fixture") for status in statuses)
    assert summarize(outcomes, frozenset({"COL-01"})) == expected


def test_empty_outcomes_are_not_full_pass():
    from isolation_tests.evaluate import summarize

    assert summarize((), frozenset({"COL-01"})) == ("not_run", 2)


def test_one_variant_per_case_is_not_full_pass(cases):
    from isolation_tests.evaluate import summarize

    outcomes = tuple(Outcome(case.id, case.variants[0], "passed", "synthetic") for case in cases.values())
    assert summarize(outcomes, frozenset(cases)) == ("not_run", 2)


def test_all_96_canonical_variants_are_required_for_full_pass(cases):
    from isolation_tests.evaluate import summarize

    outcomes = tuple(Outcome(case.id, variant, "passed", "synthetic")
                     for case in cases.values() for variant in case.variants)
    assert len(outcomes) == 96
    assert summarize(outcomes, frozenset(cases)) == ("passed", 0)


def test_omitted_variant_yields_not_run_even_when_all_ids_remain(cases):
    from isolation_tests.evaluate import summarize

    outcomes = tuple(Outcome(case.id, variant, "passed", "synthetic")
                     for case in cases.values() for variant in case.variants
                     if (case.id, variant) != ("NET-01", "fetch"))
    assert {outcome.case_id for outcome in outcomes} == set(cases)
    assert summarize(outcomes, frozenset(cases)) == ("not_run", 2)


def test_summary_failure_beats_missing_required_variants(cases):
    from isolation_tests.evaluate import summarize

    assert summarize((Outcome("NET-01", "fetch", "failed", "received"),),
                     frozenset(cases)) == ("failed", 1)


# Implementer additions (Task 9).

def test_runner_observed_elapsed_beyond_deadline_and_grace_fails(limit_case):
    result = _run(limit_case, "delay-15s", _limit_facts(),
                  _page(elapsed_ms=13001, failures=("timeout",)), ended_at="2026-10-10T00:00:14Z")
    assert result.status == "failed"


def test_runner_ending_before_remote_deadline_is_not_compliance(limit_case):
    result = _run(limit_case, "delay-15s", _limit_facts(),
                  _page(elapsed_ms=5000, failures=("timeout",)), ended_at="2026-10-10T00:00:13Z")
    assert result.status == "blocked"


def test_window_shorter_than_deadline_cannot_prove_deadline(limit_case):
    result = _run(limit_case, "delay-15s", _limit_facts(),
                  _page(elapsed_ms=12500, failures=("timeout",)))
    assert result.status == "blocked"


def test_unexpected_remote_failure_is_not_collection_success(cases):
    assert _run(cases["COL-01"], "default", {"collection": True},
                _page(failures=("timeout",))).status == "failed"


def _concurrency_facts(**changes):
    return {"positive_control_ok": True, "remote_job_terminated": True, "children_remaining": 0,
            "recovery_ok": True, "concurrency_limit_known": True, "limit_plus_one_sent": True,
            "concurrency_limit_ok": True, "queue_limit_ok": True, **changes}


@pytest.mark.parametrize("changes", [
    {"concurrency_limit_known": False}, {"limit_plus_one_sent": False},
    {"concurrency_limit": 8}, {"concurrency_limit": 0}, {"concurrency_limit": True},
])
def test_unknown_or_unexceedable_concurrency_limit_is_insufficient_load(cases, changes):
    result = _run(cases["LIM-06"], "concurrency", _concurrency_facts(**changes))
    assert result.status == "blocked"


def test_concurrency_limit_within_fixture_load_can_pass(cases):
    result = _run(cases["LIM-06"], "concurrency", _concurrency_facts(concurrency_limit=7))
    assert result.status == "passed"


def test_concurrency_over_limit_observed_fails(cases):
    result = _run(cases["LIM-06"], "concurrency", _concurrency_facts(concurrency_limit_ok=False))
    assert result.status == "failed"


def test_unknown_required_id_cannot_be_full_pass():
    from isolation_tests.evaluate import summarize

    assert summarize((Outcome("ZZZ-01", "default", "passed", "synthetic"),),
                     frozenset({"ZZZ-01"})) == ("not_run", 2)


def test_empty_requirement_is_not_full_pass():
    from isolation_tests.evaluate import summarize

    assert summarize((), frozenset()) == ("not_run", 2)
