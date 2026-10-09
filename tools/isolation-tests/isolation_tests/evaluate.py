"""Decide one variant's status from actual observations; never from expectations.

Order of decisions: correlation, capabilities and well-typed evidence must hold
(else ``blocked``); positive controls must be actually observed True (else
``blocked``); then any observed contradiction is ``failed``; any missing or
unmet precondition is ``blocked``; only a fully observed match is ``passed``.
"""

import math
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .evidence import (
    REGION_FACTS, EvidenceUnavailable, clock_aligned, validate_facts, window,
)
from .model import CaseSpec, CollectedPage, Evidence, Outcome, Status
from .receiver import RUN_ID


CANONICAL_MANIFEST = Path(__file__).resolve().parents[1] / "cases.json"
MAX_CONCURRENT_TRIALS = 8
# The fixture server processes at most 4 requests at once and queues none.
MAX_FIXTURE_ACTIVE = 4

# Controls prove the trial could have succeeded; without them a "block" proves nothing.
CONTROL_FACTS = ("positive_control_ok", "receiver_control_ok")
# A False value means the trial did not establish its premise: blocked, not failed.
PRECONDITION_FACTS = frozenset({
    "collection", "analysis", "request_blocked", "firewall_drop_observed", "probe_in_container",
    "shared_ip_verified", "same_host_verified", "download_attempt_observed", "context_fresh",
    "resource_profile_recorded", "concurrency_limit_known", "limit_plus_one_sent",
    "limit_exceeded_confirmed",
})
# Expected value of a vocabulary fact named only in required_evidence.
_CANONICAL_EXPECTED = {
    "positive_control_ok": True, "receiver_control_ok": True, "request_blocked": True,
    "receiver_observed": False, "firewall_drop_observed": True, "remote_job_terminated": True,
    "children_remaining": 0, "recovery_ok": True, "download_temporary_bytes": 0,
    "download_remaining_bytes": 0, "caps_ok": True, "sandbox_ok": True, "readonly_ok": True,
    "mounts_ok": True, "environment_names_ok": True, "digest_ok": True, "replacement_ok": True,
    "kakao_received": True, "uid_ok": True, "seccomp_ok": True, "no_new_privileges_ok": True,
    "collection": True, "analysis": True,
}
_PAGE_ASSERTIONS = ("required_text", "forbidden_text", "title", "final_path", "status_code",
                    "content_type", "redirect_count", "max_redirects", "failure_codes")
_PRIORITY: tuple[Status, ...] = ("failed", "blocked", "not_run", "passed")
_EXIT = {"failed": 1, "blocked": 2, "not_run": 2, "passed": 0}


def _kind(value: Any) -> str | None:
    if type(value) is bool:
        return "bool"
    if type(value) in (int, float) and math.isfinite(value):
        return "number"
    if isinstance(value, str):
        return "str"
    if value is None:
        return "null"
    return None


def _compare(name: str, expected: Any, actual: Any) -> str:
    """'ok', 'mismatch' (observed contradiction) or 'malformed' (proves nothing)."""
    if isinstance(expected, list):
        if not isinstance(actual, list) or any(_kind(item) is None for item in actual):
            return "malformed"
        want = {(_kind(item), item) for item in expected}
        have = {(_kind(item), item) for item in actual}
        if name in REGION_FACTS:  # reporting more regions is not a contradiction
            return "ok" if want <= have else "mismatch"
        return "ok" if want == have and len(actual) == len(have) else "mismatch"
    if _kind(expected) != _kind(actual):
        return "malformed"
    return "ok" if expected == actual else "mismatch"


def _contract(case: CaseSpec, variant: str) -> dict | None:
    variants = case.expected_observations.get("variants") if isinstance(case.expected_observations, dict) else None
    contract = variants.get(variant) if isinstance(variants, dict) else None
    if not isinstance(contract, dict) or not isinstance(contract.get("assertions"), dict):
        return None
    return contract


def _ordered_union(*groups) -> tuple[str, ...]:
    return tuple(dict.fromkeys(name for group in groups for name in group))


def _page_checks(assertions: dict, page: CollectedPage, facts: dict, failures: list, blockers: list) -> None:
    html = page.html
    for text in assertions.get("required_text", ()):
        if text not in html:
            failures.append("required_text_missing")
    forbidden = assertions.get("forbidden_text", ())
    if any(text in html for text in forbidden):
        failures.append("forbidden_text_present")
    elif forbidden and facts.get("unknown_regions") != []:
        # Uninspected regions (or unreported scope) cannot prove absence.
        blockers.append("absence_unverifiable")
    if "title" in assertions and page.title != assertions["title"]:
        failures.append("title_mismatch")
    if "final_path" in assertions:
        if page.final_url is None:
            blockers.append("final_url_missing")
        else:
            path = urlsplit(page.final_url).path
            expected = assertions["final_path"]
            if path.lstrip("/") != expected and not path.endswith("/" + expected):
                failures.append("final_path_mismatch")
    if "status_code" in assertions:
        if page.status_code is None:
            blockers.append("status_code_missing")
        elif page.status_code != assertions["status_code"]:
            failures.append("status_code_mismatch")
    if "content_type" in assertions:
        if page.content_type is None:
            blockers.append("content_type_missing")
        elif page.content_type.split(";")[0].strip().lower() != assertions["content_type"].lower():
            failures.append("content_type_mismatch")
    if "redirect_count" in assertions and len(page.redirect_chain) != assertions["redirect_count"]:
        failures.append("redirect_count_mismatch")
    if "max_redirects" in assertions and len(page.redirect_chain) > assertions["max_redirects"]:
        failures.append("redirect_limit_exceeded")
    expected_codes = assertions.get("failure_codes")
    if expected_codes is None:
        if page.failures:
            failures.append("unexpected_collection_failure")
    elif not set(expected_codes) <= set(page.failures):
        failures.append("expected_failure_missing")


def _deadline_checks(facts: dict, evidence: Evidence, page: CollectedPage | None,
                     failures: list, blockers: list) -> None:
    deadline, grace = facts.get("collector_deadline_s"), facts.get("deadline_grace_s")
    if _kind(deadline) != "number" or _kind(grace) != "number":
        return
    started, ended = window(evidence)
    if (ended - started).total_seconds() < deadline:
        # The trial window cannot contain a run that reached the deadline.
        blockers.append("window_shorter_than_deadline")
    if page is not None:
        if page.elapsed_ms > (deadline + grace) * 1000:
            failures.append("deadline_exceeded")
        elif page.elapsed_ms < deadline * 1000:
            blockers.append("runner_ended_before_deadline")


def _concurrency_checks(required: tuple[str, ...], facts: dict, blockers: list) -> None:
    """A collector limit the fixture cannot exceed is unproven: limit+1 <= min(8, fixture)."""
    if "limit_plus_one_sent" not in required and "concurrency_limit" not in facts:
        return
    limit, fixture = facts.get("concurrency_limit"), facts.get("fixture_max_active")
    if (type(limit) is not int or limit < 1
            or type(fixture) is not int or not 1 <= fixture <= MAX_FIXTURE_ACTIVE
            or limit + 1 > min(MAX_CONCURRENT_TRIALS, fixture)):
        blockers.append("insufficient_fixture_load")


def evaluate(case: CaseSpec, variant: str, page: CollectedPage | None, evidence: Evidence,
             capabilities: frozenset[str]) -> Outcome:
    def outcome(status: Status, reason: str, **details) -> Outcome:
        return Outcome(case.id, variant, status, reason, details)

    if variant not in case.variants:
        return outcome("blocked", "unknown_variant")
    if evidence.case_id != case.id:
        return outcome("blocked", "evidence_case_mismatch")
    if not isinstance(evidence.run_id, str) or not RUN_ID.fullmatch(evidence.run_id):
        return outcome("blocked", "evidence_run_id_invalid")
    try:
        facts = validate_facts(evidence.facts)
        window(evidence)
    except EvidenceUnavailable:
        return outcome("blocked", "malformed_evidence")
    if facts["variant"] != variant:
        return outcome("blocked", "evidence_variant_mismatch")

    regions = {key: list(facts[key]) for key in sorted(REGION_FACTS) if key in facts}
    contract = _contract(case, variant)
    if contract is None:
        return outcome("blocked", "missing_expectations", **regions)
    needed = set(case.required_capabilities) | set(contract.get("required_capabilities", ()))
    missing_caps = sorted(needed - set(capabilities))
    if missing_caps:
        return outcome("blocked", "missing_capability", capabilities=missing_caps, **regions)
    if not clock_aligned(facts):
        return outcome("blocked", "clock_offset_exceeded", **regions)

    assertions = contract["assertions"]
    expected_facts = assertions.get("required_facts", {})
    required = _ordered_union(case.required_evidence, contract.get("required_evidence", ()), expected_facts)
    page_asserted = [key for key in _PAGE_ASSERTIONS if key in assertions]
    if not required and not page_asserted:
        return outcome("blocked", "no_observable_expectation", **regions)
    for control in CONTROL_FACTS:
        if control in required and facts.get(control) is not True:
            return outcome("blocked", "missing_positive_control", control=control, **regions)

    failures: list[str] = []
    blockers: list[str] = []
    for name in required:
        if name not in facts:
            blockers.append(f"missing_fact:{name}")
            continue
        expected = expected_facts.get(name, _CANONICAL_EXPECTED.get(name))
        if expected is None and name not in expected_facts:
            continue  # presence-only requirement
        verdict = _compare(name, expected, facts[name])
        if verdict == "malformed":
            blockers.append(f"malformed_fact:{name}")
        elif verdict == "mismatch":
            (blockers if name in PRECONDITION_FACTS else failures).append(f"fact_mismatch:{name}")
    if "unknown_regions" in assertions:
        reported = facts.get("unknown_regions")
        if reported is None:
            blockers.append("unknown_regions_unreported")
        elif not set(assertions["unknown_regions"]) <= set(reported):
            failures.append("unknown_regions_mismatch")
    if page_asserted:
        if page is None:
            blockers.append("collected_page_missing")
        else:
            _page_checks(assertions, page, facts, failures, blockers)
    _deadline_checks(facts, evidence, page, failures, blockers)
    _concurrency_checks(required, facts, blockers)

    if failures:
        return outcome("failed", failures[0], failures=failures, blockers=blockers, **regions)
    if blockers:
        return outcome("blocked", blockers[0], blockers=blockers, **regions)
    return outcome("passed", "observed_expectations_met", **regions)


def merge_analysis(case: CaseSpec, variant: str, base: Outcome, analysis: Outcome | None) -> Outcome:
    """Combine the evidence result with the AI adapter result; the worse one wins.

    A case with a deterministic analysis contract cannot pass without an analysis
    result. Cases without one are returned unchanged.
    """
    contract = case.expected_analysis.get("variants", {}).get(variant)
    if not isinstance(contract, dict) or contract.get("final_state") is None:
        return base
    if analysis is None:
        return Outcome(base.case_id, base.variant, "failed" if base.status == "failed" else "blocked",
                       "analysis_missing" if base.status != "failed" else base.reason,
                       {**base.details, "base_status": base.status})
    worst = min((base, analysis), key=lambda item: _PRIORITY.index(item.status))
    return Outcome(base.case_id, base.variant, worst.status, worst.reason,
                   {**base.details, "analysis": dict(analysis.details), "base_status": base.status})


@lru_cache(maxsize=1)
def _canonical_variants() -> dict[str, tuple[str, ...]]:
    from .manifest import load_cases

    return {case.id: case.variants for case in load_cases(CANONICAL_MANIFEST)}


def summarize(outcomes: tuple[Outcome, ...], required_ids: frozenset[str]) -> tuple[Status, int]:
    """Aggregate with failed > blocked > not_run > passed; every canonical variant is required."""
    variants = _canonical_variants()
    statuses: set[str] = set()
    for item in outcomes:
        statuses.add(item.status if item.status in _EXIT else "blocked")
    covered = {(item.case_id, item.variant) for item in outcomes}
    if not required_ids:
        statuses.add("not_run")
    for case_id in required_ids:
        if case_id not in variants:
            statuses.add("not_run")
            continue
        if any((case_id, variant) not in covered for variant in variants[case_id]):
            statuses.add("not_run")
    for status in _PRIORITY:
        if status in statuses:
            return status, _EXIT[status]
    return "not_run", 2
