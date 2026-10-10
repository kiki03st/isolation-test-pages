"""Reject unsafe schema coercions before a case can reach an executor."""

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest


def test_load_cases_returns_typed_case_specs(case_data, write_manifest):
    from isolation_tests.manifest import load_cases
    from isolation_tests.model import CaseSpec

    cases = load_cases(write_manifest({"version": 1, "cases": [case_data]}))

    assert isinstance(cases, tuple)
    assert len(cases) == 1
    assert cases[0] == CaseSpec(
        id="COL-01",
        group="collection",
        title="수집 기준",
        description="기본 수집 합성 표본",
        execution_kind="page",
        target_key="pages",
        relative_path="v1/cases/col-01/index.html",
        variants=("default",),
        required_capabilities=("collector",),
        message="",
        expected_observations={},
        expected_analysis={},
        required_evidence=("collection",),
        risk_level="basic",
        max_requests=1,
        recovery_case=None,
    )
    with pytest.raises(FrozenInstanceError):
        cases[0].id = "ALTERED"


def test_duplicate_case_id_is_rejected(case_data, write_manifest):
    from isolation_tests.manifest import load_cases

    # The cases differ in title; duplicate detection must use IDs, not full equality.
    duplicate = {**case_data, "title": "다른 합성 표본"}
    with pytest.raises(ValueError, match="duplicate case id"):
        load_cases(write_manifest({"version": 1, "cases": [case_data, duplicate]}))


@pytest.mark.parametrize("version", [True, "1", 1.0, 2, None])
def test_manifest_version_is_strict(case_data, write_manifest, version):
    from isolation_tests.manifest import load_cases

    with pytest.raises(ValueError):
        load_cases(write_manifest({"version": version, "cases": [case_data]}))


@pytest.mark.parametrize(
    "payload",
    [[], {"version": 1}, {"cases": []}, {"version": 1, "cases": {}}],
)
def test_manifest_requires_version_and_case_array(write_manifest, payload):
    from isolation_tests.manifest import load_cases

    with pytest.raises(ValueError):
        load_cases(write_manifest(payload))


def test_manifest_rejects_unknown_top_level_key(case_data, write_manifest):
    from isolation_tests.manifest import load_cases

    with pytest.raises(ValueError):
        load_cases(write_manifest({"version": 1, "cases": [case_data], "casez": []}))


def test_case_rejects_unknown_field(case_data, write_manifest):
    from isolation_tests.manifest import load_cases

    case_data["max_request"] = 1
    with pytest.raises(ValueError):
        load_cases(write_manifest({"version": 1, "cases": [case_data]}))


def test_case_requires_documented_fields(case_data, write_manifest):
    from isolation_tests.manifest import load_cases

    del case_data["required_evidence"]
    with pytest.raises(ValueError):
        load_cases(write_manifest({"version": 1, "cases": [case_data]}))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id", 1),
        ("group", None),
        ("title", False),
        ("description", []),
        ("execution_kind", "unknown"),
        ("target_key", 7),
        ("relative_path", False),
        ("variants", "default"),
        ("variants", ["default", 1]),
        ("required_capabilities", [True]),
        ("message", None),
        ("expected_observations", []),
        ("expected_analysis", "{}"),
        ("required_evidence", [None]),
        ("risk_level", "unknown"),
        ("max_requests", True),
        ("max_requests", 1.0),
        ("max_requests", "1"),
        ("recovery_case", 1),
    ],
)
def test_case_rejects_wrong_field_types(case_data, write_manifest, field, value):
    from isolation_tests.manifest import load_cases

    case_data[field] = value
    with pytest.raises(ValueError):
        load_cases(write_manifest({"version": 1, "cases": [case_data]}))


@pytest.mark.parametrize("execution_kind", ["http_fixture", "host_probe", "integration"])
def test_non_page_cases_allow_absent_page_target(case_data, write_manifest, execution_kind):
    from isolation_tests.manifest import load_cases

    case_data.update(execution_kind=execution_kind, target_key=None, relative_path=None)
    case = load_cases(write_manifest({"version": 1, "cases": [case_data]}))[0]
    assert case.execution_kind == execution_kind
    assert case.target_key is None
    assert case.relative_path is None


def test_invalid_json_is_rejected(tmp_path):
    from isolation_tests.manifest import load_cases

    path = tmp_path / "cases.json"
    path.write_text('{"version": 1, "cases": [}', encoding="utf-8")
    with pytest.raises(ValueError):
        load_cases(path)


# Independent transcription of the binding 43-case table; no product helpers.
REQUIRED_CASES = {
    "COL-01": ("collection", "page", ("default",)),
    "COL-02": ("collection", "page", ("default",)),
    "COL-03": ("collection", "page", ("default",)),
    "COL-04": ("collection", "page", ("delayed",)),
    "COL-05": ("collection", "page", ("iframe", "open-shadow", "closed-shadow")),
    "NAV-01": ("navigation", "page", ("js", "meta")),
    "NAV-02": ("navigation", "http_fixture", ("hops-1", "hops-5")),
    "NAV-03": ("navigation", "http_fixture", ("hops-6", "loop")),
    "NAV-04": ("navigation", "http_fixture", ("http", "js")),
    "ANA-01": ("analysis", "page", ("default",)),
    "ANA-02": ("analysis", "page", ("default",)),
    "ANA-03": ("analysis", "page", ("password", "otp")),
    "ANA-04": ("analysis", "page", ("default",)),
    "ANA-05": ("analysis", "page", ("default",)),
    "ANA-06": ("analysis", "page", ("warning", "negation", "quotation")),
    "ANA-07": ("analysis", "page", ("baseline", "injection")),
    "ANA-08": ("analysis", "integration", ("absent-evidence",)),
    "NET-01": ("network", "http_fixture", ("img", "script", "iframe", "fetch")),
    "NET-02": ("network", "http_fixture", ("action", "formaction")),
    "NET-03": ("network", "http_fixture", ("loopback", "private", "link-local", "main-public", "isolation-public")),
    "NET-04": ("network", "http_fixture", ("shared-ip-host", "same-host-path")),
    "NET-05": ("network", "host_probe", ("tcp", "dns", "ipv6")),
    "NET-06": ("network", "http_fixture", ("websocket", "worker", "service-worker")),
    "NET-07": ("network", "integration", ("initial-private", "scheme", "userinfo", "normalized-host")),
    "SES-01": ("session", "page", ("seed", "read")),
    "DL-01": ("download", "page", ("default",)),
    "DL-02": ("download", "http_fixture", ("attachment",)),
    "HTTP-01": ("http", "http_fixture", ("403", "404", "500", "block-page", "captcha-page")),
    "HTTP-02": ("http", "http_fixture", ("wrong-mime", "invalid-utf8", "truncated")),
    "LIM-01": ("limits", "http_fixture", ("delay-15s",)),
    "LIM-02": ("limits", "http_fixture", ("slow-stream",)),
    "LIM-03": ("limits", "http_fixture", ("large", "length-small", "length-large", "gzip")),
    "LIM-04": ("limits", "http_fixture", ("bytes", "elements", "text", "depth", "result")),
    "LIM-05": ("limits", "http_fixture", ("dom-growth", "cpu-bursts")),
    "LIM-06": ("limits", "integration", ("concurrency",)),
    "HOST-01": ("host", "host_probe", ("process", "sandbox")),
    "HOST-02": ("host", "host_probe", ("filesystem", "mounts", "environment")),
    "HOST-03": ("host", "host_probe", ("digest", "process-cleanup", "context-cleanup")),
    "INT-01": ("integration", "integration", ("valid", "missing", "wrong-token", "untrusted-ca")),
    "INT-02": ("integration", "integration", ("allowed-source", "denied-source")),
    "INT-03": ("integration", "integration", ("pipeline", "kakao-receipt")),
    "INT-04": ("integration", "integration", ("llm-timeout", "collection-failure", "callback-failure")),
    "REC-01": ("recovery", "host_probe", ("replacement",)),
}
OBSERVATION_INPUT_KEYS = {
    "message", "token_mode", "domain_match", "page_state", "observation_status",
    "metric", "boundary_offset", "target_key",
}
OBSERVATION_ASSERTION_KEYS = {
    "required_text", "forbidden_text", "title", "final_path", "status_code",
    "content_type", "redirect_count", "max_redirects", "required_facts",
    "unknown_regions", "failure_codes",
}
ANALYSIS_VARIANT_KEYS = {
    "required_doubts", "required_signal_codes", "forbidden_signal_codes",
    "final_state", "reason_code", "mode",
}


def test_manifest_has_exact_required_ids():
    from isolation_tests.manifest import load_cases

    path = Path(__file__).resolve().parents[1] / "tools/isolation-tests/cases.json"
    cases = load_cases(path)
    assert len(cases) == 43
    assert {case.id for case in cases} == set(REQUIRED_CASES)


@pytest.mark.parametrize("case_id", list(REQUIRED_CASES))
def test_task2_canonical_case_preserves_all_fixed_variants_and_contracts(case_id):
    from isolation_tests.manifest import load_cases

    path = Path(__file__).resolve().parents[1] / "tools/isolation-tests/cases.json"
    case = next(case for case in load_cases(path) if case.id == case_id)
    group, execution_kind, variants = REQUIRED_CASES[case_id]
    assert (case.group, case.execution_kind, case.variants) == (group, execution_kind, variants)
    assert case.title.strip()
    assert case.description.strip()
    assert case.required_evidence
    assert case.max_requests > 0
    assert set(case.expected_observations) == {"variants"}
    observations = case.expected_observations["variants"]
    assert set(observations) == set(variants)
    for variant in observations.values():
        assert set(variant) == {"inputs", "assertions", "required_evidence", "required_capabilities"}
        assert isinstance(variant["inputs"], dict)
        assert set(variant["inputs"]) <= OBSERVATION_INPUT_KEYS
        assert isinstance(variant["assertions"], dict)
        assert set(variant["assertions"]) <= OBSERVATION_ASSERTION_KEYS
        for key in ("required_evidence", "required_capabilities"):
            assert isinstance(variant[key], list)
            assert all(isinstance(item, str) for item in variant[key])
        if execution_kind == "host_probe":
            assert variant["assertions"].get("required_facts")
    if case_id == "HOST-01":
        process = observations["process"]
        assert process["assertions"]["required_facts"]["no_new_privileges_ok"] is True
        assert "no_new_privileges_ok" in process["required_evidence"]
    if group == "analysis":
        assert set(case.expected_analysis) == {"variants"}
        analysis = case.expected_analysis["variants"]
        assert set(analysis) == set(variants)
        for variant in analysis.values():
            assert set(variant) == ANALYSIS_VARIANT_KEYS
            assert variant["mode"] in {"fixed", "live_optional"}
    elif case.expected_analysis:
        assert set(case.expected_analysis) == {"variants"}
        assert set(case.expected_analysis["variants"]) == set(variants)


@pytest.fixture
def task2_variant_case_data(case_data):
    case_data["expected_observations"] = {
        "variants": {
            "default": {
                "inputs": {},
                "assertions": {"title": "수집 기준", "required_text": ["배송 상태: 배송 중"]},
                "required_evidence": ["collection"],
                "required_capabilities": ["collector"],
            }
        }
    }
    return case_data


def test_task2_variant_manifest_round_trips_without_losing_requirements(task2_variant_case_data, write_manifest):
    from isolation_tests.manifest import load_cases

    case = load_cases(write_manifest({"version": 1, "cases": [task2_variant_case_data]}))[0]
    assert case.expected_observations["variants"]["default"] == {
        "inputs": {},
        "assertions": {"title": "수집 기준", "required_text": ["배송 상태: 배송 중"]},
        "required_evidence": ["collection"],
        "required_capabilities": ["collector"],
    }


@pytest.mark.parametrize("group", ["collections", "unknown", ""])
def test_task2_unknown_groups_are_rejected(case_data, write_manifest, group):
    from isolation_tests.manifest import load_cases

    case_data["group"] = group
    with pytest.raises(ValueError):
        load_cases(write_manifest({"version": 1, "cases": [case_data]}))


@pytest.mark.parametrize("variants", [[], ["default", "default"], [""]])
def test_task2_variants_must_be_nonempty_unique_names(case_data, write_manifest, variants):
    from isolation_tests.manifest import load_cases

    case_data["variants"] = variants
    with pytest.raises(ValueError):
        load_cases(write_manifest({"version": 1, "cases": [case_data]}))


@pytest.mark.parametrize("max_requests", [-1, 0])
def test_task2_max_requests_requires_a_positive_budget(case_data, write_manifest, max_requests):
    from isolation_tests.manifest import load_cases

    case_data["max_requests"] = max_requests
    with pytest.raises(ValueError):
        load_cases(write_manifest({"version": 1, "cases": [case_data]}))


@pytest.mark.parametrize("field", ["expected_observations", "expected_analysis"])
def test_task2_expectation_objects_reject_unknown_top_level_keys(case_data, write_manifest, field):
    from isolation_tests.manifest import load_cases

    case_data[field] = {"undeclared_contract": True}
    with pytest.raises(ValueError):
        load_cases(write_manifest({"version": 1, "cases": [case_data]}))


@pytest.mark.parametrize("location", ["variant", "inputs", "assertions"])
def test_task2_observations_reject_unknown_nested_keys(task2_variant_case_data, write_manifest, location):
    from isolation_tests.manifest import load_cases

    variant = task2_variant_case_data["expected_observations"]["variants"]["default"]
    target = variant if location == "variant" else variant[location]
    target["undeclared_contract"] = True
    with pytest.raises(ValueError):
        load_cases(write_manifest({"version": 1, "cases": [task2_variant_case_data]}))


@pytest.mark.parametrize("field", ["expected_observations", "expected_analysis"])
@pytest.mark.parametrize("names", [[], ["other"], ["default", "other"]])
def test_task2_nested_variants_must_match_case_variants(task2_analysis_case_data, write_manifest, field, names):
    from isolation_tests.manifest import load_cases

    template = task2_analysis_case_data[field]["variants"]["default"]
    task2_analysis_case_data[field] = {"variants": {name: template for name in names}}
    with pytest.raises(ValueError):
        load_cases(write_manifest({"version": 1, "cases": [task2_analysis_case_data]}))


@pytest.mark.parametrize(
    ("key", "value"),
    [("inputs", []), ("assertions", []), ("required_evidence", "collection"),
     ("required_evidence", [True]), ("required_capabilities", [1])],
)
def test_task2_nested_observation_field_types_are_strict(task2_variant_case_data, write_manifest, key, value):
    from isolation_tests.manifest import load_cases

    task2_variant_case_data["expected_observations"]["variants"]["default"][key] = value
    with pytest.raises(ValueError):
        load_cases(write_manifest({"version": 1, "cases": [task2_variant_case_data]}))


@pytest.mark.parametrize(
    ("section", "key", "value"),
    [("inputs", "message", False), ("inputs", "token_mode", []),
     ("inputs", "domain_match", 1), ("inputs", "page_state", False),
     ("inputs", "observation_status", {}), ("inputs", "metric", True),
     ("inputs", "boundary_offset", True), ("inputs", "target_key", 7),
     ("assertions", "required_text", "배송"), ("assertions", "forbidden_text", [1]),
     ("assertions", "title", False), ("assertions", "final_path", False),
     ("assertions", "status_code", True), ("assertions", "content_type", 1),
     ("assertions", "redirect_count", True), ("assertions", "max_redirects", True),
     ("assertions", "unknown_regions", [1]), ("assertions", "failure_codes", None)],
)
def test_task2_declared_nested_values_are_not_coerced(task2_variant_case_data, write_manifest, section, key, value):
    from isolation_tests.manifest import load_cases

    task2_variant_case_data["expected_observations"]["variants"]["default"][section][key] = value
    with pytest.raises(ValueError):
        load_cases(write_manifest({"version": 1, "cases": [task2_variant_case_data]}))


@pytest.mark.parametrize("key", ["inputs", "assertions", "required_evidence", "required_capabilities"])
def test_task2_variant_observations_require_all_contract_fields(task2_variant_case_data, write_manifest, key):
    from isolation_tests.manifest import load_cases

    del task2_variant_case_data["expected_observations"]["variants"]["default"][key]
    with pytest.raises(ValueError):
        load_cases(write_manifest({"version": 1, "cases": [task2_variant_case_data]}))


@pytest.fixture
def task2_analysis_case_data(task2_variant_case_data):
    task2_variant_case_data["expected_analysis"] = {
        "variants": {
            "default": {
                "required_doubts": [], "required_signal_codes": [],
                "forbidden_signal_codes": ["password_required"],
                "final_state": "inconclusive", "reason_code": None, "mode": "fixed",
            }
        }
    }
    return task2_variant_case_data


def test_task2_analysis_contract_round_trips(task2_analysis_case_data, write_manifest):
    from isolation_tests.manifest import load_cases

    case = load_cases(write_manifest({"version": 1, "cases": [task2_analysis_case_data]}))[0]
    assert case.expected_analysis["variants"]["default"] == {
        "required_doubts": [], "required_signal_codes": [],
        "forbidden_signal_codes": ["password_required"],
        "final_state": "inconclusive", "reason_code": None, "mode": "fixed",
    }


@pytest.mark.parametrize(
    ("key", "value"),
    [("undeclared_contract", True), ("required_doubts", "password"),
     ("required_signal_codes", [True]), ("forbidden_signal_codes", {}),
     ("final_state", 1), ("reason_code", False), ("mode", "unknown")],
)
def test_task2_analysis_rejects_unknown_keys_and_wrong_types(task2_analysis_case_data, write_manifest, key, value):
    from isolation_tests.manifest import load_cases

    task2_analysis_case_data["expected_analysis"]["variants"]["default"][key] = value
    with pytest.raises(ValueError):
        load_cases(write_manifest({"version": 1, "cases": [task2_analysis_case_data]}))


@pytest.fixture
def task2_selection_cases(case_data, write_manifest):
    from isolation_tests.manifest import load_cases

    # Two matching cases expose accidental reordering or first-match selection.
    rows = [case_data, {**case_data, "id": "NAV-01", "group": "navigation"},
            {**case_data, "id": "COL-02"}]
    return load_cases(write_manifest({"version": 1, "cases": rows}))


@pytest.mark.parametrize(
    ("group", "case_id", "expected_ids"),
    [(None, None, ("COL-01", "NAV-01", "COL-02")),
     ("collection", None, ("COL-01", "COL-02")),
     (None, "COL-02", ("COL-02",)),
     ("collection", "COL-02", ("COL-02",))],
)
def test_task2_selection_intersects_filters_and_preserves_order(task2_selection_cases, group, case_id, expected_ids):
    from isolation_tests.manifest import select_cases

    selected = select_cases(task2_selection_cases, group, case_id)
    assert isinstance(selected, tuple)
    assert tuple(case.id for case in selected) == expected_ids
    assert all(any(case is original for original in task2_selection_cases) for case in selected)


@pytest.mark.parametrize(
    ("group", "case_id"),
    [("unknown", None), (None, "COL-99"), ("navigation", "COL-02"), ("", None)],
)
def test_task2_selection_rejects_no_match(task2_selection_cases, group, case_id):
    from isolation_tests.manifest import select_cases

    with pytest.raises(ValueError, match="no matching cases"):
        select_cases(task2_selection_cases, group, case_id)


def test_task2_selection_rejects_empty_manifest():
    from isolation_tests.manifest import select_cases

    with pytest.raises(ValueError, match="no matching cases"):
        select_cases((), None, None)


def test_task2_canonical_manifest_preserves_known_korean_content():
    import json
    from isolation_tests.manifest import load_cases

    path = Path(__file__).resolve().parents[1] / "tools/isolation-tests/cases.json"
    cases = {case.id: case for case in load_cases(path)}
    assert sum(len(case.variants) for case in cases.values()) == 96
    assert cases["COL-01"].title == "기본 텍스트 수집"
    assert cases["COL-01"].message == "가상택배 배송 상태를 확인해 주세요."
    assert cases["COL-01"].expected_observations["variants"]["default"]["assertions"]["required_text"] == ["배송 상태: 배송 중", "📦"]
    assert cases["ANA-03"].expected_analysis["variants"]["otp"]["required_doubts"] == ["로그인·인증 입력폼"]
    text = json.dumps(json.loads(path.read_text(encoding="utf-8")), ensure_ascii=False)
    assert "\ufffd" not in text and "?" not in text


@pytest.mark.parametrize("relative_path", ["../escape", "/absolute", "//remote/path", "https://remote/path", "v1/../escape", "v1\\escape", "v1/%2e%2e/escape", "v1/%252e%252e/escape", "v1/%2525252e/escape", "v1/file?query", "v1/file#fragment", "v1//file"])
def test_task2_case_paths_cannot_escape_site(case_data, write_manifest, relative_path):
    from isolation_tests.manifest import load_cases

    case_data["relative_path"] = relative_path
    with pytest.raises(ValueError):
        load_cases(write_manifest({"version": 1, "cases": [case_data]}))


@pytest.mark.parametrize("value", [{"unsafe-key": True}, {"valid": {}}, {"valid": [[1]]}, {"valid": float("nan")}, {"valid": [float("inf")]}])
def test_task2_required_facts_reject_unsafe_names_and_nested_values(task2_variant_case_data, write_manifest, value):
    from isolation_tests.manifest import load_cases

    task2_variant_case_data["expected_observations"]["variants"]["default"]["assertions"]["required_facts"] = value
    with pytest.raises(ValueError):
        load_cases(write_manifest({"version": 1, "cases": [task2_variant_case_data]}))


@pytest.mark.parametrize(("key", "value"), [("positive_control_ok", 1), ("children_remaining", True), ("children_remaining", -1), ("download_temporary_bytes", 0.5), ("download_remaining_bytes", False), ("inspected_regions", [False]), ("unknown_regions", "closed_shadow")])
def test_task2_known_fact_types_preserve_evaluator_contract(task2_variant_case_data, write_manifest, key, value):
    from isolation_tests.manifest import load_cases

    task2_variant_case_data["expected_observations"]["variants"]["default"]["assertions"]["required_facts"] = {key: value}
    with pytest.raises(ValueError):
        load_cases(write_manifest({"version": 1, "cases": [task2_variant_case_data]}))


def test_task2_fact_values_round_trip_with_exact_types(task2_variant_case_data, write_manifest):
    from isolation_tests.manifest import load_cases

    facts = {"positive_control_ok": True, "children_remaining": 0, "unknown_regions": ["closed_shadow"],
             "boundary_offsets": [-1, 0, 1], "clock_offset_seconds": 0.5, "navigation_kind": "js"}
    task2_variant_case_data["expected_observations"]["variants"]["default"]["assertions"]["required_facts"] = facts
    case = load_cases(write_manifest({"version": 1, "cases": [task2_variant_case_data]}))[0]
    assert case.expected_observations["variants"]["default"]["assertions"]["required_facts"] == facts


def test_task2_manifest_rejects_duplicate_nested_keys(tmp_path):
    from isolation_tests.manifest import load_cases

    path = tmp_path / "duplicate.json"
    path.write_text('{"version": 1, "version": 1, "cases": []}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        load_cases(path)


@pytest.mark.parametrize("mode", [None, [], {}])
def test_task2_analysis_mode_wrong_types_raise_value_error(task2_analysis_case_data, write_manifest, mode):
    from isolation_tests.manifest import load_cases

    task2_analysis_case_data["expected_analysis"]["variants"]["default"]["mode"] = mode
    with pytest.raises(ValueError):
        load_cases(write_manifest({"version": 1, "cases": [task2_analysis_case_data]}))


@pytest.mark.parametrize("value", [0, 1, "true", None, [], {}])
def test_task2_no_new_privileges_fact_requires_boolean(task2_variant_case_data, write_manifest, value):
    from isolation_tests.manifest import load_cases

    facts = task2_variant_case_data["expected_observations"]["variants"]["default"]["assertions"].setdefault("required_facts", {})
    facts["no_new_privileges_ok"] = value
    with pytest.raises(ValueError, match="no_new_privileges_ok.*boolean"):
        load_cases(write_manifest({"version": 1, "cases": [task2_variant_case_data]}))


@pytest.mark.parametrize("value", [True, False])
def test_task2_no_new_privileges_fact_preserves_actual_booleans(task2_variant_case_data, write_manifest, value):
    from isolation_tests.manifest import load_cases

    facts = task2_variant_case_data["expected_observations"]["variants"]["default"]["assertions"].setdefault("required_facts", {})
    facts["no_new_privileges_ok"] = value
    case = load_cases(write_manifest({"version": 1, "cases": [task2_variant_case_data]}))[0]
    assert case.expected_observations["variants"]["default"]["assertions"]["required_facts"]["no_new_privileges_ok"] is value


# --- final review: one fact vocabulary (evidence.py) for the manifest too -----------

@pytest.mark.parametrize("facts", [
    {"extra_fact": True}, {"positive_control_okk": True}, {"navigation_kind": "redirect"},
    {"boundary_offsets": [-1, 0, 2]}, {"session_stores_seeded": ["free text"]},
    {"payment_amount_krw": "1000"},
])
def test_required_facts_outside_the_approved_vocabulary_are_rejected(task2_variant_case_data, write_manifest, facts):
    from isolation_tests.manifest import load_cases

    task2_variant_case_data["expected_observations"]["variants"]["default"]["assertions"]["required_facts"] = facts
    with pytest.raises(ValueError):
        load_cases(write_manifest({"version": 1, "cases": [task2_variant_case_data]}))


@pytest.mark.parametrize("location", ["case", "variant"])
def test_required_evidence_names_must_be_approved_facts(task2_variant_case_data, write_manifest, location):
    from isolation_tests.manifest import load_cases

    if location == "case":
        task2_variant_case_data["required_evidence"] = ["collection", "colection"]
    else:
        task2_variant_case_data["expected_observations"]["variants"]["default"]["required_evidence"] = ["colection"]
    with pytest.raises(ValueError):
        load_cases(write_manifest({"version": 1, "cases": [task2_variant_case_data]}))


def test_manifest_keeps_no_second_fact_vocabulary():
    from isolation_tests import manifest

    assert not hasattr(manifest, "_BOOLEAN_FACTS") and not hasattr(manifest, "_COUNT_FACTS")
