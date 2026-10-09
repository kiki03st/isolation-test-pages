"""Reject unsafe schema coercions before a case can reach an executor."""

from dataclasses import FrozenInstanceError

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
