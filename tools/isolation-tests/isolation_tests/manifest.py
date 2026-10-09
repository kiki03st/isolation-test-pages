"""Load versioned JSON manifests without coercing case field types."""

import json
from dataclasses import fields
from pathlib import Path
from typing import Any

from .model import CaseSpec


_CASE_FIELDS = {field.name for field in fields(CaseSpec)}
_STRING_FIELDS = ("id", "group", "title", "description", "execution_kind", "message", "risk_level")
_NULLABLE_STRING_FIELDS = ("target_key", "relative_path", "recovery_case")
_STRING_ARRAY_FIELDS = ("variants", "required_capabilities", "required_evidence")
_OBJECT_FIELDS = ("expected_observations", "expected_analysis")


def _load_case(data: Any) -> CaseSpec:
    if not isinstance(data, dict) or set(data) != _CASE_FIELDS:
        raise ValueError("case requires exactly the documented fields")
    for name in _STRING_FIELDS:
        if not isinstance(data[name], str):
            raise ValueError(f"case field {name} must be a string")
    for name in _NULLABLE_STRING_FIELDS:
        if data[name] is not None and not isinstance(data[name], str):
            raise ValueError(f"case field {name} must be a string or null")
    for name in _STRING_ARRAY_FIELDS:
        if not isinstance(data[name], list) or any(not isinstance(item, str) for item in data[name]):
            raise ValueError(f"case field {name} must be an array of strings")
    for name in _OBJECT_FIELDS:
        if not isinstance(data[name], dict):
            raise ValueError(f"case field {name} must be an object")
    if data["execution_kind"] not in {"page", "http_fixture", "host_probe", "integration"}:
        raise ValueError("invalid execution_kind")
    if data["risk_level"] not in {"basic", "explicit"}:
        raise ValueError("invalid risk_level")
    if type(data["max_requests"]) is not int:
        raise ValueError("case field max_requests must be an integer")
    values = {**data, **{name: tuple(data[name]) for name in _STRING_ARRAY_FIELDS}}
    return CaseSpec(**values)


def load_cases(path: Path) -> tuple[CaseSpec, ...]:
    """Validate version 1 and return cases in their declared order."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or set(data) != {"version", "cases"}:
        raise ValueError("manifest requires exactly version and cases")
    if type(data["version"]) is not int or data["version"] != 1:
        raise ValueError("manifest version must be integer 1")
    if not isinstance(data["cases"], list):
        raise ValueError("manifest cases must be an array")
    cases = tuple(_load_case(item) for item in data["cases"])
    seen: set[str] = set()
    for case in cases:
        if case.id in seen:
            raise ValueError("duplicate case id")
        seen.add(case.id)
    return cases
