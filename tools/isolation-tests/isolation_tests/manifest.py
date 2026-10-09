"""Load versioned JSON manifests without coercing case field types."""

import json
import math
import re
from dataclasses import fields
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from .model import CaseSpec


_CASE_FIELDS = {field.name for field in fields(CaseSpec)}
_STRING_FIELDS = ("id", "group", "title", "description", "execution_kind", "message", "risk_level")
_NULLABLE_STRING_FIELDS = ("target_key", "relative_path", "recovery_case")
_STRING_ARRAY_FIELDS = ("variants", "required_capabilities", "required_evidence")
_OBJECT_FIELDS = ("expected_observations", "expected_analysis")
_GROUPS = {"collection", "navigation", "analysis", "network", "session", "download", "http", "limits", "host", "integration", "recovery"}
_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_VARIANT = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_INPUTS = {"message", "token_mode", "domain_match", "page_state", "observation_status", "metric", "boundary_offset", "target_key"}
_ASSERTIONS = {"required_text", "forbidden_text", "title", "final_path", "status_code", "content_type", "redirect_count", "max_redirects", "required_facts", "unknown_regions", "failure_codes"}
_ANALYSIS = {"required_doubts", "required_signal_codes", "forbidden_signal_codes", "final_state", "reason_code", "mode"}
_BOOLEAN_FACTS = {
    "positive_control_ok", "receiver_control_ok", "request_blocked", "receiver_observed",
    "firewall_drop_observed", "remote_job_terminated", "recovery_ok", "caps_ok",
    "sandbox_ok", "readonly_ok", "mounts_ok", "environment_names_ok", "digest_ok",
    "replacement_ok", "kakao_received", "collection", "analysis", "no_new_privileges_ok",
}
_COUNT_FACTS = {"children_remaining", "download_temporary_bytes", "download_remaining_bytes"}


def _strings(value: Any, name: str, *, names: bool = False) -> None:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
        raise ValueError(f"{name} must be an array of nonempty strings")
    if len(set(value)) != len(value) or (names and any(not _NAME.fullmatch(item) for item in value)):
        raise ValueError(f"{name} must contain unique safe names")


def _relative_path(value: str, name: str) -> None:
    decoded = value
    for _ in range(3):
        decoded = unquote(decoded)
    parts = urlsplit(decoded)
    if (not value or parts.scheme or parts.netloc or parts.query or parts.fragment or "%" in decoded
            or decoded.startswith("/") or "\\" in decoded or ":" in decoded
            or any(ord(c) < 32 or c.isspace() for c in decoded)
            or any(segment in {".", "..", ""} for segment in decoded.split("/"))):
        raise ValueError(f"{name} must be a safe relative path")


def _facts(value: Any) -> None:
    if not isinstance(value, dict) or any(not _NAME.fullmatch(key) for key in value):
        raise ValueError("required_facts must map safe fact names to scalar expectations")
    for key, expected in value.items():
        if key in _BOOLEAN_FACTS and type(expected) is not bool:
            raise ValueError(f"fact {key} must be a boolean")
        if key in _COUNT_FACTS and (type(expected) is not int or expected < 0):
            raise ValueError(f"fact {key} must be a nonnegative integer")
        if key in {"inspected_regions", "unknown_regions"}:
            _strings(expected, key, names=True)
        items = expected if isinstance(expected, list) else [expected]
        for item in items:
            if item is not None and type(item) not in {str, bool, int, float}:
                raise ValueError("required_facts permits only scalars or flat scalar arrays")
            if type(item) is float and not math.isfinite(item):
                raise ValueError("required_facts numbers must be finite")


def _expectations(data: dict, variants: list[str], *, analysis: bool) -> None:
    # Empty legacy contracts remain loadable for Task 1's minimal local fixtures.
    if not data:
        return
    if set(data) != {"variants"} or not isinstance(data["variants"], dict) or set(data["variants"]) != set(variants):
        raise ValueError("expectation variants must exactly match case variants")
    for contract in data["variants"].values():
        if analysis:
            if not isinstance(contract, dict) or set(contract) != _ANALYSIS:
                raise ValueError("analysis variant requires exactly the documented fields")
            for key in ("required_doubts", "required_signal_codes", "forbidden_signal_codes"):
                _strings(contract[key], key, names=key != "required_doubts")
            for key in ("final_state", "reason_code"):
                if contract[key] is not None and (not isinstance(contract[key], str) or not _NAME.fullmatch(contract[key])):
                    raise ValueError(f"{key} must be a state/code name or null")
            if not isinstance(contract["mode"], str) or contract["mode"] not in {"fixed", "live_optional"}:
                raise ValueError("analysis mode must be fixed or live_optional")
            continue
        if not isinstance(contract, dict) or set(contract) != {"inputs", "assertions", "required_evidence", "required_capabilities"}:
            raise ValueError("observation variant requires exactly the documented fields")
        for key in ("required_evidence", "required_capabilities"):
            _strings(contract[key], key, names=True)
        inputs, assertions = contract["inputs"], contract["assertions"]
        if not isinstance(inputs, dict) or set(inputs) - _INPUTS:
            raise ValueError("inputs contains unsupported fields")
        if not isinstance(assertions, dict) or set(assertions) - _ASSERTIONS:
            raise ValueError("assertions contains unsupported fields")
        for key, value in inputs.items():
            if key == "boundary_offset":
                if type(value) is not int or value not in {-1, 0, 1}:
                    raise ValueError("boundary_offset must be integer -1, 0 or 1")
            elif not isinstance(value, str) or (key != "message" and not _NAME.fullmatch(value)):
                raise ValueError(f"input {key} must be a string with the documented meaning")
        for key, value in assertions.items():
            if key in {"required_text", "forbidden_text", "unknown_regions", "failure_codes"}:
                _strings(value, key, names=key in {"unknown_regions", "failure_codes"})
            elif key == "required_facts":
                _facts(value)
            elif key in {"status_code", "redirect_count", "max_redirects"}:
                if type(value) is not int or value < 0 or (key == "status_code" and not 100 <= value <= 599):
                    raise ValueError(f"assertion {key} requires a valid integer")
            elif not isinstance(value, str) or not value.strip():
                raise ValueError(f"assertion {key} requires a nonempty string")
            elif key == "final_path":
                _relative_path(value, key)


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
    if data["group"] not in _GROUPS:
        raise ValueError("invalid case group")
    if not re.fullmatch(r"(?:COL|NAV|ANA|NET|SES|DL|HTTP|LIM|HOST|INT|REC)-[0-9]{2}", data["id"]):
        raise ValueError("invalid case id")
    if not data["title"].strip() or not data["description"].strip():
        raise ValueError("case title and description must be nonempty")
    if type(data["max_requests"]) is not int or data["max_requests"] <= 0:
        raise ValueError("case field max_requests must be a positive integer")
    for key in ("required_capabilities", "required_evidence"):
        _strings(data[key], key, names=True)
    _strings(data["variants"], "variants")
    if not data["variants"] or any(not _VARIANT.fullmatch(item) for item in data["variants"]):
        raise ValueError("variants require nonempty safe names")
    if data["target_key"] is not None and not _NAME.fullmatch(data["target_key"]):
        raise ValueError("target_key must be a safe name or null")
    if data["relative_path"] is not None:
        _relative_path(data["relative_path"], "relative_path")
    if data["execution_kind"] == "page" and (data["target_key"] is None or data["relative_path"] is None):
        raise ValueError("page cases require a target and relative path")
    if data["recovery_case"] is not None and not re.fullmatch(r"(?:COL|NAV|ANA|NET|SES|DL|HTTP|LIM|HOST|INT|REC)-[0-9]{2}", data["recovery_case"]):
        raise ValueError("invalid recovery case id")
    _expectations(data["expected_observations"], data["variants"], analysis=False)
    _expectations(data["expected_analysis"], data["variants"], analysis=True)
    values = {**data, **{name: tuple(data[name]) for name in _STRING_ARRAY_FIELDS}}
    return CaseSpec(**values)


def load_cases(path: Path) -> tuple[CaseSpec, ...]:
    """Validate version 1 and return cases in their declared order."""
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate manifest key")
            result[key] = value
        return result

    data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
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


def select_cases(cases: tuple[CaseSpec, ...], group: str | None, case_id: str | None) -> tuple[CaseSpec, ...]:
    """Intersect optional filters without rebuilding or reordering case objects."""
    chosen = tuple(case for case in cases if (group is None or case.group == group)
                   and (case_id is None or case.id == case_id))
    if not chosen:
        raise ValueError("no matching cases")
    return chosen
