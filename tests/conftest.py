"""Synthetic fixtures shared by the manifest and CLI contract tests."""

import json
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools" / "isolation-tests"))


@pytest.fixture
def case_data():
    # Every documented CaseSpec field is present, independent of product code.
    return {
        "id": "COL-01",
        "group": "collection",
        "title": "수집 기준",
        "description": "기본 수집 합성 표본",
        "execution_kind": "page",
        "target_key": "pages",
        "relative_path": "v1/cases/col-01/index.html",
        "variants": ["default"],
        "required_capabilities": ["collector"],
        "message": "",
        "expected_observations": {},
        "expected_analysis": {},
        "required_evidence": ["collection"],
        "risk_level": "basic",
        "max_requests": 1,
        "recovery_case": None,
    }


@pytest.fixture
def write_manifest(tmp_path):
    def write(payload):
        path = tmp_path / "cases.json"
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        return path

    return write
