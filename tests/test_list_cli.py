"""The list command presents real manifest content without running cases."""

import subprocess
import sys
from pathlib import Path


def test_list_uses_selected_manifest_and_lists_every_case(case_data, write_manifest, capsys):
    from isolation_tests.runner import main

    second = {
        **case_data,
        "id": "ANA-01",
        "group": "analysis",
        "title": "조회 결과 합성 표본",
        "relative_path": "v1/cases/ana-01/index.html",
    }
    manifest = write_manifest({"version": 1, "cases": [case_data, second]})

    assert main(["list", "--manifest", str(manifest)]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    for expected in ("COL-01", "수집 기준", "ANA-01", "조회 결과 합성 표본", "page"):
        assert expected in captured.out


def test_compatibility_runner_lists_manifest_from_other_directory(case_data, write_manifest, tmp_path):
    manifest = write_manifest({"version": 1, "cases": [case_data]})
    script = Path(__file__).resolve().parents[1] / "tools" / "isolation-tests" / "runner.py"
    result = subprocess.run(
        [sys.executable, "-X", "utf8", str(script), "list", "--manifest", str(manifest)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=10,
    )

    assert result.returncode == 0, result.stderr
    assert "COL-01" in result.stdout
    assert "수집 기준" in result.stdout
