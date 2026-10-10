"""Reports are escaped, sanitized, atomically written and never overstate completion."""

import json
import os
from pathlib import Path

import pytest

from isolation_tests.model import Outcome


def _out(case_id="COL-01", variant="default", status="passed", reason="observed_expectations_met",
         **details):
    return Outcome(case_id, variant, status, reason, details)


def test_report_escapes_observed_html(tmp_path):
    from isolation_tests.report import write_reports
    out = Outcome('COL-01', 'default', 'failed', 'content_mismatch',
                  {'observed_html': '<script>synthetic()</script>'})
    _, html = write_reports((out,), tmp_path, {'run_id': 'run-test', 'scope': 'subset'})
    text = html.read_text(encoding='utf-8')
    assert '<script>synthetic()</script>' not in text
    assert '&lt;script&gt;' in text


def test_html_report_has_no_script_and_escapes_every_column(tmp_path):
    from isolation_tests.report import write_reports

    hostile = '"><img src=x onerror=alert(1)><script>x()</script>'
    out = Outcome("COL-01", "default", "failed", hostile, {"error_text": hostile, hostile: 1})
    _, html = write_reports((out,), tmp_path, {"run_id": "run-test", "scope": "subset"})
    text = html.read_text(encoding="utf-8")
    assert "<script" not in text.lower()
    assert "<img" not in text.lower()
    assert "onerror=alert(1)>" not in text
    assert "Content-Security-Policy" in text


def test_metadata_accepts_only_documented_keys(tmp_path):
    from isolation_tests.report import write_reports

    with pytest.raises(ValueError):
        write_reports((_out(),), tmp_path, {"run_id": "run-test", "token": "x"})
    assert list(tmp_path.iterdir()) == []


def test_unsafe_run_id_cannot_choose_the_report_path(tmp_path):
    from isolation_tests.report import write_reports

    target = tmp_path / "out"
    with pytest.raises(ValueError):
        write_reports((_out(),), target, {"run_id": "../escape"})
    assert not (tmp_path / "escape.json").exists()


def test_reports_remove_tokens_authorization_and_url_queries(tmp_path):
    from isolation_tests.report import write_reports

    secret = "synthetic-secret-token-value"
    out = _out(status="failed", reason="collection_failed",
               log="Authorization: Bearer " + secret + " sent",
               raw=f"token was {secret}",
               bearer="bearer abc.def-ghi",
               url="https://user:pw@pages.example.invalid/project/v1/cases/col-01/index.html?run_id=r123&t=" + secret,
               other="see https://evil.example.invalid/some/arbitrary/path?q=1 now",
               headers={"authorization": "Bearer x"}, cookie="a=b")
    json_path, html_path = write_reports((out,), tmp_path, {"run_id": "run-test"}, secrets=(secret,))
    for path in (json_path, html_path):
        text = path.read_text(encoding="utf-8")
        assert secret not in text
        assert "abc.def-ghi" not in text
        assert "Bearer x" not in text
        assert "user:pw" not in text
        assert "run_id=r123" not in text
        assert "q=1" not in text
        assert "/some/arbitrary/path" not in text
        assert "a=b" not in text
    data = json.loads(json_path.read_text(encoding="utf-8"))
    details = data["items"][0]["details"]
    assert details["url"] == "https://pages.example.invalid/project/v1/cases/col-01/index.html"
    assert "https://evil.example.invalid/" in details["other"]
    assert "headers" not in details and "cookie" not in details


def test_summary_uses_all_canonical_cases_so_partial_pass_is_incomplete(tmp_path):
    from isolation_tests.report import write_reports

    json_path, html_path = write_reports((_out(),), tmp_path, {"run_id": "run-test", "scope": "subset"})
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["summary"]["status"] == "not_run"
    assert data["summary"]["exit_code"] == 2
    assert len(data["metadata"]["required_ids"]) == 43
    assert data["summary"]["counts"]["passed"] == 1
    assert "environment_verified" not in html_path.read_text(encoding="utf-8")


def test_failed_item_makes_summary_failed(tmp_path):
    from isolation_tests.report import write_reports

    json_path, _ = write_reports((_out(status="failed", reason="x"),), tmp_path, {"run_id": "run-test"})
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert (data["summary"]["status"], data["summary"]["exit_code"]) == ("failed", 1)


def test_reports_are_written_atomically_without_temporary_leftovers(tmp_path):
    from isolation_tests.report import write_reports

    json_path, html_path = write_reports((_out(),), tmp_path, {"run_id": "run-a"})
    second = write_reports((_out(status="failed", reason="x"),), tmp_path, {"run_id": "run-a"})
    assert second == (json_path, html_path)
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted([json_path.name, html_path.name])
    assert json.loads(json_path.read_text(encoding="utf-8"))["items"][0]["status"] == "failed"


def test_output_that_is_a_file_is_refused(tmp_path):
    from isolation_tests.report import write_reports

    target = tmp_path / "file"
    target.write_text("keep", encoding="utf-8")
    with pytest.raises(ValueError):
        write_reports((_out(),), target, {"run_id": "run-test"})
    assert target.read_text(encoding="utf-8") == "keep"


def _symlink(link: Path, target: Path, directory=False):
    try:
        os.symlink(target, link, target_is_directory=directory)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not permitted on this host")


def test_symlinked_report_file_is_never_overwritten(tmp_path):
    from isolation_tests.report import write_reports

    outside = tmp_path / "outside.txt"
    outside.write_text("keep", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    _symlink(out / "isolation-report-run-test.json", outside)
    with pytest.raises(ValueError):
        write_reports((_out(),), out, {"run_id": "run-test"})
    assert outside.read_text(encoding="utf-8") == "keep"


def test_symlinked_output_directory_is_refused(tmp_path):
    from isolation_tests.report import write_reports

    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    _symlink(link, real, directory=True)
    with pytest.raises(ValueError):
        write_reports((_out(),), link, {"run_id": "run-test"})
    assert list(real.iterdir()) == []


def test_load_report_round_trips_items_and_metadata(tmp_path):
    from isolation_tests.report import load_report, write_reports

    json_path, _ = write_reports((_out(status="blocked", reason="missing_fact:x", note="n"),),
                                 tmp_path, {"run_id": "run-test", "scope": "subset"})
    outcomes, metadata = load_report(json_path)
    assert outcomes == (_out(status="blocked", reason="missing_fact:x", note="n"),)
    assert metadata["run_id"] == "run-test" and metadata["scope"] == "subset"


def test_load_report_rejects_malformed_items(tmp_path):
    from isolation_tests.report import load_report

    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"metadata": {}, "summary": {}, "items": [{"case_id": 1}]}),
                    encoding="utf-8")
    with pytest.raises(ValueError):
        load_report(path)
