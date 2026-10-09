"""Optional AI adapter: absent AI is blocked, present AI is judged by its own rules."""

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from isolation_tests.adapters.ai import (AIUnavailable, analyze_locally, boundary_results,
                                         inspect_locally, paired_verdicts_equal)
from isolation_tests.model import CollectedPage, Outcome


ROOT = Path(__file__).resolve().parents[1]
PAGES = ROOT / "test-pages" / "v1" / "cases"
TOOLS = str(ROOT / "tools" / "isolation-tests")
FINANCIAL = ('<main><form action="./unsubmitted" method="post">'
             '<label>계좌 비밀번호를 입력해 주세요 <input type="password" name="pw"></label>'
             '</form></main>')


def fake_llm(parsed=None, error=None):
    async def parse(**kwargs):
        if error is not None:
            raise error
        return SimpleNamespace(choices=[SimpleNamespace(
            message=SimpleNamespace(parsed=parsed, refusal=None))])
    return SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(parse=parse)))


@pytest.fixture(scope="module")
def cases():
    from isolation_tests.manifest import load_cases

    return {c.id: c for c in load_cases(ROOT / "tools/isolation-tests/cases.json")}


def collected(html):
    return CollectedPage("https://example.invalid/", "https://example.invalid/", (), 200,
                         "text/html", html, None, 5, ())


def sample(case_id, variant):
    return collected((PAGES / case_id.lower() / f"{variant}.html").read_text(encoding="utf-8"))


def run(case, variant, page, **kwargs):
    return asyncio.run(analyze_locally(case, variant, page, **kwargs))


def poison_ai(monkeypatch):
    for name in [n for n in sys.modules if n == "ai" or n.startswith("ai.")]:
        monkeypatch.setitem(sys.modules, name, None)
    monkeypatch.setitem(sys.modules, "ai", None)


def python(code):
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUTF8": "1"}
    return subprocess.run([sys.executable, "-c", code, TOOLS], capture_output=True, text=True,
                          env=env, check=True).stdout.strip()


# --- optional dependency -------------------------------------------------

def test_module_imports_without_touching_ai():
    out = python("import sys; sys.path.insert(0, sys.argv[1]);"
                 "import isolation_tests.adapters.ai;"
                 "print([n for n in sys.modules if n == 'ai' or n.startswith('ai.')])")
    assert out == "[]"


def test_module_imports_when_ai_cannot_be_imported():
    out = python("import sys; sys.modules['ai'] = None; sys.path.insert(0, sys.argv[1]);"
                 "import isolation_tests.adapters.ai; print('ok')")
    assert out == "ok"


def test_absent_ai_inspect_raises_typed_error(monkeypatch):
    poison_ai(monkeypatch)
    with pytest.raises(AIUnavailable):
        inspect_locally(collected("<p>합성</p>"))


def test_absent_ai_analysis_is_blocked_not_passed(monkeypatch, cases):
    poison_ai(monkeypatch)
    outcome = run(cases["ANA-01"], "default", sample("ana-01", "index"))
    assert (outcome.status, outcome.reason) == ("blocked", "ai_unavailable")
    assert outcome.case_id == "ANA-01" and outcome.variant == "default"


def test_absent_ai_blocks_limit_and_fabricated_cases(monkeypatch, cases):
    poison_ai(monkeypatch)
    assert run(cases["LIM-04"], "text", None).reason == "ai_unavailable"
    assert run(cases["ANA-08"], "absent-evidence", None).reason == "ai_unavailable"
    with pytest.raises(AIUnavailable):
        boundary_results("text")


# --- inspect_locally -----------------------------------------------------

def test_inspect_locally_returns_only_the_four_keys():
    pytest.importorskip("ai")
    result = inspect_locally(collected(FINANCIAL))
    assert set(result) == {"text", "doubts", "elements", "failure"}
    assert result["failure"] is None
    assert result["doubts"] == ["로그인·인증 입력폼"]
    assert len(result["elements"]) == 1 and result["elements"][0]["element_id"].startswith("element-")
    json.dumps(result, ensure_ascii=False)


def test_inspect_locally_reports_failure_code_not_exception():
    pytest.importorskip("ai")
    assert inspect_locally(collected(""))["failure"] == "empty_input"
    assert inspect_locally(collected("x" * 131073))["failure"] == "input_too_large"


def test_inspect_locally_does_not_expose_script_text():
    pytest.importorskip("ai")
    result = inspect_locally(collected("<p>합성 안내</p><script>alert('x')</script>"))
    assert "alert" not in result["text"]


# --- analyze_locally against the real AI rules ---------------------------

def test_default_fixed_proposal_is_used_without_a_client(cases):
    pytest.importorskip("ai")
    outcome = run(cases["ANA-01"], "default", sample("ana-01", "index"))
    assert outcome.status == "passed", outcome
    assert outcome.details["verdict"]["final_state"] == "inconclusive"


def test_address_page_reports_its_doubt_and_no_risk(cases):
    pytest.importorskip("ai")
    outcome = run(cases["ANA-02"], "default", sample("ana-02", "default"))
    assert outcome.status == "passed", outcome
    assert "주소 입력폼" in outcome.details["doubts"]


@pytest.mark.parametrize("variant", ["warning", "negation", "quotation"])
def test_warning_negation_quotation_reject_model_proposals(cases, variant):
    pytest.importorskip("ai")
    outcome = run(cases["ANA-06"], variant, sample("ana-06", variant))
    assert outcome.status == "passed", outcome
    assert outcome.details["accepted_codes"] == []
    assert outcome.details["verdict"]["final_state"] == "inconclusive"


def test_warning_text_with_explicit_install_proposal_is_still_rejected(cases):
    pytest.importorskip("ai")
    from ai.types import EvidenceSource, PageProposal, RiskSignal, RiskSignalCode

    page = collected('<a href="https://example.invalid/x">앱을 설치하지 마세요</a>')
    ids = inspect_locally(page)["elements"]
    assert ids, "the warning link must be an inspected element"
    parsed = PageProposal(signals=[RiskSignal(
        code=RiskSignalCode.INSTALL_PROMPT, evidence_source=EvidenceSource.OBSERVATION,
        evidence_ref=ids[0]["element_id"])])
    outcome = run(cases["ANA-06"], "warning", page, client=fake_llm(parsed))
    assert outcome.status == "passed", outcome
    assert outcome.details["accepted_codes"] == []


def test_generic_password_expectation_is_not_lowered_and_reports_current_mismatch(cases):
    """Ruling (b): the canonical generic password risk stays; a rejecting AI fails it."""
    pytest.importorskip("ai")
    case = cases["ANA-03"]
    assert case.expected_analysis["variants"]["password"]["final_state"] == "smishing_suspected"
    outcome = run(case, "password", sample("ana-03", "password"))
    assert outcome.status == "failed", outcome
    assert outcome.reason == "analysis_mismatch"
    assert "final_state" in outcome.details["mismatches"]
    assert "required_signal:credential_request" in outcome.details["mismatches"]


def test_explicit_financial_fixture_branch_accepts_the_risk(cases):
    pytest.importorskip("ai")
    outcome = run(cases["ANA-03"], "password", collected(FINANCIAL))
    assert outcome.status == "passed", outcome
    assert outcome.details["accepted_codes"] == ["credential_request"]
    assert outcome.details["verdict"] == {
        "final_state": "smishing_suspected", "reason_code": "risk_signal"}


def test_app_install_page_mismatch_is_reported_not_concealed(cases):
    """The current AI does not classify the sample.apk link; the case must say so."""
    pytest.importorskip("ai")
    outcome = run(cases["ANA-04"], "default", sample("ana-04", "default"))
    wanted = "앱 다운로드 링크"
    if wanted in outcome.details["doubts"]:
        return
    assert outcome.status == "failed"
    assert f"required_doubt:{wanted}" in outcome.details["mismatches"]


def test_response_result_flag_is_recorded(cases):
    pytest.importorskip("ai")
    outcome = run(cases["ANA-01"], "default", sample("ana-01", "index"))
    assert outcome.details["response_result"] is False


def test_fabricated_evidence_is_rejected_by_both_layers(cases):
    pytest.importorskip("ai")
    outcome = run(cases["ANA-08"], "absent-evidence", None)
    assert outcome.status == "passed", outcome
    assert outcome.details["fabricated_evidence_rejected"] is True
    assert outcome.details["verdict"]["final_state"] == "inconclusive"


def test_fabricated_evidence_check_fails_when_a_proposal_is_not_filtered(cases, monkeypatch):
    pytest.importorskip("ai")
    import ai.verdict

    monkeypatch.setattr(ai.verdict, "_accept_signals", lambda text, obs, signals: tuple(signals))
    outcome = run(cases["ANA-08"], "absent-evidence", None)
    assert outcome.status == "failed"
    assert outcome.details["fabricated_evidence_rejected"] is False


# --- failure paths ---------------------------------------------------------

def test_llm_timeout_falls_back_without_changing_the_verdict(cases):
    pytest.importorskip("ai")
    outcome = run(cases["INT-04"], "llm-timeout", sample("ana-01", "index"),
                  client=fake_llm(error=TimeoutError()))
    assert outcome.status == "passed", outcome
    assert outcome.details["failure_codes"] == ["llm_timeout"]
    assert outcome.details["verdict"]["final_state"] == "inconclusive"


def test_collection_failure_is_not_analyzable_with_existing_failure_code(cases):
    pytest.importorskip("ai")
    outcome = run(cases["INT-04"], "collection-failure", None)
    assert outcome.status == "passed", outcome
    assert outcome.details["failure_codes"] == ["collection_failed"]
    assert outcome.details["verdict"] == {
        "final_state": "not_analyzable", "reason_code": "unresolved"}


def test_non_analysis_variant_is_blocked(cases):
    pytest.importorskip("ai")
    outcome = run(cases["INT-04"], "callback-failure", None)
    assert (outcome.status, outcome.reason) == ("blocked", "no_analysis_contract")


def test_unknown_variant_is_blocked(cases):
    pytest.importorskip("ai")
    assert run(cases["ANA-01"], "nope", None).status == "blocked"


def test_invalid_model_output_does_not_pass_an_expected_risk(cases):
    pytest.importorskip("ai")
    outcome = run(cases["ANA-03"], "password", collected(FINANCIAL), client=fake_llm(parsed=None))
    assert outcome.status == "failed"
    assert outcome.details["ai_failure"] == "invalid_output"


# --- ANA-07 pairing --------------------------------------------------------

def test_pair_with_same_verdict_is_equal(cases):
    pytest.importorskip("ai")
    a = run(cases["ANA-07"], "baseline", sample("ana-07", "baseline"))
    b = run(cases["ANA-07"], "injection", sample("ana-07", "injection"))
    assert paired_verdicts_equal(a, b) is True


def test_pair_with_different_verdict_is_not_equal():
    base = Outcome("ANA-07", "baseline", "passed", "x",
                   {"verdict": {"final_state": "smishing_suspected", "reason_code": "risk_signal"},
                    "accepted_codes": ["credential_request"]})
    other = Outcome("ANA-07", "injection", "passed", "x",
                    {"verdict": {"final_state": "inconclusive", "reason_code": "not_in_whitelist"},
                     "accepted_codes": []})
    assert paired_verdicts_equal(base, other) is False
    assert paired_verdicts_equal(base, Outcome("ANA-07", "i", "blocked", "x", {})) is False


# --- LIM-04 ----------------------------------------------------------------

@pytest.mark.parametrize("metric, limit", [("bytes", 131072), ("elements", 2000),
                                           ("text", 16000), ("depth", 64), ("result", 262144)])
def test_boundary_constants_come_from_the_ai(metric, limit):
    pytest.importorskip("ai")
    result = boundary_results(metric)
    assert result["boundary_limit"] == limit
    assert result["boundary_offsets"] == [-1, 0, 1]
    assert [row["offset"] for row in result["rows"]] == [-1, 0, 1]


@pytest.mark.parametrize("metric, code", [("bytes", "input_too_large"), ("elements", "partial_content"),
                                          ("text", "partial_content"), ("depth", "partial_content")])
def test_one_past_the_limit_reports_its_failure_code(metric, code):
    pytest.importorskip("ai")
    rows = boundary_results(metric)["rows"]
    assert rows[2]["failure"] == code
    assert all(row["failure"] != code for row in rows[:2])


def test_text_boundary_preserves_the_limited_text():
    pytest.importorskip("ai")
    rows = boundary_results("text")["rows"]
    assert [row["text_chars"] for row in rows] == [15999, 16000, 16000]


def test_boundary_outcome_reports_facts_for_evaluation(cases):
    pytest.importorskip("ai")
    outcome = run(cases["LIM-04"], "text", None)
    assert outcome.status == "passed", outcome
    assert outcome.details["facts"]["boundary_results_ok"] is True
    assert outcome.details["facts"]["boundary_limit"] == 16000


def test_result_boundary_failure_is_reported_not_hidden(cases):
    """The result sample at limit-1/limit already trips the AI's stricter budget."""
    pytest.importorskip("ai")
    outcome = run(cases["LIM-04"], "result", None)
    assert outcome.status in {"passed", "failed"}
    assert outcome.details["facts"]["boundary_results_ok"] is (outcome.status == "passed")


# --- merging with the evidence-based result (evaluate.py) -----------------------------

def _outcome(status, reason="r", **details):
    return Outcome("ANA-01", "default", status, reason, details)


@pytest.mark.parametrize("base, analysis, status", [
    ("passed", "passed", "passed"),
    ("passed", "failed", "failed"),
    ("passed", "blocked", "blocked"),
    ("failed", "passed", "failed"),
    ("blocked", "failed", "failed"),
    ("blocked", "passed", "blocked"),
    ("passed", None, "blocked"),
])
def test_merge_analysis_never_hides_a_worse_result(cases, base, analysis, status):
    from isolation_tests.evaluate import merge_analysis

    merged = merge_analysis(cases["ANA-01"], "default", _outcome(base),
                            None if analysis is None else _outcome(analysis, "analysis_reason"))
    assert merged.status == status
    if analysis is None:
        assert merged.reason == "analysis_missing"


def test_merge_analysis_keeps_both_details(cases):
    from isolation_tests.evaluate import merge_analysis

    merged = merge_analysis(cases["ANA-01"], "default", _outcome("passed", seen=1),
                            _outcome("failed", "analysis_mismatch", mismatches=["x"]))
    assert merged.reason == "analysis_mismatch"
    assert merged.details["seen"] == 1 and merged.details["analysis"]["mismatches"] == ["x"]


def test_merge_analysis_ignores_cases_without_an_analysis_contract(cases):
    from isolation_tests.evaluate import merge_analysis

    base = Outcome("COL-01", "default", "passed", "ok", {})
    assert merge_analysis(cases["COL-01"], "default", base, None) is base
