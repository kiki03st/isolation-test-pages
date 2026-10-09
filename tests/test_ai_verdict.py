"""Deterministic verdict contract: signals count only when their evidence exists."""

import asyncio

import pytest

from isolation_tests.adapters.ai import AIUnavailable, verdict_contract


FOUND = {"login": {"state": "found", "items": []}}
RISK = {"code": "credential_request", "evidence_source": "observation", "evidence_ref": "login"}


def test_absent_observation_evidence_is_dropped():
    pytest.importorskip("ai")
    result = verdict_contract("not_registered", "rendered", "success", {}, [
        {"code": "credential_request", "evidence_source": "observation",
         "evidence_ref": "missing-element"}])
    assert result["final_state"] == "inconclusive"
    assert result["accepted_signals"] == []


@pytest.mark.parametrize("match, page_state, status, checks, signals, state, reason", [
    ("official", "rendered", "success", {}, [], "official_domain", "official_match"),
    ("not_registered", "rendered", "success", {}, [], "inconclusive", "not_in_whitelist"),
    ("not_registered", "rendered", "success", FOUND, [RISK], "smishing_suspected", "risk_signal"),
    ("official", "rendered", "success", FOUND, [RISK], "smishing_suspected", "official_but_risky"),
    ("unresolved", "rendered", "success", {}, [], "not_analyzable", "unresolved"),
    ("not_registered", "unreachable", "failed", {}, [], "not_analyzable", "unresolved"),
    ("not_registered", "rendered", "failed", {}, [], "not_analyzable", "unresolved"),
    ("no_url", "rendered", "success", {}, [], "input_required", "no_url"),
    ("brand_mismatch", "rendered", "success", {}, [], "smishing_suspected", "lookalike"),
])
def test_decision_table(match, page_state, status, checks, signals, state, reason):
    pytest.importorskip("ai")
    result = verdict_contract(match, page_state, status, checks, signals)
    assert (result["final_state"], result["reason_code"]) == (state, reason)


def test_verified_risk_is_reported_with_its_evidence():
    pytest.importorskip("ai")
    result = verdict_contract("not_registered", "rendered", "success", FOUND, [RISK])
    assert [s["evidence_ref"] for s in result["accepted_signals"]] == ["login"]
    assert set(result) == {"final_state", "reason_code", "accepted_signals"}


def test_check_that_was_not_found_gives_no_evidence():
    pytest.importorskip("ai")
    checks = {"login": {"state": "checked_absent", "items": []}}
    result = verdict_contract("not_registered", "rendered", "success", checks, [RISK])
    assert result["accepted_signals"] == []
    assert result["final_state"] == "inconclusive"


def test_message_signal_without_text_in_message_is_dropped():
    pytest.importorskip("ai")
    signal = {"code": "credential_request", "evidence_source": "message",
              "evidence_ref": "not in the synthetic message"}
    result = verdict_contract("not_registered", "rendered", "success", {}, [signal])
    assert result["accepted_signals"] == []


def test_official_domain_is_not_flipped_by_a_message_quote():
    pytest.importorskip("ai")
    signal = {"code": "credential_request", "evidence_source": "message",
              "evidence_ref": "합성 조회 안내"}
    result = verdict_contract("official", "rendered", "success", {}, [signal])
    assert result["final_state"] == "official_domain"


def test_model_cannot_mint_the_synthetic_expired_signal():
    pytest.importorskip("ai")
    signal = {"code": "expired_link", "evidence_source": "observation", "evidence_ref": "login"}
    result = verdict_contract("not_registered", "rendered", "success", FOUND, [signal])
    assert result["accepted_signals"] == []
    assert result["final_state"] == "inconclusive"


def test_cloaked_page_evidence_is_not_trusted():
    pytest.importorskip("ai")
    result = verdict_contract("not_registered", "cloaked_suspect", "success", FOUND, [RISK])
    assert result["final_state"] == "inconclusive"
    assert result["accepted_signals"] == []


def test_final_state_vocabulary_is_the_product_contract():
    ai_types = pytest.importorskip("ai.types")
    assert {s.value for s in ai_types.FinalState} == {
        "smishing_suspected", "official_domain", "inconclusive", "not_analyzable",
        "input_required"}


def test_analysis_response_result_is_a_bool_and_false_without_message_part():
    pytest.importorskip("ai")
    from types import SimpleNamespace

    from ai.pipeline.finalize import finalize_analysis
    from ai.types import DomainMatch, IsolatedPage, PageProposal, UrlAnalysis

    async def parse(**kwargs):
        return SimpleNamespace(choices=[SimpleNamespace(
            message=SimpleNamespace(parsed=PageProposal(), refusal=None))])

    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(parse=parse)))
    url = UrlAnalysis(final_url="https://example.invalid/", domain="example.invalid",
                      official=DomainMatch.OFFICIAL)
    page = IsolatedPage(brand="unknown", category="unknown", info="<p>합성 조회 결과입니다</p>")
    response = asyncio.run(finalize_analysis(url, None, page, client=client, model="fixture"))
    assert response.result is False


def test_absent_ai_reports_unavailable_not_a_verdict(monkeypatch):
    import sys

    for name in [n for n in sys.modules if n == "ai" or n.startswith("ai.")]:
        monkeypatch.setitem(sys.modules, name, None)
    monkeypatch.setitem(sys.modules, "ai", None)
    with pytest.raises(AIUnavailable):
        verdict_contract("official", "rendered", "success", {}, [])
