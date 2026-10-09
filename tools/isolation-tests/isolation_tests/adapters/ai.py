"""Optional adapter to the team's AI package; the package is never required.

``ai`` is imported inside functions only, so this module (and the CLI) loads
without it. Product parsing and verdict rules are used as they are: the test
tool reports a mismatch with a case contract, it never changes the rules.

Model proposals are never trusted. The default client is a fixed, offline
proposal that offers every observation signal for every inspected element (plus
one fabricated reference for ANA-08); only what the AI's own validation and
``decide()`` accept can reach a result.
"""

from types import SimpleNamespace

from ..model import CaseSpec, CollectedPage, Outcome


FIXTURE_MODEL = "fixture"
_FABRICATED_REF = "missing-element"
_SYNTHETIC_MESSAGE = "합성 조회 안내"
_SYNTHETIC_DOMAIN = "example.invalid"
_BENIGN_PAGE = "<main><p>합성 조회 결과입니다. 조치할 내용이 없습니다.</p></main>"
_PROPOSED_CODES = ("install_prompt", "credential_request", "remote_control")
_LIMIT_FAILURE = {"bytes": "input_too_large"}  # other metrics: partial_content
_OFFSETS = [-1, 0, 1]


class AIUnavailable(RuntimeError):
    """The optional AI package cannot be imported."""

    def __init__(self):
        super().__init__("ai_unavailable")


def _load() -> SimpleNamespace:
    try:
        import ai.page
        import ai.llm.page
        import ai.pipeline.finalize
        import ai.types
        import ai.verdict
    except ImportError:
        raise AIUnavailable() from None
    return SimpleNamespace(page=ai.page, types=ai.types, verdict=ai.verdict,
                           analyze_page=ai.llm.page.analyze_page,
                           finalize=ai.pipeline.finalize.finalize_analysis)


def _blocked(case_id, variant, reason, **details) -> Outcome:
    return Outcome(case_id, variant, "blocked", reason, details)


# --- inspection ----------------------------------------------------------------

def _inspect(ai, html: str):
    """The AI's inspection, or None when the text cannot be encoded as UTF-8."""
    try:
        return ai.page.inspect_html(html)
    except ValueError:
        return None


def inspect_locally(page: CollectedPage) -> dict:
    ai = _load()
    inspected = _inspect(ai, page.html)
    if inspected is None:
        return {"text": "", "doubts": [], "elements": [], "failure": "invalid_html"}
    ordered = sorted(inspected.elements, key=lambda item: item.start)
    return {
        "text": inspected.text,
        "doubts": list(dict.fromkeys(item.doubt.value for item in ordered)),
        "elements": [{"element_id": item.element_id, "doubt": item.doubt.value,
                      "tag": item.tag, "text": item.text} for item in ordered],
        "failure": inspected.failure.value if inspected.failure else None,
    }


# --- deterministic verdict -----------------------------------------------------

def verdict_contract(match: str, page_state: str, status: str, checks: dict,
                     signals: list[dict]) -> dict:
    ai = _load()
    t = ai.types
    verdict = ai.verdict.decide(
        _SYNTHETIC_MESSAGE,
        t.MessageAnalysis(analysis_status="completed"),
        t.DomainCheck(match=match, checked_domain=_SYNTHETIC_DOMAIN),
        t.Observations(status=status, source="fixture", page_state=page_state, checks=checks),
        [t.RiskSignal.model_validate(s) for s in signals])
    return {"final_state": verdict.final_state.value,
            "reason_code": verdict.reason_code.value,
            "accepted_signals": [s.model_dump(mode="json") for s in verdict.accepted_signals]}


# --- model client ----------------------------------------------------------------

def _client(parse) -> SimpleNamespace:
    return SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(parse=parse)))


def _fixed_client(ai, inspection, fabricated: bool) -> SimpleNamespace:
    t = ai.types
    refs = [item.element_id for item in inspection.elements]
    if fabricated:
        refs.append(_FABRICATED_REF)
    proposal = t.PageProposal(signals=[
        t.RiskSignal(code=code, evidence_source="observation", evidence_ref=ref)
        for ref in refs for code in _PROPOSED_CODES])

    async def parse(**_kwargs):
        return SimpleNamespace(choices=[SimpleNamespace(
            message=SimpleNamespace(parsed=proposal, refusal=None))])

    return _client(parse)


def _once(client) -> SimpleNamespace:
    """Answer the second page analysis from the first call (no second model request)."""
    memo: list = []

    async def parse(**kwargs):
        if not memo:
            try:
                memo.append((True, await client.chat.completions.parse(**kwargs)))
            except Exception as error:
                memo.append((False, error))
        ok, value = memo[0]
        if ok:
            return value
        raise value

    return _client(parse)


# --- analysis ----------------------------------------------------------------------

def _contract(case: CaseSpec, variant: str):
    analysis = case.expected_analysis.get("variants", {}).get(variant)
    observed = case.expected_observations.get("variants", {}).get(variant, {})
    return analysis, observed


def _compare(contract: dict, assertions: dict, doubts, codes, verdict, failure_codes) -> list[str]:
    mismatches = []
    mismatches += [f"required_doubt:{d}" for d in contract.get("required_doubts", ()) if d not in doubts]
    mismatches += [f"required_signal:{c}" for c in contract.get("required_signal_codes", ()) if c not in codes]
    mismatches += [f"forbidden_signal:{c}" for c in contract.get("forbidden_signal_codes", ()) if c in codes]
    if verdict["final_state"] != contract["final_state"]:
        mismatches.append("final_state")
    if verdict["reason_code"] != contract.get("reason_code"):
        mismatches.append("reason_code")
    mismatches += [f"failure_code:{c}" for c in assertions.get("failure_codes", ()) if c not in failure_codes]
    return mismatches


async def analyze_locally(case: CaseSpec, variant: str, page: CollectedPage | None,
                          *, client=None, model: str = FIXTURE_MODEL) -> Outcome:
    try:
        ai = _load()
    except AIUnavailable:
        return _blocked(case.id, variant, "ai_unavailable")
    if variant not in case.variants:
        return _blocked(case.id, variant, "unknown_variant")
    if case.id == "LIM-04":
        return _limit_outcome(case, variant)
    contract, observed = _contract(case, variant)
    if not isinstance(contract, dict) or contract.get("final_state") is None:
        return _blocked(case.id, variant, "no_analysis_contract")
    inputs = observed.get("inputs", {})
    assertions = observed.get("assertions", {})
    t = ai.types
    try:
        match = t.DomainMatch(inputs.get("domain_match", "not_registered"))
    except ValueError:
        return _blocked(case.id, variant, "invalid_inputs")

    fabricated = case.id == "ANA-08"
    html = page.html if page is not None else (_BENIGN_PAGE if fabricated else "")
    collection_failed = (page is None and not fabricated) or (
        page is not None and bool(page.failures) and not page.html)
    failure_codes: list[str] = []
    inspection = llm = analysis = None
    ai_failure = None
    if collection_failed:
        ai_failure = failure = t.FailureCode.COLLECTION_FAILED
        failure_codes.append("collection_failed")
        isolated = None
    else:
        failure = None
        isolated = t.IsolatedPage(brand="unknown", category="unknown", info=html)
        inspection = _inspect(ai, html)
        if inspection is None:
            return _blocked(case.id, variant, "invalid_html")
        llm = _once(client if client is not None else _fixed_client(ai, inspection, fabricated))
        if inspection.failure is None:
            analysis = await ai.analyze_page(inspection, client=llm, model=model)
        ai_failure = inspection.failure or (analysis.failure if analysis else None)
        if inspection.failure is not None:
            failure_codes.append(inspection.failure.value)
        elif analysis is not None and analysis.failure is not None:
            failure_codes.append("llm_timeout" if analysis.failure is t.FailureCode.TIMEOUT
                                 else analysis.failure.value)

    url = t.UrlAnalysis(final_url=(page.final_url or page.input_url) if page else "https://example.invalid/",
                        domain=_SYNTHETIC_DOMAIN, official=match)
    response = await ai.finalize(url, None, isolated, failure=failure,
                                 client=llm, model=model)

    elements = list(inspection.elements) if inspection else []
    validated = [s.model_dump(mode="json") for s in (analysis.signals if analysis else [])]
    proposed = list(validated)
    if fabricated:
        proposed.append({"code": "credential_request", "evidence_source": "observation",
                         "evidence_ref": _FABRICATED_REF})
    checks = {e.element_id: {"state": "found", "items": []} for e in elements}
    status = inputs.get("observation_status", "failed" if collection_failed else "success")
    page_state = inputs.get("page_state", "unreachable" if collection_failed else "rendered")
    try:
        verdict = verdict_contract(match.value, page_state, status, checks, proposed)
    except ValueError:
        return _blocked(case.id, variant, "invalid_inputs")
    accepted = verdict.pop("accepted_signals")
    accepted_codes = [s["code"] for s in accepted]
    doubts = list(dict.fromkeys(e.doubt.value for e in sorted(elements, key=lambda i: i.start)))
    mismatches = _compare(contract, assertions, doubts, accepted_codes, verdict, failure_codes)
    details = {
        "doubts": doubts, "accepted_codes": accepted_codes, "verdict": verdict,
        "failure_codes": failure_codes, "ai_failure": ai_failure.value if ai_failure else None,
        "response_result": response.result, "env_answer": response.env.answer.value,
        "facts": {"analysis": True},
    }
    if fabricated:
        rejected = all(s["evidence_ref"] != _FABRICATED_REF for s in accepted)
        details["fabricated_evidence_rejected"] = rejected
        details["facts"]["fabricated_evidence_rejected"] = rejected
        if not rejected:
            mismatches.append("fabricated_evidence_accepted")
    if response.result is not False:
        mismatches.append("response_result")
    if failure_codes or ai_failure:
        details["facts"]["fallback_ok"] = not mismatches
    if mismatches:
        return Outcome(case.id, variant, "failed", "analysis_mismatch",
                       {**details, "mismatches": mismatches})
    return Outcome(case.id, variant, "passed", "analysis_expectations_met", details)


def paired_verdicts_equal(first: Outcome, second: Outcome) -> bool:
    """ANA-07: the same required behavior must give the same verdict and signals."""
    keys = ("verdict", "accepted_codes")
    if first.status == "blocked" or second.status == "blocked":
        return False
    return all(key in first.details and first.details.get(key) == second.details.get(key)
               for key in keys) and all(key in second.details for key in keys)


# --- LIM-04 boundaries ---------------------------------------------------------------

def _limits(ai) -> dict[str, int]:
    page = ai.page
    return {"bytes": page.MAX_HTML_BYTES, "elements": page.MAX_ELEMENTS,
            "text": page.MAX_PAGE_TEXT_CHARS, "depth": page.MAX_DEPTH,
            "result": page.MAX_INSPECTION_BYTES}


def boundary_results(metric: str) -> dict:
    """Inspect limit-1, limit and limit+1 with the AI's own constants."""
    ai = _load()
    from ..fixtures import CalibrationUnavailable, boundary_html

    limit = _limits(ai)[metric]
    rows = []
    for offset in _OFFSETS:
        try:
            html = boundary_html(metric, limit + offset).decode("utf-8")
        except CalibrationUnavailable:
            raise AIUnavailable() from None
        inspected = ai.page.inspect_html(html)
        rows.append({"offset": offset, "html_bytes": len(html.encode("utf-8")),
                     "failure": inspected.failure.value if inspected.failure else None,
                     "text_chars": len(inspected.text), "elements": len(inspected.elements)})
    code = _LIMIT_FAILURE.get(metric, "partial_content")
    ok = all((row["failure"] == code) == (row["offset"] > 0) for row in rows)
    if metric == "text":
        ok = ok and [r["text_chars"] for r in rows] == [limit - 1, limit, limit]
    if metric == "result":
        ok = ok and rows[2]["elements"] > 0
    return {"boundary_offsets": list(_OFFSETS), "boundary_limit": limit,
            "boundary_results_ok": ok, "rows": rows}


def _limit_outcome(case: CaseSpec, variant: str) -> Outcome:
    try:
        result = boundary_results(variant)
    except AIUnavailable:
        return _blocked(case.id, variant, "ai_unavailable")
    facts = {"analysis": True, **{k: v for k, v in result.items() if k != "rows"}}
    status, reason = (("passed", "boundaries_observed") if result["boundary_results_ok"]
                      else ("failed", "boundary_mismatch"))
    return Outcome(case.id, variant, status, reason, {"facts": facts, "rows": result["rows"]})
