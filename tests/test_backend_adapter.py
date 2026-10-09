"""BE adapter: echo is never a result, secrets never leave, contracts are strict."""

import asyncio
import json
from dataclasses import replace

import httpx
import pytest

SUBMIT = "https://backend.example.invalid/skill"
RESULT = "https://backend.example.invalid/result/{job_id}"
FULL = dict(
    submit_url=SUBMIT, job_id_path=["jobId"], result_url_template=RESULT,
    result_evidence_path=["result", "evidence"], max_initial_s=1, max_result_s=1,
)
TOKEN = "synthetic-backend-token-do-not-leak"


def run(case, config, handler=None, transport=None):
    from isolation_tests.adapters.backend import probe_backend

    async def call():
        t = transport or httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=t) as client:
            return await probe_backend(case, config, client=client)

    return asyncio.run(call())


def with_contract(config, write_backend_contract, **overrides):
    return replace(config, backend_contract=write_backend_contract(**overrides))


def sent(request):
    return json.loads(request.content)["userRequest"]["utterance"]


def no_request(request):
    pytest.fail("no request expected")


def test_echo_response_is_not_e2e_success(backend_case, configured_backend):
    def handler(request):
        return httpx.Response(200, json={"version": "2.0", "template": {
            "outputs": [{"simpleText": {"text": "받았습니다: 합성 문자"}}]}})
    assert run(backend_case, configured_backend, handler).status == "blocked"


def test_real_echo_of_the_request_is_blocked_with_reason(backend_case, configured_backend):
    def handler(request):
        return httpx.Response(200, json={"text": "받았습니다: " + sent(request)})
    result = run(backend_case, configured_backend, handler)
    assert (result.status, result.reason) == ("blocked", "echo_response_not_result")
    assert result.details["echo_detected"] is True


def test_no_callback_url_is_injected(backend_case, configured_backend):
    seen = []

    def handler(request):
        seen.append(json.loads(request.content))
        return httpx.Response(200, json={})
    run(backend_case, configured_backend, handler)
    assert set(seen[0]) == {"userRequest"} and set(seen[0]["userRequest"]) == {"utterance"}


@pytest.mark.parametrize("name", [None, "missing.json"])
def test_missing_contract_is_blocked(backend_case, configured_backend, tmp_path, name):
    config = replace(configured_backend, backend_contract=None if name is None else tmp_path / name)
    result = run(backend_case, config, no_request)
    assert (result.status, result.reason) == ("blocked", "backend_contract_missing")


def test_null_submit_url_is_blocked(backend_case, configured_backend, write_backend_contract):
    config = with_contract(configured_backend, write_backend_contract, submit_url=None)
    assert run(backend_case, config, no_request).reason == "backend_submit_url_missing"


@pytest.mark.parametrize("overrides", [
    {"submit_url": "http://backend.example.invalid/skill"},
    {"submit_url": SUBMIT, "max_initial_s": 6},
    {"submit_url": SUBMIT, "max_result_s": 61},
    {"submit_url": SUBMIT, "max_initial_s": True},
    {"submit_url": SUBMIT, "utterance_path": []},
    {"submit_url": SUBMIT, "auth_env": "bad name"},
    {"submit_url": SUBMIT, "result_url_template": "https://other.example.invalid/{job_id}"},
    {"submit_url": SUBMIT, "result_url_template": "https://backend.example.invalid/result"},
])
def test_invalid_contract_is_blocked(backend_case, configured_backend, write_backend_contract, overrides):
    config = with_contract(configured_backend, write_backend_contract, **overrides)
    result = run(backend_case, config, no_request)
    assert (result.status, result.reason) == ("blocked", "backend_contract_invalid")


def test_duplicate_contract_fields_are_blocked(backend_case, configured_backend, tmp_path):
    path = tmp_path / "dup.json"
    path.write_text('{"submit_url": null, "submit_url": null}', encoding="utf-8")
    result = run(backend_case, replace(configured_backend, backend_contract=path), no_request)
    assert result.reason == "backend_contract_invalid"


def test_only_int03_is_supported(configured_backend, case_data):
    from isolation_tests.model import CaseSpec

    spec = CaseSpec(**{**case_data, "variants": tuple(case_data["variants"]),
                       "required_capabilities": (), "required_evidence": ()})
    assert run(spec, configured_backend, no_request).reason == "unsupported_case"


def linked_handler(*, evidence=True, pending=0):
    state = {"polls": 0, "run": None}

    def handler(request):
        if request.method == "POST":
            state["run"] = sent(request).split()[-1]
            return httpx.Response(200, json={"useCallback": True, "jobId": "job-1"})
        state["polls"] += 1
        if state["polls"] <= pending:
            return httpx.Response(404)
        text = f"합성 결과 {state['run']}" if evidence is True else evidence
        return httpx.Response(200, json={"result": {"evidence": text}})
    handler.state = state
    return handler


def test_linked_result_via_lookup_fallback_passes(backend_case, configured_backend, write_backend_contract):
    config = with_contract(configured_backend, write_backend_contract, **FULL)
    handler = linked_handler(pending=1)
    result = run(backend_case, config, handler)
    assert (result.status, result.reason) == ("passed", "backend_result_linked")
    assert result.details["callback_deferred"] is True
    assert result.details["first_response_deadline_ok"] is True
    assert handler.state["polls"] == 2


def test_result_for_another_run_is_failed(backend_case, configured_backend, write_backend_contract):
    config = with_contract(configured_backend, write_backend_contract, **FULL)
    result = run(backend_case, config, linked_handler(evidence="다른 실행의 결과"))
    assert (result.status, result.reason) == ("failed", "backend_result_not_linked")


def test_result_never_ready_times_out_failed(backend_case, configured_backend, write_backend_contract):
    config = with_contract(configured_backend, write_backend_contract, **{**FULL, "max_result_s": 0.3})
    result = run(backend_case, config, linked_handler(pending=10_000))
    assert (result.status, result.reason) == ("failed", "backend_result_timeout")


def test_wrong_result_json_path_is_blocked(backend_case, configured_backend, write_backend_contract):
    config = with_contract(configured_backend, write_backend_contract,
                           **{**FULL, "result_evidence_path": ["nope", 0], "max_result_s": 0.3})
    result = run(backend_case, config, linked_handler())
    assert (result.status, result.reason) == ("blocked", "backend_result_path_unresolved")


def test_job_id_path_unresolved_is_blocked(backend_case, configured_backend, write_backend_contract):
    config = with_contract(configured_backend, write_backend_contract, **{**FULL, "job_id_path": ["x"]})
    assert run(backend_case, config, linked_handler()).reason == "backend_job_id_unresolved"


def test_slow_first_response_is_failed(backend_case, configured_backend, write_backend_contract):
    config = with_contract(configured_backend, write_backend_contract, **{**FULL, "max_initial_s": 0.05})

    class Slow(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            await asyncio.sleep(0.2)
            return httpx.Response(200, json={}, request=request)

    result = run(backend_case, config, transport=Slow())
    assert (result.status, result.reason) == ("failed", "first_response_too_slow")
    assert result.details["first_response_deadline_ok"] is False


@pytest.mark.parametrize("status,expected", [
    (401, ("blocked", "backend_authentication_failed")),
    (503, ("failed", "backend_unavailable")),
    (418, ("failed", "backend_unexpected_status")),
    (302, ("failed", "backend_unexpected_status")),
])
def test_http_status_classification(backend_case, configured_backend, status, expected):
    result = run(backend_case, configured_backend, lambda r: httpx.Response(status))
    assert (result.status, result.reason) == expected


@pytest.mark.parametrize("body", [b"not json", b'{"a": 1, "a": 2}', b"NaN"])
def test_malformed_json_is_failed(backend_case, configured_backend, body):
    result = run(backend_case, configured_backend, lambda r: httpx.Response(200, content=body))
    assert result.reason == "backend_malformed_response"


def test_auth_header_sent_but_never_reported(backend_case, configured_backend, write_backend_contract, monkeypatch):
    monkeypatch.setenv("SYNTHETIC_BE_AUTH", TOKEN)
    config = with_contract(configured_backend, write_backend_contract,
                           auth_env="SYNTHETIC_BE_AUTH", submit_url=SUBMIT)
    headers = []

    def handler(request):
        headers.append(request.headers.get("authorization"))
        return httpx.Response(200, json={"text": sent(request)})
    result = run(backend_case, config, handler)
    assert headers == [f"Bearer {TOKEN}"]
    assert TOKEN not in repr(result)


def test_transport_error_with_token_text_is_translated(backend_case, configured_backend,
                                                        write_backend_contract, monkeypatch):
    monkeypatch.setenv("SYNTHETIC_BE_AUTH", TOKEN)
    config = with_contract(configured_backend, write_backend_contract,
                           auth_env="SYNTHETIC_BE_AUTH", submit_url=SUBMIT)

    def handler(request):
        raise httpx.ConnectError(f"boom Bearer {TOKEN}", request=request)
    result = run(backend_case, config, handler)
    assert (result.status, result.reason) == ("blocked", "backend_unreachable")
    assert TOKEN not in repr(result)


def test_missing_auth_env_value_is_blocked(backend_case, configured_backend, write_backend_contract, monkeypatch):
    monkeypatch.delenv("SYNTHETIC_BE_AUTH", raising=False)
    config = with_contract(configured_backend, write_backend_contract,
                           auth_env="SYNTHETIC_BE_AUTH", submit_url=SUBMIT)
    assert run(backend_case, config, no_request).reason == "backend_auth_missing"


def test_example_contract_has_only_null_placeholders():
    from pathlib import Path

    path = (Path(__file__).resolve().parents[1] / "tools" / "isolation-tests"
            / "backend-contract.example.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    for name in ("submit_url", "job_id_path", "result_url_template", "result_evidence_path", "auth_env"):
        assert data[name] is None


def test_result_that_only_echoes_the_sent_utterance_is_blocked(backend_case, configured_backend,
                                                                write_backend_contract):
    config = with_contract(configured_backend, write_backend_contract, **FULL)
    state = {}

    def handler(request):
        if request.method == "POST":
            state["text"] = sent(request)
            return httpx.Response(200, json={"useCallback": True, "jobId": "job-1"})
        return httpx.Response(200, json={"result": {"evidence": "저장됨: " + state["text"]}})
    result = run(backend_case, config, handler)
    assert (result.status, result.reason) == ("blocked", "echo_response_not_result")


def test_persistent_server_error_while_polling_is_unavailable(backend_case, configured_backend,
                                                               write_backend_contract):
    config = with_contract(configured_backend, write_backend_contract, **{**FULL, "max_result_s": 0.3})

    def handler(request):
        if request.method == "POST":
            return httpx.Response(200, json={"jobId": "job-1"})
        return httpx.Response(503)
    result = run(backend_case, config, handler)
    assert (result.status, result.reason) == ("failed", "backend_unavailable")


def test_httpx_timeout_is_a_failed_deadline_without_collector_wording(backend_case, configured_backend):
    def handler(request):
        raise httpx.ReadTimeout("slow", request=request)
    result = run(backend_case, configured_backend, handler)
    assert (result.status, result.reason) == ("failed", "backend_timeout")


def test_unexpected_stream_error_becomes_a_fixed_code(backend_case, configured_backend):
    def handler(request):
        raise httpx.StreamConsumed()
    result = run(backend_case, configured_backend, handler)
    assert (result.status, result.reason) == ("blocked", "backend_request_failed")


def test_utterance_path_must_be_string_keys(backend_case, configured_backend, write_backend_contract):
    config = with_contract(configured_backend, write_backend_contract, submit_url=SUBMIT,
                           utterance_path=["userRequest", 0])
    assert run(backend_case, config, no_request).reason == "backend_contract_invalid"
