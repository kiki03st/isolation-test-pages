"""Backend (BE) adapter for the INT-03 pipeline variant.

No product result contract exists yet, so the adapter only follows what an
operator writes into the contract file. Without a result path (or when the
response merely echoes the request) the end-to-end result is ``blocked``; it is
never inferred. Failures are translated to fixed codes: no header, token or
exception text reaches an Outcome, and results are returned from outside the
``except`` blocks so no exception context can carry credentials.
"""

import asyncio
import json
import os
import re
import secrets
import ssl
import time
from urllib.parse import urlsplit

import certifi
import httpx

from ..config import _unique_object, _url
from ..model import CaseSpec, Outcome, RuntimeConfig
from .collector import HARD_RESPONSE_BYTES, CollectionError


CASE_ID = "INT-03"
VARIANT = "pipeline"
CONTRACT_FIELDS = frozenset({
    "submit_url", "utterance_path", "initial_callback_flag_path", "job_id_path",
    "result_url_template", "result_evidence_path", "auth_env", "max_initial_s", "max_result_s",
})
MAX_INITIAL_S = 5
MAX_RESULT_S = 60
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_TOKEN = re.compile(r"[\x21-\x7e]{1,4096}\Z")
_JOB_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_MISSING = object()


class _Stop(Exception):
    def __init__(self, status: str, code: str, **details):
        super().__init__(code)
        self.status, self.code, self.details = status, code, details


def _blocked(code, **details):
    return _Stop("blocked", code, **details)


def _failed(code, **details):
    return _Stop("failed", code, **details)


# --- contract ------------------------------------------------------------------

def _path_ok(value, nullable: bool) -> bool:
    if value is None:
        return nullable
    return (isinstance(value, list) and 0 < len(value) <= 16 and all(
        (isinstance(item, str) and item) or (type(item) is int and item >= 0) for item in value))


def _number(value, upper) -> bool:
    return type(value) in (int, float) and 0 < value <= upper


def load_contract(path, allow_loopback_http: bool = False) -> dict:
    if path is None:
        raise _blocked("backend_contract_missing")
    try:
        data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    except FileNotFoundError:
        raise _blocked("backend_contract_missing") from None
    except (OSError, ValueError):
        raise _blocked("backend_contract_invalid") from None
    if not isinstance(data, dict) or set(data) != CONTRACT_FIELDS:
        raise _blocked("backend_contract_invalid")
    valid = (
        _path_ok(data["utterance_path"], False)
        and all(isinstance(step, str) for step in data["utterance_path"])
        and _path_ok(data["initial_callback_flag_path"], True)
        and _path_ok(data["job_id_path"], True)
        and _path_ok(data["result_evidence_path"], True)
        and (data["auth_env"] is None or (isinstance(data["auth_env"], str)
                                          and _ENV_NAME.fullmatch(data["auth_env"])))
        and _number(data["max_initial_s"], MAX_INITIAL_S)
        and _number(data["max_result_s"], MAX_RESULT_S)
    )
    if not valid:
        raise _blocked("backend_contract_invalid")
    if data["submit_url"] is None:
        raise _blocked("backend_submit_url_missing")
    try:
        _url(data["submit_url"], allow_loopback_http)
        template = data["result_url_template"]
        if template is not None:
            if not isinstance(template, str) or template.count("{job_id}") != 1:
                raise ValueError("template")
            probe = _url(template.replace("{job_id}", "x"), allow_loopback_http)
            first, second = urlsplit(data["submit_url"]), urlsplit(probe)
            # Credentials are only ever sent back to the origin they were meant for.
            if (first.scheme, first.netloc.lower()) != (second.scheme, second.netloc.lower()):
                raise ValueError("origin")
    except ValueError:
        raise _blocked("backend_contract_invalid") from None
    return data


def _resolve(document, path):
    """Generic JSON path: string keys for objects, integers for arrays."""
    current = document
    for step in path:
        if isinstance(step, int) and isinstance(current, list) and step < len(current):
            current = current[step]
        elif isinstance(step, str) and isinstance(current, dict) and step in current:
            current = current[step]
        else:
            return _MISSING
    return current


def _request_body(path, text):
    body: dict = {}
    cursor = body
    for step in path[:-1]:
        cursor = cursor.setdefault(step, {})
    cursor[path[-1]] = text
    return body


def _contains(value, marker: str) -> bool:
    if isinstance(value, str):
        return marker in value
    if isinstance(value, dict):
        return any(_contains(item, marker) for item in value.values())
    if isinstance(value, list):
        return any(_contains(item, marker) for item in value)
    return False


def _headers(contract: dict) -> dict[str, str]:
    name = contract["auth_env"]
    headers = {"accept-encoding": "identity"}
    if name is None:
        return headers
    token = os.environ.get(name)
    if not token:
        raise _blocked("backend_auth_missing")
    if not _TOKEN.fullmatch(token):
        raise _blocked("backend_auth_invalid")
    headers["authorization"] = f"Bearer {token}"
    return headers


def _reject_constant(_name):
    raise ValueError("non-finite number")


async def _read_limited(response: httpx.Response) -> bytes:
    if response.headers.get("content-encoding", "identity").strip().lower() != "identity":
        raise CollectionError("unsupported_response_encoding")
    buffer = bytearray()
    # aiter_bytes also serves bodies that were fully read by the transport.
    async for part in response.aiter_bytes():
        if len(buffer) + len(part) > HARD_RESPONSE_BYTES:
            raise CollectionError("runner_response_too_large")
        buffer.extend(part)
    return bytes(buffer)


async def _json(response: httpx.Response):
    status = response.status_code
    if status in {401, 403}:
        raise _blocked("backend_authentication_failed")
    if status >= 500:
        raise _failed("backend_unavailable")
    if status != 200:
        raise _failed("backend_unexpected_status")
    raw = await _read_limited(response)
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                          parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise _failed("backend_malformed_response") from None


# --- flow ----------------------------------------------------------------------

async def _poll(client, contract, headers, job_id, run_id, text, started, details):
    """The lookup fallback: the callback is one-shot, so the stored result is polled."""
    url = contract["result_url_template"].replace("{job_id}", job_id)
    limit = started + contract["max_initial_s"] + contract["max_result_s"]
    interval = min(0.5, contract["max_result_s"] / 4)
    path_unresolved = False
    server_error = False
    while time.monotonic() <= limit:
        response = await client.send(client.build_request("GET", url, headers=headers),
                                     stream=True, follow_redirects=False)
        try:
            if response.status_code in {401, 403}:
                raise _blocked("backend_authentication_failed", **details)
            pending = response.status_code != 200
            server_error = response.status_code >= 500
            document = _MISSING if pending else await _json(response)
        finally:
            await response.aclose()
        if document is not _MISSING:
            evidence = _resolve(document, contract["result_evidence_path"])
            if evidence is _MISSING:
                path_unresolved = True
            elif evidence is not None:
                if _contains(evidence, text):
                    # A store-and-echo endpoint returns what we sent, not a result.
                    raise _blocked("echo_response_not_result", **details)
                if not isinstance(evidence, (str, dict, list)) or not _contains(evidence, run_id):
                    raise _failed("backend_result_not_linked", **details)
                details["result_ms"] = int((time.monotonic() - started) * 1000)
                return
        await asyncio.sleep(interval)
    if path_unresolved:
        raise _blocked("backend_result_path_unresolved", **details)
    if server_error:
        raise _failed("backend_unavailable", **details)
    raise _failed("backend_result_timeout", **details)


async def _submit(client, contract, headers, body, run_id):
    started = time.monotonic()
    try:
        async with asyncio.timeout(contract["max_initial_s"] + 2):
            request = client.build_request("POST", contract["submit_url"], json=body,
                                           headers=headers)
            response = await client.send(request, stream=True, follow_redirects=False)
            try:
                return started, await _json(response)
            finally:
                await response.aclose()
    except TimeoutError:
        timed_out = True
    if timed_out:
        raise _failed("first_response_timeout", run_id=run_id)


async def _flow(case, contract, headers, client):
    run_id = "be" + secrets.token_hex(8)
    text = f"{case.message} {run_id}".strip()
    body = _request_body(contract["utterance_path"], text)
    details: dict = {"run_id": run_id}
    started, first = await _submit(client, contract, headers, body, run_id)
    elapsed = time.monotonic() - started
    details["first_response_ms"] = int(elapsed * 1000)
    details["first_response_deadline_ok"] = elapsed <= contract["max_initial_s"]
    if not details["first_response_deadline_ok"]:
        raise _failed("first_response_too_slow", **details)
    flag_path = contract["initial_callback_flag_path"]
    details["callback_deferred"] = bool(flag_path) and _resolve(first, flag_path) is True
    details["echo_detected"] = _contains(first, run_id)
    complete = all(contract[key] for key in
                   ("job_id_path", "result_url_template", "result_evidence_path"))
    if details["echo_detected"] and not complete:
        raise _blocked("echo_response_not_result", **details)
    if not complete:
        raise _blocked("backend_result_contract_missing", **details)
    job_id = _resolve(first, contract["job_id_path"])
    if not isinstance(job_id, str) or not _JOB_ID.fullmatch(job_id):
        raise _blocked("backend_job_id_unresolved", **details)
    await _poll(client, contract, headers, job_id, run_id, text, started, details)
    return Outcome(case.id, VARIANT, "passed", "backend_result_linked", details)


async def _probe(case: CaseSpec, config: RuntimeConfig, client) -> Outcome:
    if case.id != CASE_ID:
        raise _blocked("unsupported_case")
    contract = load_contract(config.backend_contract, config.allow_loopback_http)
    headers = _headers(contract)
    total = contract["max_initial_s"] + contract["max_result_s"] + 2
    async with asyncio.timeout(total):
        if client is not None:
            return await _flow(case, contract, headers, client)
        try:
            context = ssl.create_default_context(
                cafile=str(config.ca_file) if config.ca_file else certifi.where())
        except (OSError, ssl.SSLError):
            raise _blocked("backend_ca_file_unusable") from None
        async with httpx.AsyncClient(verify=context, follow_redirects=False,
                                     trust_env=False, timeout=total) as owned:
            return await _flow(case, contract, headers, owned)


def _is_tls(error: BaseException) -> bool:
    cause = error
    while cause is not None:
        if isinstance(cause, ssl.SSLError):
            return True
        cause = cause.__cause__ or cause.__context__
    return False


async def probe_backend(case: CaseSpec, config: RuntimeConfig, *,
                        client: httpx.AsyncClient | None = None) -> Outcome:
    """Observe the BE first response and, if a contract exists, its linked result."""
    try:
        return await _probe(case, config, client)
    except _Stop as stop:
        status, code, details = stop.status, stop.code, dict(stop.details)
    except CollectionError:
        status, code, details = "failed", "backend_response_unreadable", {}
    except TimeoutError:
        status, code, details = "failed", "backend_timeout", {}
    except httpx.InvalidURL:
        status, code, details = "blocked", "backend_contract_invalid", {}
    except httpx.TimeoutException:
        status, code, details = "failed", "backend_timeout", {}
    except httpx.HTTPError as error:
        tls = _is_tls(error)
        status, details = "blocked", {}
        code = "backend_tls_verification_failed" if tls else (
            "backend_unreachable" if isinstance(error, httpx.TransportError) else "backend_request_failed")
    except httpx.StreamError:
        status, code, details = "blocked", "backend_request_failed", {}
    except (OSError, ssl.SSLError):
        status, code, details = "blocked", "backend_request_failed", {}
    # Returned outside the handlers: the result has no exception context.
    return Outcome(case.id, VARIANT, status, code, details)
