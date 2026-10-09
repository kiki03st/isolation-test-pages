"""Authenticated collection API client with a strict response boundary.

Errors carry only a fixed classification code. Exception text, request headers,
tokens and raw response bodies never reach results.
"""

import asyncio
import json
import os
import re
import ssl

import certifi
import httpx

from ..model import CollectedPage, RuntimeConfig


HARD_RESPONSE_BYTES = 1024 * 1024
TOKEN_MODES = frozenset({"valid", "missing", "wrong"})
_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_TOKEN = re.compile(r"[\x21-\x7e]{1,4096}\Z")
_WRONG_TOKEN = "invalid-synthetic-token"
_FIELDS = {
    "input_url", "final_url", "redirect_chain", "status_code", "content_type",
    "html", "title", "elapsed_ms", "failures",
}


class CollectionError(Exception):
    """A classified collection failure; only ``code`` is public."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code

    def __str__(self) -> str:
        return self.code

    def __repr__(self) -> str:
        return f"CollectionError({self.code!r})"


async def read_limited(response: httpx.Response, max_bytes: int) -> bytes:
    if response.headers.get("content-encoding", "identity").strip().lower() != "identity":
        raise CollectionError("unsupported_response_encoding")
    buffer = bytearray()
    async for part in response.aiter_raw():
        if len(buffer) + len(part) > max_bytes:
            raise CollectionError("runner_response_too_large")
        buffer.extend(part)
    return bytes(buffer)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(_name):
    raise ValueError("non-finite number")


def _text(value, nullable=False):
    return (nullable and value is None) or isinstance(value, str)


def _parse(raw: bytes) -> CollectedPage:
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                          parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise CollectionError("malformed_response") from None
    if not isinstance(data, dict) or set(data) != _FIELDS:
        raise CollectionError("malformed_response")
    chain, failures = data["redirect_chain"], data["failures"]
    elapsed, status = data["elapsed_ms"], data["status_code"]
    valid = (
        _text(data["input_url"]) and _text(data["final_url"], True)
        and _text(data["content_type"], True) and _text(data["html"])
        and _text(data["title"], True)
        and isinstance(chain, list) and all(isinstance(item, str) for item in chain)
        and isinstance(failures, list) and all(isinstance(item, str) for item in failures)
        and type(elapsed) is int and elapsed >= 0
        and (status is None or type(status) is int)
    )
    if not valid:
        raise CollectionError("malformed_response")
    if "stub_not_collected" in failures:
        raise CollectionError("stub_not_collected")
    # Remote failures are reported as short codes; free text is not echoed.
    if any(not _CODE.fullmatch(item) for item in failures):
        raise CollectionError("malformed_response")
    if not data["html"] and not failures:
        raise CollectionError("empty_html")
    return CollectedPage(
        data["input_url"], data["final_url"], tuple(chain), status,
        data["content_type"], data["html"], data["title"], elapsed, tuple(failures),
    )


def _authorization(config: RuntimeConfig, token_mode: str) -> dict[str, str]:
    if token_mode == "missing":
        return {}
    if token_mode == "wrong":
        return {"authorization": f"Bearer {_WRONG_TOKEN}"}
    token = os.environ.get(config.token_env) if config.token_env else None
    if not token:
        raise CollectionError("token_missing")
    if not _TOKEN.fullmatch(token):
        raise CollectionError("token_invalid")
    return {"authorization": f"Bearer {token}"}


def _classify_transport(error: BaseException) -> str:
    cause = error
    while cause is not None:
        if isinstance(cause, ssl.SSLError):
            return "tls_verification_failed"
        cause = cause.__cause__ or cause.__context__
    if isinstance(error, httpx.TimeoutException):
        return "collector_timeout"
    if isinstance(error, httpx.TransportError):
        return "collector_unreachable"
    return "collector_request_failed"


async def _post(client: httpx.AsyncClient, config: RuntimeConfig, url: str,
                headers: dict[str, str]) -> CollectedPage:
    request = client.build_request(
        "POST", config.collector_url, json={"url": url},
        headers={"accept-encoding": "identity"} | headers,
    )
    try:
        response = await client.send(request, stream=True, follow_redirects=False)
    except httpx.HTTPError as error:
        raise CollectionError(_classify_transport(error)) from None
    try:
        status = response.status_code
        if 300 <= status < 400:
            raise CollectionError("api_redirect_rejected")
        if status in {401, 403}:
            raise CollectionError("authentication_failed")
        if status >= 500:
            raise CollectionError("collector_unavailable")
        if status != 200:
            raise CollectionError("unexpected_status")
        limit = min(config.limits.get("runner_response_bytes", HARD_RESPONSE_BYTES),
                    HARD_RESPONSE_BYTES)
        try:
            raw = await read_limited(response, int(limit))
        except httpx.HTTPError as error:
            raise CollectionError(_classify_transport(error)) from None
        return _parse(raw)
    finally:
        await response.aclose()


async def collect(config: RuntimeConfig, url: str, token_mode: str = "valid", *,
                  client: httpx.AsyncClient | None = None) -> CollectedPage:
    if token_mode not in TOKEN_MODES:
        raise CollectionError("invalid_token_mode")
    if not config.collector_url:
        raise CollectionError("collector_not_configured")
    headers = _authorization(config, token_mode)
    limits = config.limits
    # Collector deadline + measurement margin + response cleanup (default 15 s).
    budget = limits.get("collector_deadline_s", 12) + limits.get("deadline_grace_s", 1) + 2
    try:
        async with asyncio.timeout(budget):
            if client is not None:
                return await _post(client, config, url, headers)
            context = ssl.create_default_context(
                cafile=str(config.ca_file) if config.ca_file else certifi.where())
            async with httpx.AsyncClient(
                verify=context, follow_redirects=False, trust_env=False,
                timeout=budget,
            ) as owned:
                return await _post(owned, config, url, headers)
    except TimeoutError:
        # The local watchdog alone does not prove the remote collection ended.
        raise CollectionError("runner_timeout") from None
