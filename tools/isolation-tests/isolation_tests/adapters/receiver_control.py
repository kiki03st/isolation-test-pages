"""Receiver liveness control: one GET to the receiver the variant's leak would reach.

The control goes straight to the receiver, never through the collector. Its URL
comes from the runner's configuration and, for fixture-rendered cases, must equal
the receiver URL the fixture server itself renders for that run_id (asked through
``/v1/receiver-target``). Network-relative receivers get no runner control at all.
Only fixed codes are returned; no URL or exception text reaches results.
"""

import asyncio
import ssl
from urllib.parse import urlsplit

import certifi
import httpx

from ..model import RuntimeConfig
from ..receiver import (
    CONTROL_PREFIX, FIXTURE_RENDERED, RECEIVE_PREFIX, RUN_ID, isolation_side_control, receiver_base_key,
)
from ..targets import normalize_base


TIMEOUT_S = 5
MAX_TARGET_BYTES = 2048


def _base(config: RuntimeConfig, key: str) -> str | None:
    try:
        return normalize_base(config.bases[key], config.allow_loopback_http)
    except (KeyError, ValueError):
        return None


def _endpoint(url: str) -> tuple | None:
    """Scheme, host, effective port, path and query: the receiver endpoint a URL names."""
    try:
        parts = urlsplit(url)
        port = parts.port or {"https": 443, "http": 80}.get(parts.scheme)
    except ValueError:
        return None
    if not parts.hostname:
        return None
    return parts.scheme, parts.hostname.lower().rstrip("."), port, parts.path, parts.query


async def _fixture_target(client: httpx.AsyncClient, fixture: str, case_id: str, variant: str,
                          run_id: str) -> str | None:
    """The leak URL the fixture server renders, rewritten to its control path; None if unknown."""
    response = await client.get(f"{fixture}v1/receiver-target/{case_id}/{variant}", params={"run_id": run_id})
    body = response.content
    if response.status_code != 200 or len(body) > MAX_TARGET_BYTES:
        return None
    try:
        leak = body.decode("ascii")
    except UnicodeDecodeError:
        return None
    marker = RECEIVE_PREFIX + case_id + "?"
    if leak.count(marker) != 1:
        return None
    return leak.replace(marker, CONTROL_PREFIX + case_id + "?")


async def send_control(config: RuntimeConfig, case_id: str, variant: str, run_id: str) -> str:
    """Return "sent" (the receiver stored the control) or a fixed code."""
    if isolation_side_control(case_id, variant):
        return "receiver_control_isolation_side"
    base = _base(config, receiver_base_key(case_id, variant))
    fixture = _base(config, "http_fixture") if case_id in FIXTURE_RENDERED else ""
    if base is None or fixture is None or not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        return "receiver_control_not_configured"
    url = f"{base}v1/control/{case_id}?run_id={run_id}"
    try:
        # The same trust as the collector and backend adapters.
        context = ssl.create_default_context(
            cafile=str(config.ca_file) if config.ca_file else certifi.where())
    except (OSError, ssl.SSLError):
        return "receiver_control_not_configured"
    try:
        async with asyncio.timeout(2 * TIMEOUT_S):
            async with httpx.AsyncClient(verify=context, follow_redirects=False, trust_env=False,
                                         timeout=TIMEOUT_S) as client:
                if fixture:
                    try:
                        rendered = await _fixture_target(client, fixture, case_id, variant, run_id)
                    except (httpx.HTTPError, OSError, ssl.SSLError):
                        rendered = None
                    if rendered is None:
                        return "receiver_control_target_unverified"
                    if _endpoint(rendered) != _endpoint(url):
                        return "receiver_control_target_mismatch"
                response = await client.get(url)
    except (httpx.HTTPError, OSError, ssl.SSLError, TimeoutError):
        return "receiver_control_failed"
    return "sent" if response.status_code == 200 else "receiver_control_rejected"
