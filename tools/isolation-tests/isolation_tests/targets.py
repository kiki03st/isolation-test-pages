"""Build case URLs from configured bases without leaving the configured prefix."""

import ipaddress
import re
from urllib.parse import urljoin, urlsplit

from .model import CaseSpec, RuntimeConfig


_RUN_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
_VARIANT = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_RELATIVE = re.compile(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*")


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host.lower().rstrip(".") == "localhost"


def normalize_base(value: object, allow_loopback_http: bool = False) -> str:
    """Return a validated base URL that always ends with one slash."""
    if (not isinstance(value, str) or not value
            or any(ord(c) <= 32 or ord(c) == 127 for c in value)
            or any(c in value for c in "\\%?#")):
        raise ValueError("target base is missing or unsafe")
    try:
        parts = urlsplit(value)
        host = parts.hostname
        parts.port  # noqa: B018 - raises ValueError for an invalid port
    except ValueError as error:
        raise ValueError("target base has an invalid host or port") from error
    if not host or "@" in parts.netloc or parts.query or parts.fragment:
        raise ValueError("target base requires a plain host without userinfo, query or fragment")
    if parts.scheme != "https" and not (
            parts.scheme == "http" and allow_loopback_http and _is_loopback(host)):
        raise ValueError("target base requires HTTPS; loopback HTTP needs explicit opt-in")
    segments = parts.path.split("/")[1:]
    if segments and segments[-1] == "":
        segments.pop()
    if any(part in {"", ".", ".."} for part in segments):
        raise ValueError("target base path is unsafe")
    path = "/" + "".join(f"{part}/" for part in segments)
    return f"{parts.scheme}://{parts.netloc}{path}"


def _bare(config: RuntimeConfig, key: str) -> str:
    if key not in config.bases:
        raise ValueError(f"target {key!r} is not configured (preparation missing)")
    value = normalize_base(config.bases[key], config.allow_loopback_http)
    return value[:-1] if value.endswith("/") and urlsplit(value).path != "/" else value


def _net07_url(variant: str, config: RuntimeConfig, run_id: str) -> str:
    """Fixed forbidden initial inputs; never an arbitrary caller-supplied URL."""
    if variant == "initial-private":
        url = _bare(config, "private")
    elif variant == "scheme":
        url = "file:///isolation-test-only"
    else:
        parts = urlsplit(_bare(config, "forbidden_receiver"))
        if variant == "userinfo":
            netloc = f"isolation-test@{parts.netloc}"
        else:
            port = f":{parts.port}" if parts.port else ""
            netloc = f"{parts.hostname.upper()}.{port}"
        url = f"{parts.scheme}://{netloc}{parts.path}"
    return f"{url}?run_id={run_id}"


def case_url(case: CaseSpec, variant: str, config: RuntimeConfig, run_id: str) -> str:
    """Return the URL for one registered variant, or raise ValueError.

    A base that is not configured is a preparation failure, never a dummy URL.
    """
    if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id):
        raise ValueError("run_id must be 1-64 characters of letters, digits, _ or -")
    if variant not in case.variants or not _VARIANT.fullmatch(variant):
        raise ValueError("variant is not registered for this case")
    if case.id == "NET-07":
        return _net07_url(variant, config, run_id)
    if case.target_key is None or case.target_key not in config.bases:
        raise ValueError(f"target {case.target_key!r} is not configured (preparation missing)")
    base = normalize_base(config.bases[case.target_key], config.allow_loopback_http)
    relative = case.relative_path
    if not isinstance(relative, str) or not _RELATIVE.fullmatch(relative) \
            or any(part in {".", ".."} for part in relative.split("/")):
        raise ValueError("case relative path is unsafe")
    if case.execution_kind == "page":
        if len(case.variants) > 1:
            relative = f"{relative.rsplit('/', 1)[0]}/{variant}.html"
    elif case.execution_kind == "http_fixture":
        relative = f"{relative}/{variant}"
    else:
        raise ValueError("case kind has no URL")
    joined = urljoin(base, relative)
    expected, actual = urlsplit(base), urlsplit(joined)
    if (actual.scheme, actual.netloc) != (expected.scheme, expected.netloc) \
            or not actual.path.startswith(expected.path):
        raise ValueError("case URL left the configured base")
    return f"{joined}?run_id={run_id}"
