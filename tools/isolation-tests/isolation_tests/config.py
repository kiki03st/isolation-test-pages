"""Validate local runtime configuration without contacting external services."""

import ipaddress
import json
import math
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .model import RuntimeConfig


DEFAULT_LIMITS = {
    "collector_deadline_s": 12,
    "deadline_grace_s": 1,
    "max_redirects": 5,
    "runner_response_bytes": 1048576,
    "concurrency": 1,
}
_FIELDS = {
    "bases", "collector_url", "token_env", "ca_file", "limits", "capabilities",
    "evidence_dir", "backend_contract", "allow_loopback_http",
}
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate configuration key")
        result[key] = value
    return result


def _url(value: object, allow_loopback_http: bool) -> str:
    if not isinstance(value, str) or not value or any(c.isspace() or ord(c) < 32 for c in value):
        raise ValueError("connection URL must be a nonempty URL")
    decoded = unquote(value)
    if any(c in decoded for c in ("*", "\\", "#")) or any(ord(c) < 32 for c in decoded):
        raise ValueError("connection URL forbids wildcards, fragments and backslashes")
    try:
        parts = urlsplit(value)
        host = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise ValueError("invalid connection URL host or port") from exc
    if not host or parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise ValueError("connection URL requires a host without userinfo")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("invalid connection URL port")
    if parts.netloc.endswith(":") or "%" in host:
        raise ValueError("invalid connection URL host or port")
    try:
        address = ipaddress.ip_address(host)
        loopback = address.is_loopback
    except ValueError:
        labels = host.rstrip(".").split(".")
        try:
            labels = [label.encode("idna").decode("ascii") for label in labels]
        except UnicodeError as exc:
            raise ValueError("invalid connection URL host") from exc
        if len(host) > 253 or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in labels):
            raise ValueError("invalid connection URL host")
        loopback = host.lower().rstrip(".") == "localhost"
    if parts.scheme != "https" and not (parts.scheme == "http" and allow_loopback_http and loopback):
        raise ValueError("connection URL requires HTTPS; opted-in loopback HTTP is local only")
    return value


def _path(value: object, config_path: Path, name: str) -> Path | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip() or any(ord(c) < 32 for c in value):
        raise ValueError(f"{name} must be a nonempty local path or null")
    if "://" in value:
        raise ValueError(f"{name} must be a local path")
    path = Path(value)
    if not path.is_absolute():
        path = config_path.parent / path
    path = path.resolve()
    if name == "ca_file" and not path.is_file():
        raise ValueError(f"{name} must be an existing file")
    if name == "backend_contract" and path.exists() and not path.is_file():
        raise ValueError("backend_contract must be a file path")
    if name == "evidence_dir" and path.exists() and not path.is_dir():
        raise ValueError("evidence_dir must be a directory")
    return path


def load_config(path: Path) -> RuntimeConfig:
    """Apply safe defaults; missing operational prerequisites remain unset."""
    data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    if not isinstance(data, dict) or set(data) - _FIELDS:
        raise ValueError("configuration requires an object with only documented fields")
    local_http = data.get("allow_loopback_http", False)
    if type(local_http) is not bool:
        raise ValueError("allow_loopback_http must be a boolean")
    bases = data.get("bases", {})
    if not isinstance(bases, dict) or any(not _NAME.fullmatch(key) for key in bases):
        raise ValueError("bases must be an object with target names")
    bases = {key: _url(value, local_http) for key, value in bases.items()}
    collector = data.get("collector_url")
    if collector is not None:
        collector = _url(collector, local_http)
    token_env = data.get("token_env", "ISOLATION_TEST_TOKEN")
    if token_env is not None and (not isinstance(token_env, str) or not _NAME.fullmatch(token_env)):
        raise ValueError("token_env must name an environment variable or be null")
    supplied_limits = data.get("limits", {})
    if not isinstance(supplied_limits, dict) or set(supplied_limits) - DEFAULT_LIMITS.keys():
        raise ValueError("limits must contain only documented limit keys")
    limits = DEFAULT_LIMITS | supplied_limits
    for name, value in limits.items():
        if type(value) not in {int, float} or (type(value) is float and not math.isfinite(value)) or value < 0:
            raise ValueError(f"{name} must be a finite nonnegative number, not a boolean")
        if name in {"max_redirects", "runner_response_bytes", "concurrency"} and type(value) is not int:
            raise ValueError(f"{name} must be an integer")
        if name in {"collector_deadline_s", "runner_response_bytes"} and value == 0:
            raise ValueError(f"{name} must be positive")
    if not 1 <= limits["concurrency"] <= 8:
        raise ValueError("concurrency must be between 1 and 8")
    capabilities = data.get("capabilities", [])
    if not isinstance(capabilities, list) or any(not isinstance(item, str) or not _NAME.fullmatch(item) for item in capabilities):
        raise ValueError("capabilities must be an array of capability names")
    return RuntimeConfig(
        bases=bases, collector_url=collector, token_env=token_env,
        ca_file=_path(data.get("ca_file"), path, "ca_file"), limits=limits,
        capabilities=frozenset(capabilities),
        evidence_dir=_path(data.get("evidence_dir"), path, "evidence_dir"),
        backend_contract=_path(data.get("backend_contract"), path, "backend_contract"),
        allow_loopback_http=local_http,
    )
