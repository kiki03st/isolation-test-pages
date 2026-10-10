"""Write sanitized JSON and escaped HTML reports into one local output directory.

Every value is sanitized before output: URLs are reduced to scheme, host and a
fixed case path; known runtime token values, Authorization/Cookie patterns and
header-like keys are removed. The HTML report contains no script, and every
value, including observed page HTML and error text, is escaped.
"""

import hashlib
import json
import os
import re
import stat
import tempfile
from functools import lru_cache
from html import escape
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .evaluate import CANONICAL_MANIFEST, _canonical_variants, summarize
from .model import Outcome
from .receiver import RUN_ID


METADATA_KEYS = frozenset({
    "run_id", "started_at", "ended_at", "manifest_version", "pages_commit", "case_hashes",
    "limits", "required_ids", "scope", "manifest_sha256",
})
STATUSES = ("passed", "failed", "not_run", "blocked")
MAX_REPORT_BYTES = 64 * 1048576
_HTML_VALUE_CHARS = 4000
_REDACTED = "[redacted]"
_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]{0,15}://[^\s\"'<>\\`]*")
_FIXED_PATH = re.compile(r"(?:/[A-Za-z0-9._-]+)*/v1/(?:cases|static)(?:/[A-Za-z0-9._-]+)+/?")
_AUTH = re.compile(r"(?i)\b(proxy-)?authorization\b(\s*[:=]\s*)\"?[^\s\",;]+(?:\s+[^\s\",;]+)?")
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
_COOKIE = re.compile(r"(?i)\b(set-cookie|cookie)\b(\s*[:=]\s*)[^\r\n]*")
_SENSITIVE_KEY = re.compile(r"(?i)(authorization|cookie|header|token|secret|password|api_?key|credential)")
_SAFE_KEYS = frozenset({"token_mode", "credentials_rotated", "old_credentials_rejected",
                        "authentication_ok", "authentication_rejected"})


def _url(match: re.Match) -> str:
    raw = match.group(0)
    try:
        parts = urlsplit(raw)
        host = parts.hostname or ""
        port = f":{parts.port}" if parts.port else ""
    except ValueError:
        return f"{raw.split(':', 1)[0]}://"
    path = parts.path if _FIXED_PATH.fullmatch(parts.path or "") else "/"
    if not host:
        return f"{parts.scheme}://"
    return f"{parts.scheme}://{host}{port}{path}"


def _text(value: str, secrets: tuple[str, ...]) -> str:
    for secret in secrets:
        if secret:
            value = value.replace(secret, _REDACTED)
    value = _AUTH.sub(lambda m: f"{m.group(1) or ''}authorization{m.group(2)}{_REDACTED}", value)
    value = _BEARER.sub(f"Bearer {_REDACTED}", value)
    value = _COOKIE.sub(lambda m: f"{m.group(1)}{m.group(2)}{_REDACTED}", value)
    return _URL.sub(_url, value)


def sanitize(value: Any, secrets: tuple[str, ...] = ()) -> Any:
    """Return a JSON-safe copy without URLs' queries, token values or header-like keys."""
    secrets = tuple(s for s in secrets if isinstance(s, str) and len(s) >= 4)
    if isinstance(value, str):
        return _text(value, secrets)
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            key = str(key)
            if key not in _SAFE_KEYS and _SENSITIVE_KEY.search(key):
                continue
            result[_text(key, secrets)] = sanitize(item, secrets)
        return result
    if isinstance(value, (list, tuple)):
        return [sanitize(item, secrets) for item in value]
    if value is None or type(value) in (bool, int):
        return value
    if type(value) is float:
        return value if value == value and value not in (float("inf"), float("-inf")) else None
    return _text(str(value), secrets)


def _metadata(metadata: dict) -> dict:
    if not isinstance(metadata, dict) or set(metadata) - METADATA_KEYS:
        raise ValueError("report metadata permits only documented keys")
    run_id = metadata.get("run_id", "report")
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        raise ValueError("report run_id is unsafe")
    return {**metadata, "run_id": run_id}


def _is_link(info: os.stat_result) -> bool:
    reparse = getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return stat.S_ISLNK(info.st_mode) or bool(reparse)


def _directory(output: Path) -> Path:
    output = Path(output)
    try:
        info = os.lstat(output)
    except FileNotFoundError:
        output.mkdir(parents=True)
        info = os.lstat(output)
    if _is_link(info) or not stat.S_ISDIR(info.st_mode):
        raise ValueError("report output must be a real directory")
    return output


def _check_target(path: Path) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if _is_link(info) or not stat.S_ISREG(info.st_mode):
        raise ValueError("report file exists and is not a regular file; refusing to replace it")


def _atomic_write(path: Path, text: str) -> None:
    _check_target(path)
    handle, temporary = tempfile.mkstemp(prefix=".report-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        _check_target(path)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


@lru_cache(maxsize=1)
def canonical_manifest_sha256() -> str:
    """sha256 of the packaged canonical cases.json, the only manifest that can pass overall."""
    return hashlib.sha256(CANONICAL_MANIFEST.read_bytes()).hexdigest()


def manifest_canonical(metadata: dict) -> bool:
    return metadata.get("manifest_sha256") == canonical_manifest_sha256()


def overall(outcomes: tuple[Outcome, ...], metadata: dict) -> tuple[str, int]:
    """Overall status and exit code; a pass judged on any other manifest is capped at blocked/2."""
    status, code = summarize(tuple(outcomes), frozenset(_canonical_variants()))
    if code == 0 and not manifest_canonical(metadata):
        return "blocked", 2
    return status, code


def _summary(outcomes: tuple[Outcome, ...], metadata: dict) -> dict:
    status, code = overall(outcomes, metadata)
    counts = {name: 0 for name in STATUSES}
    for item in outcomes:
        counts[item.status if item.status in counts else "blocked"] += 1
    return {"status": status, "exit_code": code, "counts": counts,
            "manifest_canonical": manifest_canonical(metadata),
            "required_variants": sum(len(v) for v in _canonical_variants().values())}


def _item(outcome: Outcome) -> dict:
    return {"case_id": outcome.case_id, "variant": outcome.variant, "status": outcome.status,
            "reason": outcome.reason, "details": dict(outcome.details)}


def _short(value: Any) -> str:
    text = json.dumps(value, ensure_ascii=False, indent=1, sort_keys=True)
    if len(text) > _HTML_VALUE_CHARS:
        text = text[:_HTML_VALUE_CHARS] + f"\n... ({len(text) - _HTML_VALUE_CHARS} more characters in JSON report)"
    return text


def outcome_row(item: dict) -> str:
    cells = "".join("<td>" + escape(str(item[key])) + "</td>"
                    for key in ("case_id", "variant", "status", "reason"))
    details = "<td><details><summary>details</summary><pre>" + escape(_short(item["details"])) \
        + "</pre></details></td>"
    return f'<tr class="{escape(item["status"])}">' + cells + details + "</tr>"


def _html(data: dict) -> str:
    summary, metadata = data["summary"], data["metadata"]
    meta_rows = "".join(
        "<tr><th>" + escape(str(key)) + "</th><td><pre>" + escape(_short(metadata[key])) + "</pre></td></tr>"
        for key in sorted(metadata) if key not in {"case_hashes", "required_ids"})
    counts = ", ".join(f"{escape(k)} {int(v)}" for k, v in summary["counts"].items())
    rows = "".join(outcome_row(item) for item in data["items"])
    return (
        "<!doctype html>\n<html lang=\"ko\"><head><meta charset=\"utf-8\">"
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<title>Isolation test report</title><style>"
        "body{font-family:system-ui,sans-serif;margin:16px;background:#fff;color:#111}"
        "table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:4px;"
        "vertical-align:top;text-align:left}pre{white-space:pre-wrap;word-break:break-all;margin:0}"
        ".passed td:nth-child(3){color:#0a6b2d}.failed td:nth-child(3){color:#b00020}"
        ".blocked td:nth-child(3),.not_run td:nth-child(3){color:#8a5a00}"
        "</style></head><body>"
        "<h1>Isolation test report</h1>"
        f"<p>Overall: <strong>{escape(summary['status'])}</strong> (exit {int(summary['exit_code'])}); "
        f"{counts}. Required: all {len(metadata.get('required_ids', []))} cases and "
        f"{int(summary['required_variants'])} variants. A partial run is never a full verification.</p>"
        f"<table>{meta_rows}</table><h2>Items</h2>"
        "<table><thead><tr><th>case</th><th>variant</th><th>status</th><th>reason</th><th>details</th>"
        f"</tr></thead><tbody>{rows}</tbody></table></body></html>\n"
    )


def write_reports(outcomes: tuple[Outcome, ...], output: Path, metadata: dict, *,
                  secrets: tuple[str, ...] = ()) -> tuple[Path, Path]:
    """Write ``isolation-report-<run_id>.json`` and ``.html`` atomically into ``output``."""
    metadata = _metadata(metadata)
    metadata.setdefault("required_ids", sorted(_canonical_variants()))
    data = sanitize({"metadata": metadata, "summary": _summary(tuple(outcomes), metadata),
                     "items": [_item(item) for item in outcomes]}, tuple(secrets))
    directory = _directory(output)
    name = f"isolation-report-{metadata['run_id']}"
    json_path, html_path = directory / f"{name}.json", directory / f"{name}.html"
    _check_target(json_path)
    _check_target(html_path)
    _atomic_write(json_path, json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    _atomic_write(html_path, _html(data))
    return json_path, html_path


def load_report(path: Path) -> tuple[tuple[Outcome, ...], dict]:
    """Read a JSON report written by ``write_reports``; raise ValueError if malformed."""
    path = Path(path)
    info = os.lstat(path)
    if _is_link(info) or not stat.S_ISREG(info.st_mode) or info.st_size > MAX_REPORT_BYTES:
        raise ValueError("report must be a regular file within the size limit")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise ValueError("report is not valid JSON") from None
    if not isinstance(data, dict) or not isinstance(data.get("items"), list) \
            or not isinstance(data.get("metadata"), dict):
        raise ValueError("report structure is invalid")
    metadata = {k: v for k, v in data["metadata"].items() if k in METADATA_KEYS}
    outcomes = []
    for item in data["items"]:
        if (not isinstance(item, dict)
                or not all(isinstance(item.get(k), str) for k in ("case_id", "variant", "status", "reason"))
                or item["status"] not in STATUSES or not isinstance(item.get("details"), dict)):
            raise ValueError("report item is invalid")
        outcomes.append(Outcome(item["case_id"], item["variant"], item["status"], item["reason"],
                                item["details"]))
    return tuple(outcomes), metadata
