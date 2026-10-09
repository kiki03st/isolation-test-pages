"""Load untrusted JSONL evidence and correlate it to exactly one case run.

Every rejected input raises ``EvidenceUnavailable``; nothing here fills in a
missing fact. A record supplies facts only when its run_id, case_id, UTC
observation window and ``facts.variant`` all match the trial being evaluated.
"""

import json
import math
import os
import re
import stat
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .model import Evidence
from .receiver import RUN_ID


MAX_FILE_BYTES = 1048576
# Allowed clock difference between administrator, fixture and receiver hosts.
MAX_CLOCK_OFFSET_SECONDS = 1.0

_CASE_ID = re.compile(r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*\Z")
_VARIANT = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_RECORD_FIELDS = {"run_id", "case_id", "started_at", "ended_at", "facts", "references"}

# Authoritative fact vocabulary: names and types. Truthy substitutes (1, "true",
# [] ...) are rejected and so is every name that is not listed here, which keeps
# raw secrets and ad-hoc keys out of results.
BOOLEAN_FACTS = frozenset({
    "positive_control_ok", "receiver_control_ok", "request_blocked", "receiver_observed",
    "firewall_drop_observed", "remote_job_terminated", "recovery_ok", "caps_ok",
    "sandbox_ok", "readonly_ok", "mounts_ok", "environment_names_ok", "digest_ok",
    "replacement_ok", "kakao_received", "collection", "analysis", "no_new_privileges_ok",
    # Host, integration and recovery evidence.
    "uid_ok", "seccomp_ok", "unsupported_boundary", "write_probe_applicable",
    "source_allowed", "source_denied", "credentials_rotated", "old_credentials_rejected",
    "context_cleanup_ok", "resource_profile_recorded", "resource_limits_ok",
    "probe_in_container", "authentication_ok", "authentication_rejected", "tls_rejected",
    "backend_result_ok", "first_response_deadline_ok", "collector_deadline_ok",
    "fallback_ok", "callback_failure_recorded", "false_success_reported",
    # Collection, network, session, limits and analysis.
    "actual_byte_limit_ok", "boundary_results_ok", "concurrency_limit_known",
    "concurrency_limit_ok", "context_fresh", "deadline_met", "disabled_readonly_ok",
    "download_attempt_observed", "download_clicked", "download_link_recorded",
    "fabricated_evidence_rejected", "file_executed", "form_associations_ok",
    "form_destination_ok", "forms_submitted", "initial_url_rejected", "limit_exceeded_confirmed",
    "limit_plus_one_sent", "navigation_chain_ok", "page_opened", "paired_verdict_equal",
    "payment_request_observed", "queue_limit_ok", "redirect_limit_ok", "relative_targets_ok",
    "safe_claimed", "same_host_verified", "service_worker_registered", "shared_ip_verified",
    "stream_bounds_ok",
})
COUNT_FACTS = frozenset({"children_remaining", "download_temporary_bytes", "download_remaining_bytes"})
REGION_FACTS = frozenset({"inspected_regions", "unknown_regions"})
CLOCK_FACT = "clock_offset_seconds"
# Finite non-boolean numbers. Resource limits use -1 for "unlimited".
NUMBER_FACTS = frozenset({
    CLOCK_FACT, "concurrency_limit", "fixture_max_active", "collector_deadline_s",
    "deadline_grace_s", "boundary_limit", "payment_amount_krw", "cpu_limit",
    "memory_limit_mib", "pids_limit", "shm_mib", "tmpfs_mib",
})
# Flat scalar arrays (not regions).
LIST_FACTS = frozenset({"boundary_offsets", "session_stores_seeded", "session_markers_present"})
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_DIGEST_KIND = re.compile(r"(image_manifest|image_index|image_config|container_id)\Z")
_PLATFORM_ID = re.compile(r"[a-z0-9]+/[a-z0-9]+(?:/[a-z0-9]+)?\Z")
# Strings are restricted by pattern so a pasted secret cannot fit.
TEXT_FACTS = {
    "variant": _VARIANT,
    "boundary": re.compile(r"(host|container)\Z"),
    "boundary_declared": re.compile(r"(host|container)\Z"),
    "platform": re.compile(r"(linux|unsupported|windows|darwin)\Z"),
    "evidence_source": re.compile(r"(observed|self_reported)\Z"),
    "replacement_kind": re.compile(r"(new_instance|restart|reboot)\Z"),
    "followup_run_id": RUN_ID,
    "observed_digest": _DIGEST, "approved_digest": _DIGEST,
    "observed_digest_kind": _DIGEST_KIND, "approved_digest_kind": _DIGEST_KIND,
    "observed_digest_platform": _PLATFORM_ID, "approved_digest_platform": _PLATFORM_ID,
    "http_page_state": re.compile(r"(403|404|500|block_page|captcha_page)\Z"),
    "navigation_kind": re.compile(r"(js|meta)\Z"),
}
APPROVED_FACTS = (BOOLEAN_FACTS | COUNT_FACTS | REGION_FACTS | NUMBER_FACTS | LIST_FACTS
                  | frozenset(TEXT_FACTS))


class EvidenceUnavailable(ValueError):
    """The evidence is missing, ambiguous or untrusted; it proves nothing."""


def _is_number(value: Any) -> bool:
    return type(value) in (int, float) and math.isfinite(value)


def validate_facts(facts: Any) -> dict:
    """Return ``facts`` if every value is well typed, else raise EvidenceUnavailable."""
    if not isinstance(facts, dict):
        raise EvidenceUnavailable("facts must be an object")
    variant = facts.get("variant")
    if not isinstance(variant, str) or not _VARIANT.fullmatch(variant):
        raise EvidenceUnavailable("facts.variant is missing or unsafe")
    for key, value in facts.items():
        if not isinstance(key, str) or not _NAME.fullmatch(key):
            raise EvidenceUnavailable("fact name is unsafe")
        items = value if isinstance(value, list) else [value]
        for item in items:
            if item is not None and type(item) not in (str, bool, int, float):
                raise EvidenceUnavailable("facts permit only scalars or flat scalar arrays")
            if type(item) is float and not math.isfinite(item):
                raise EvidenceUnavailable("fact numbers must be finite")
        if key not in APPROVED_FACTS:
            raise EvidenceUnavailable("fact name is not in the approved vocabulary")
        if key in TEXT_FACTS and not (isinstance(value, str) and TEXT_FACTS[key].fullmatch(value)):
            raise EvidenceUnavailable(f"fact {key} has an unapproved value")
        if key in LIST_FACTS and not isinstance(value, list):
            raise EvidenceUnavailable(f"fact {key} must be a list")
        if key in BOOLEAN_FACTS and type(value) is not bool:
            raise EvidenceUnavailable(f"fact {key} must be a boolean")
        if key in COUNT_FACTS and (type(value) is not int or value < 0):
            raise EvidenceUnavailable(f"fact {key} must be a nonnegative integer")
        if key in REGION_FACTS and (
                not isinstance(value, list) or len(set(map(repr, value))) != len(value)
                or any(not isinstance(item, str) or not _NAME.fullmatch(item) for item in value)):
            raise EvidenceUnavailable(f"fact {key} must list unique region names")
        if key in NUMBER_FACTS and not _is_number(value):
            raise EvidenceUnavailable(f"fact {key} must be a finite number")
    return facts


def parse_utc(value: Any) -> datetime:
    """Parse an ISO 8601 timestamp whose offset is exactly UTC (Z or +00:00)."""
    if not isinstance(value, str) or len(value) > 40 or not (value.endswith("Z") or value.endswith("+00:00")):
        raise EvidenceUnavailable("timestamp must be ISO 8601 UTC")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise EvidenceUnavailable("timestamp must be ISO 8601 UTC") from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise EvidenceUnavailable("timestamp must be ISO 8601 UTC")
    return parsed


def window(evidence: Evidence) -> tuple[datetime, datetime]:
    """Return the ordered UTC observation window or raise EvidenceUnavailable."""
    started, ended = parse_utc(evidence.started_at), parse_utc(evidence.ended_at)
    if ended < started:
        raise EvidenceUnavailable("observation window ends before it starts")
    return started, ended


def clock_aligned(facts: dict) -> bool:
    """False when a recorded host clock difference exceeds one second."""
    if CLOCK_FACT not in facts:
        return True
    offset = facts[CLOCK_FACT]
    return _is_number(offset) and abs(offset) <= MAX_CLOCK_OFFSET_SECONDS


def _is_reparse(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _regular_file(path: Path) -> os.stat_result:
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or _is_reparse(info) or not stat.S_ISREG(info.st_mode):
        raise EvidenceUnavailable("evidence must be a regular file")
    return info


def _read_bounded(path: Path) -> bytes:
    info = _regular_file(path)
    if info.st_size > MAX_FILE_BYTES:
        raise EvidenceUnavailable("evidence file exceeds 1 MiB")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_ino, opened.st_dev) != (info.st_ino, info.st_dev):
            raise EvidenceUnavailable("evidence file changed while opening")
        data = stream.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise EvidenceUnavailable("evidence file exceeds 1 MiB")
    return data


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceUnavailable("duplicate key in evidence record")
        result[key] = value
    return result


def _reject_constant(_name):
    raise EvidenceUnavailable("non-finite JSON number in evidence")


def _records(path: Path):
    try:
        text = _read_bounded(path).decode("utf-8")
    except UnicodeDecodeError:
        raise EvidenceUnavailable("evidence is not UTF-8") from None
    for line in text.split("\n"):
        if not line.strip():
            continue
        try:
            record = json.loads(line, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
        except json.JSONDecodeError:
            raise EvidenceUnavailable("malformed evidence line") from None
        if not isinstance(record, dict):
            raise EvidenceUnavailable("evidence line must be an object")
        yield record


def _references(root: Path, references: Any) -> tuple[str, ...]:
    if not isinstance(references, list) or any(not isinstance(item, str) for item in references):
        raise EvidenceUnavailable("references must be an array of strings")
    for reference in references:
        parts = reference.split("/")
        if (not reference or reference.startswith("/") or "\\" in reference or ":" in reference
                or any(ord(c) < 32 for c in reference) or any(part in {"", ".", ".."} for part in parts)):
            raise EvidenceUnavailable("evidence reference escapes the evidence directory")
        target = root.joinpath(*parts)
        current = root
        for part in parts:  # no symlink anywhere along the reference path
            current = current / part
            info = os.lstat(current)
            if stat.S_ISLNK(info.st_mode) or _is_reparse(info):
                raise EvidenceUnavailable("evidence reference must not be a link")
        _regular_file(target)
    return tuple(references)


def load_evidence(directory: Path, run_id: str, case_id: str, *, variant: str | None = None) -> Evidence:
    """Return the single record of this run, case (and variant); raise otherwise.

    Without ``variant`` more than one matching record is ambiguous and rejected.
    Rows of other runs or cases are ignored, but any malformed line rejects the
    whole directory: a torn or forged line cannot be told apart from a stale one.
    """
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        raise EvidenceUnavailable("run_id is unsafe")
    if not isinstance(case_id, str) or not _CASE_ID.fullmatch(case_id):
        raise EvidenceUnavailable("case_id is unsafe")
    if variant is not None and (not isinstance(variant, str) or not _VARIANT.fullmatch(variant)):
        raise EvidenceUnavailable("variant is unsafe")
    root = Path(directory)
    try:
        info = os.lstat(root)
    except OSError:
        raise EvidenceUnavailable("evidence directory is unavailable") from None
    if stat.S_ISLNK(info.st_mode) or _is_reparse(info) or not stat.S_ISDIR(info.st_mode):
        raise EvidenceUnavailable("evidence directory must be a real directory")

    matches = []
    try:
        for entry in sorted(os.scandir(root), key=lambda item: item.name):
            if not entry.name.endswith(".jsonl"):
                continue
            for record in _records(root / entry.name):
                if record.get("run_id") != run_id or record.get("case_id") != case_id:
                    continue
                if set(record) != _RECORD_FIELDS:
                    raise EvidenceUnavailable("evidence record has missing or unknown fields")
                facts = validate_facts(record["facts"])
                if variant is None or facts["variant"] == variant:
                    matches.append(record)
    except OSError:
        raise EvidenceUnavailable("evidence directory could not be read") from None
    if len(matches) != 1:
        raise EvidenceUnavailable("no single matching evidence record")
    record = matches[0]
    evidence = Evidence(run_id, case_id, record["started_at"], record["ended_at"],
                        dict(record["facts"]), ())
    window(evidence)
    try:
        references = _references(root, record["references"])
    except OSError:
        raise EvidenceUnavailable("evidence reference is not a regular file") from None
    return Evidence(run_id, case_id, evidence.started_at, evidence.ended_at, evidence.facts, references)


def receiver_observed(evidence: Evidence, events: tuple[dict, ...]) -> bool | None:
    """Correlate receiver events (``read_receiver_events`` output) with one trial.

    Receiver events carry no variant, so each (case, variant) trial needs its own
    unguessable run_id. Returns True when this run's request reached the receiver
    inside the observation window, False when no event exists, and None (proves
    nothing) when any event belongs elsewhere, lies outside the window allowing
    one second of clock difference, or a recorded ``clock_offset_seconds`` is
    malformed or exceeds one second. An absent offset is treated as aligned.
    """
    try:
        started, ended = window(evidence)
    except EvidenceUnavailable:
        return None
    if not clock_aligned(evidence.facts):
        return None
    slack = timedelta(seconds=MAX_CLOCK_OFFSET_SECONDS)
    observed = False
    for event in events:
        if event.get("run_id") != evidence.run_id or event.get("case_id") != evidence.case_id:
            return None
        try:
            at = datetime.fromisoformat(event["at"])
        except (KeyError, TypeError, ValueError):
            return None
        if at.tzinfo is None or not started - slack <= at <= ended + slack:
            return None
        observed = True
    return observed
