"""Synthetic receiver evidence: a fixed, secret-free JSONL record per request."""

import json
import os
import re
import stat
from datetime import datetime
from pathlib import Path
from threading import Lock


# Cases whose fixtures may point at the receiver.
RECEIVER_CASES = frozenset(
    {"NAV-04", "NET-01", "NET-02", "NET-03", "NET-04", "NET-05", "NET-06", "NET-07"}
)
RUN_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
MAX_LOG_BYTES = 1048576
_FIELDS = ("at", "case_id", "run_id", "method", "path", "bytes_sent")
_METHOD = re.compile(r"[A-Z]{3,10}")
_APPEND_LOCK = Lock()


def _validate(event: object) -> dict:
    """Return the event if every field is allowlisted and typed, else raise."""
    if not isinstance(event, dict) or set(event) != set(_FIELDS):
        raise ValueError("receiver event has missing or unknown fields")
    case_id = event["case_id"]
    if case_id not in RECEIVER_CASES:
        raise ValueError("receiver event case is not registered")
    run_id = event["run_id"]
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        raise ValueError("receiver event run_id is unsafe")
    method = event["method"]
    if not isinstance(method, str) or not _METHOD.fullmatch(method):
        raise ValueError("receiver event method is unsafe")
    if event["path"] != f"/v1/receive/{case_id}":
        raise ValueError("receiver event path is not the fixed receiver path")
    sent = event["bytes_sent"]
    if type(sent) is not int or sent < 0:
        raise ValueError("receiver event bytes_sent is invalid")
    at = event["at"]
    if not isinstance(at, str) or len(at) > 40:
        raise ValueError("receiver event time is invalid")
    try:
        datetime.fromisoformat(at)
    except ValueError:
        raise ValueError("receiver event time is invalid") from None
    return event


def write_receiver_event(path, *, case_id, run_id, method, fixed_path, bytes_sent, at):
    """Append one allowlisted event; no header, body or query value is accepted."""
    event = _validate({"at": at, "case_id": case_id, "run_id": run_id,
                       "method": method, "path": fixed_path, "bytes_sent": bytes_sent})
    line = json.dumps(event, ensure_ascii=False) + "\n"
    with _APPEND_LOCK:
        with Path(path).open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(line)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key in receiver event")
        result[key] = value
    return result


def read_receiver_events(path: Path, run_id: str) -> tuple[dict, ...]:
    """Return the validated events of exactly one run; a missing log has none."""
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        raise ValueError("run_id is unsafe")
    path = Path(path)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return ()
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
        raise ValueError("receiver log must be a regular file")
    if info.st_size > MAX_LOG_BYTES:
        raise ValueError("receiver log is too large")
    with path.open("rb") as stream:
        data = stream.read(MAX_LOG_BYTES + 1)
    if len(data) > MAX_LOG_BYTES:
        raise ValueError("receiver log is too large")
    events = []
    for line in data.decode("utf-8").split("\n"):
        if not line.strip():
            continue
        event = _validate(json.loads(line, object_pairs_hook=_unique_object))
        if event["run_id"] == run_id:
            events.append(event)
    return tuple(events)
