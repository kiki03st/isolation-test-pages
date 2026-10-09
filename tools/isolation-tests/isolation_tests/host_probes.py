"""Host probe facts and the administrator evidence contract.

The runner never executes SSH commands. ``collect_host_facts`` is run by the
administrator on the inspected host/container through ``isolation-tests
host-probe``. It reads process and mount metadata and the *names* of
environment variables; values, tokens and file contents are never read into
the result. Facts that cannot be observed here are omitted, never guessed.

``validate_host_evidence`` accepts only an approved fact vocabulary with
strictly typed values, so a pasted secret cannot be carried into a result.
"""

import errno
import os
import re
import sys
from functools import lru_cache
from pathlib import Path

from .model import Evidence, Outcome
from .receiver import RUN_ID


# The single path the read-only check may create (and then remove).
WRITE_PROBE_PATH = Path("/home/collector/isolation-test-write-probe")
PROC_STATUS = Path("/proc/self/status")
PROC_MOUNTS = Path("/proc/self/mounts")
CGROUP_ROOT = Path("/sys/fs/cgroup")
CANONICAL_MANIFEST = Path(__file__).resolve().parents[1] / "cases.json"

_FORBIDDEN_PREFIXES = ("AWS_",)
_FORBIDDEN_SUFFIXES = ("_API_KEY",)
_FORBIDDEN_NAMES = frozenset({"ISOLATION_TOKEN", "KAKAO_SKILL_SECRET"})


def environment_names_ok(names) -> bool:
    return not any(n.startswith(_FORBIDDEN_PREFIXES) or n.endswith(_FORBIDDEN_SUFFIXES)
                   or n in _FORBIDDEN_NAMES for n in names)


# --- observation helpers (monkeypatched in tests) ----------------------------

def _platform() -> str:
    return sys.platform


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _status_fields(text: str) -> dict[str, str]:
    fields = {}
    for line in text.splitlines():
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()
    return fields


def _detect_boundary() -> str:
    markers = (Path("/.dockerenv"), Path("/run/.containerenv"))
    return "container" if any(p.exists() for p in markers) else "host"


def _mount_facts(text: str) -> bool | None:
    """True when the root filesystem is read-only and no runtime socket is mounted."""
    root_options = None
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        if parts[1] == "/":
            root_options = parts[3].split(",")
        if parts[1].endswith(("docker.sock", "containerd.sock")):
            return False
    if root_options is None:
        return None
    return "ro" in root_options


def _write_probe() -> bool | None:
    """True if creation is refused as read-only, False if it succeeded; None if unclear."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(WRITE_PROBE_PATH, flags, 0o600)
    except OSError as error:
        return True if error.errno == errno.EROFS else None
    os.close(descriptor)
    try:
        os.unlink(WRITE_PROBE_PATH)  # only the file this probe just created
    except OSError:
        pass
    return False


def _resource_profile() -> bool | None:
    values = []
    for name in ("memory.max", "pids.max", "cpu.max"):
        text = _read_text(CGROUP_ROOT / name)
        if text is None:
            return None
        values.append(text.split()[0] if text.split() else "")
    return all(value and value != "max" for value in values)


def collect_host_facts(*, boundary: str | None = None) -> dict:
    """Facts for the boundary this process runs in; values of env vars never read."""
    facts: dict = {
        "environment_names_ok": environment_names_ok(list(os.environ)),
        "boundary": boundary if boundary in {"host", "container"} else None,
        "platform": "linux" if _platform().startswith("linux") else "unsupported",
    }
    if facts["platform"] != "linux":
        # A Windows administrator PC proves nothing about the Linux boundary.
        facts["unsupported_boundary"] = True
        facts["boundary"] = facts["boundary"] or "host"
        return facts
    facts["unsupported_boundary"] = False
    facts["boundary"] = facts["boundary"] or _detect_boundary()
    status = _read_text(PROC_STATUS)
    if status is not None:
        fields = _status_fields(status)
        facts["positive_control_ok"] = True  # the probe can read the process state it reports
        facts["uid_ok"] = os.getuid() != 0
        if "CapEff" in fields and "CapPrm" in fields:
            try:
                facts["caps_ok"] = int(fields["CapEff"], 16) == 0 and int(fields["CapPrm"], 16) == 0
            except ValueError:
                pass
        if "Seccomp" in fields:
            facts["seccomp_ok"] = fields["Seccomp"] == "2"
        if "NoNewPrivs" in fields:
            facts["no_new_privileges_ok"] = fields["NoNewPrivs"] == "1"
    mounts = _read_text(PROC_MOUNTS)
    if mounts is not None:
        mounts_ok = _mount_facts(mounts)
        if mounts_ok is not None:
            facts["mounts_ok"] = mounts_ok
    readonly = _write_probe()
    if readonly is not None:
        facts["readonly_ok"] = readonly
    profile = _resource_profile()
    if profile is not None:
        facts["resource_profile_recorded"] = profile
    return facts


# --- administrator evidence contract -----------------------------------------

_TEXT = {
    "variant": re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z"),
    "boundary": re.compile(r"(host|container)\Z"),
    "platform": re.compile(r"(linux|unsupported|windows|darwin)\Z"),
    "evidence_source": re.compile(r"(observed|self_reported)\Z"),
    "replacement_kind": re.compile(r"(new_instance|restart|reboot)\Z"),
    "followup_run_id": RUN_ID,
    "observed_digest": re.compile(r"sha256:[0-9a-f]{64}\Z"),
    "approved_digest": re.compile(r"sha256:[0-9a-f]{64}\Z"),
    "observed_digest_kind": re.compile(r"(image_manifest|image_index|image_config|container_id)\Z"),
    "approved_digest_kind": re.compile(r"(image_manifest|image_index|image_config|container_id)\Z"),
    "observed_digest_platform": re.compile(r"[a-z0-9]+/[a-z0-9]+(?:/[a-z0-9]+)?\Z"),
    "approved_digest_platform": re.compile(r"[a-z0-9]+/[a-z0-9]+(?:/[a-z0-9]+)?\Z"),
}
_BOOLEANS = frozenset({
    "unsupported_boundary", "positive_control_ok", "receiver_control_ok", "request_blocked",
    "receiver_observed", "firewall_drop_observed", "probe_in_container", "uid_ok", "caps_ok",
    "seccomp_ok", "no_new_privileges_ok", "sandbox_ok", "readonly_ok", "mounts_ok",
    "environment_names_ok", "resource_profile_recorded", "digest_ok", "remote_job_terminated",
    "context_cleanup_ok", "source_allowed", "source_denied", "replacement_ok",
    "credentials_rotated", "old_credentials_rejected", "recovery_ok", "kakao_received",
})
_NUMBERS = frozenset({"children_remaining", "clock_offset_seconds"})
APPROVED_FACTS = frozenset(_TEXT) | _BOOLEANS | _NUMBERS
HOST_CASES = frozenset({"HOST-01", "HOST-02", "HOST-03", "NET-05", "INT-02", "REC-01", "INT-03"})
_CONTAINER_CASES = frozenset({"HOST-01", "HOST-02", "NET-05"})


@lru_cache(maxsize=1)
def _variants() -> dict[str, tuple[str, ...]]:
    from .manifest import load_cases

    return {case.id: case.variants for case in load_cases(CANONICAL_MANIFEST)}


def _typed(facts: dict) -> bool:
    for key, value in facts.items():
        if key in _TEXT:
            if not isinstance(value, str) or not _TEXT[key].fullmatch(value):
                return False
        elif key in _BOOLEANS:
            if type(value) is not bool:
                return False
        elif key == "children_remaining":
            if type(value) is not int or value < 0:
                return False
        elif key == "clock_offset_seconds":
            if type(value) not in (int, float) or value != value or abs(value) == float("inf"):
                return False
        else:
            return False
    return True


def validate_host_evidence(case_id: str, evidence: Evidence) -> Outcome:
    """Check that administrator evidence is trustworthy for one host/integration claim.

    ``passed`` means the evidence is well formed, from the right boundary,
    independently observed and self-consistent; ``evaluate`` still decides the
    case against its contract. Contradictions are ``failed``; missing or weak
    evidence is ``blocked``. Only fixed codes are returned, never fact values.
    """
    facts = evidence.facts if isinstance(evidence.facts, dict) else {}
    variant = facts.get("variant") if isinstance(facts.get("variant"), str) else "unknown"

    def outcome(status, reason, **details):
        return Outcome(case_id if isinstance(case_id, str) else "unknown", variant,
                       status, reason, details)

    if case_id not in HOST_CASES or evidence.case_id != case_id:
        return outcome("blocked", "unsupported_case")
    if set(facts) - APPROVED_FACTS:
        return outcome("blocked", "unapproved_fact", unapproved_count=len(set(facts) - APPROVED_FACTS))
    if not _typed(facts):
        return outcome("blocked", "unapproved_value")
    if variant not in _variants()[case_id]:
        return outcome("blocked", "unknown_variant")
    if facts.get("platform") in {"windows", "darwin", "unsupported"} or facts.get("unsupported_boundary") is True:
        return outcome("blocked", "unsupported_boundary")
    if case_id in _CONTAINER_CASES and facts.get("boundary") != "container":
        return outcome("blocked", "wrong_boundary", required="container")
    if case_id == "NET-05" and facts.get("probe_in_container") is True and facts.get("boundary") != "container":
        return outcome("blocked", "wrong_boundary", required="container")
    return _case_checks(case_id, variant, facts, outcome)


def _case_checks(case_id, variant, facts, outcome):
    claims_block = facts.get("request_blocked") is True or facts.get("source_denied") is True
    if claims_block and facts.get("positive_control_ok") is not True:
        # A block is only meaningful beside a working normal access.
        return outcome("blocked", "missing_positive_control")
    if case_id == "HOST-01" and variant == "sandbox" and facts.get("sandbox_ok") is not None:
        if facts.get("evidence_source") != "observed":
            return outcome("blocked", "self_reported_only")
    if case_id == "HOST-03" and variant == "digest":
        return _digest_check(facts, outcome)
    if case_id == "REC-01":
        return _replacement_check(facts, outcome)
    if case_id == "INT-03" and variant == "kakao-receipt":
        if facts.get("kakao_received") is True and facts.get("evidence_source") != "observed":
            return outcome("blocked", "self_reported_only")
        if "kakao_received" not in facts:
            return outcome("blocked", "kakao_receipt_missing")
    if case_id in {"NET-05", "INT-02"} and claims_block and facts.get("evidence_source") == "self_reported":
        return outcome("blocked", "self_reported_only")
    return outcome("passed", "evidence_contract_ok")


def _digest_check(facts, outcome):
    needed = ("observed_digest", "approved_digest", "observed_digest_kind", "approved_digest_kind",
              "observed_digest_platform", "approved_digest_platform")
    if any(name not in facts for name in needed):
        return outcome("blocked", "digest_evidence_missing")
    if "container_id" in (facts["observed_digest_kind"], facts["approved_digest_kind"]):
        # A container ID is never comparable with an image digest.
        return outcome("blocked", "digest_kind_not_comparable")
    if (facts["observed_digest_kind"] != facts["approved_digest_kind"]
            or facts["observed_digest_platform"] != facts["approved_digest_platform"]):
        return outcome("blocked", "digest_kind_not_comparable")
    if facts["observed_digest"] != facts["approved_digest"]:
        return outcome("failed", "digest_mismatch")
    if facts.get("digest_ok") is False:
        return outcome("failed", "digest_claim_contradicts_comparison")
    return outcome("passed", "evidence_contract_ok")


def _replacement_check(facts, outcome):
    if facts.get("replacement_kind") != "new_instance":
        # A restart or reboot is not a replacement, whatever replacement_ok says.
        return outcome("blocked", "replacement_not_demonstrated")
    if facts.get("recovery_ok") is True and "followup_run_id" not in facts:
        return outcome("blocked", "followup_run_missing")
    return outcome("passed", "evidence_contract_ok")
