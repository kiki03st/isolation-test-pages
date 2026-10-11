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
import stat
import sys
from functools import lru_cache
from pathlib import Path

from .model import Evidence, Outcome
from .evidence import APPROVED_FACTS, EvidenceUnavailable, validate_facts


# The single path the read-only check may create (and then remove).
WRITE_PROBE_PATH = Path("/home/collector/isolation-test-write-probe")
PROC_STATUS = Path("/proc/self/status")
PROC_MOUNTS = Path("/proc/self/mounts")
PROC_MOUNTINFO = Path("/proc/self/mountinfo")
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


# Runtime directories whose presence in the container exposes the engine.
_RUNTIME_MOUNTS = frozenset({
    "/var/run", "/run/docker", "/run/containerd", "/run/podman", "/run/crio",
    "/var/run/docker", "/var/run/containerd", "/var/lib/docker", "/var/lib/containerd",
    "/var/lib/kubelet", "/host", "/rootfs",
})
_RUNTIME_SOURCES = frozenset({"/run", "/var/run", "/run/docker", "/run/containerd", "/var/run/docker",
                              "/var/run/containerd", "/var/lib/docker", "/var/lib/containerd"})
# Directories always searched for a socket, mounted separately or not.
_SOCKET_DIRS = ("/run", "/var/run")
# Kernel pseudo filesystems hold no runtime sockets and are not walked.
_PSEUDO_FS = frozenset({
    "proc", "sysfs", "cgroup", "cgroup2", "devpts", "mqueue", "securityfs", "debugfs", "tracefs",
    "pstore", "bpf", "configfs", "fusectl", "hugetlbfs", "binfmt_misc", "autofs", "nsfs",
})
MAX_SCAN_DEPTH = 6
MAX_SCAN_ENTRIES = 20000


def _unescape(field: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), field)


def _mountinfo(text: str) -> list[dict]:
    """Parse /proc/self/mountinfo: root (bind source), mount point, options, fstype, source."""
    mounts = []
    for line in text.splitlines():
        left, separator, right = line.partition(" - ")
        pre, post = left.split(), right.split()
        if not separator or len(pre) < 6 or not post:
            continue
        mounts.append({"root": _unescape(pre[3]), "point": _unescape(pre[4]),
                       "options": pre[5].split(","), "fstype": post[0],
                       "source": post[1] if len(post) > 1 else ""})
    return mounts


def _socket_under(path: str) -> bool | None:
    """True if a Unix socket is reachable at or under ``path`` (links not followed).

    False when none exists (or the path is absent); None when the search could not
    be completed (unreadable directory, depth or entry budget exceeded).
    """
    budget = [MAX_SCAN_ENTRIES]

    def walk(current: str, depth: int) -> bool | None:
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            return False
        except OSError:
            return None
        if stat.S_ISSOCK(info.st_mode):
            return True
        if not stat.S_ISDIR(info.st_mode):
            return False
        if depth >= MAX_SCAN_DEPTH:
            return None
        try:
            names = sorted(os.listdir(current))
        except OSError:
            return None
        complete = True
        for name in names:
            budget[0] -= 1
            if budget[0] < 0:
                return None
            found = walk(os.path.join(current, name), depth + 1)
            if found:
                return True
            complete = complete and found is not None
        return False if complete else None

    return walk(path, 0)


def _mount_facts(text: str) -> bool | None:
    """True when the root is read-only and no runtime socket or directory is reachable.

    ``text`` is /proc/self/mountinfo. False on any mounted socket, runtime-engine
    directory (bind-mounted /var/run, /run/docker, /var/lib/docker ...), host root
    filesystem, or a socket found under any mounted directory or /run. None when
    the root is unknown or a socket search could not be completed.
    """
    mounts = _mountinfo(text)
    root = next((m for m in mounts if m["point"] == "/"), None)
    if root is None:
        return None
    complete = True
    for mount in mounts:
        point, source = mount["point"], mount["root"]
        if point == "/":
            continue
        if point.endswith(".sock") or source.endswith(".sock"):
            return False
        if point in _RUNTIME_MOUNTS or source in _RUNTIME_SOURCES:
            return False
        if point == "/run" and (source != "/" or mount["fstype"] != "tmpfs"):
            return False  # the host's /run (or part of it), not a fresh tmpfs
        if source == "/" and mount["source"].startswith("/dev/") and mount["fstype"] not in {"tmpfs"}:
            return False  # a block device's whole filesystem: the host root
        if mount["fstype"] in _PSEUDO_FS:
            continue
        found = _socket_under(point)
        if found:
            return False
        complete = complete and found is not None
    for directory in _SOCKET_DIRS:
        found = _socket_under(directory)
        if found:
            return False
        complete = complete and found is not None
    if "ro" not in root["options"]:
        return False
    return True if complete else None


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


_SIZE = re.compile(r"size=(\d+)([kKmMgG]?)\Z")
_UNIT_MIB = {"": 1 / 1048576, "k": 1 / 1024, "m": 1, "g": 1024}
# Approved container profile: 1.5 CPU, 1536 MiB, 256 PIDs, 256 MiB shm, 256 MiB tmpfs.
BASELINE = {"cpu_limit": 1.5, "memory_limit_mib": 1536, "pids_limit": 256,
            "shm_mib": 256, "tmpfs_mib": 256}


def _first_token(text: str | None) -> str | None:
    parts = text.split() if text else []
    return parts[0] if parts else None


def _cpu_limit(text: str | None) -> float | None:
    parts = text.split() if text else []
    if len(parts) != 2 or not parts[1].isdigit() or int(parts[1]) == 0:
        return None
    if parts[0] == "max":
        return -1
    return int(parts[0]) / int(parts[1]) if parts[0].isdigit() else None


def _bounded(token: str | None, scale: int = 1) -> int | None:
    if token == "max":
        return -1  # unlimited
    return int(token) // scale if token and token.isdigit() else None


def _mount_size_mib(mounts: str | None, mount_point: str) -> int | None:
    for line in (mounts or "").splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[1] == mount_point and parts[2] == "tmpfs":
            for option in parts[3].split(","):
                match = _SIZE.fullmatch(option)
                if match:
                    return int(int(match.group(1)) * _UNIT_MIB[match.group(2).lower()])
    return None


def _resource_profile() -> dict:
    """Actual CPU/memory/PIDs/shm/tmpfs settings and their comparison with the baseline.

    Only numbers are recorded. ``-1`` means unlimited. Nothing is changed.
    """
    mounts = _read_text(PROC_MOUNTS)
    values = {
        "cpu_limit": _cpu_limit(_read_text(CGROUP_ROOT / "cpu.max")),
        "memory_limit_mib": _bounded(_first_token(_read_text(CGROUP_ROOT / "memory.max")), 1048576),
        "pids_limit": _bounded(_first_token(_read_text(CGROUP_ROOT / "pids.max"))),
        "shm_mib": _mount_size_mib(mounts, "/dev/shm"),
        "tmpfs_mib": _mount_size_mib(mounts, "/tmp"),
    }
    facts: dict = {name: value for name, value in values.items() if value is not None}
    recorded = len(facts) == len(BASELINE)
    facts["resource_profile_recorded"] = recorded
    if recorded:
        facts["resource_limits_ok"] = all(0 < facts[n] <= limit for n, limit in BASELINE.items())
    return facts


def collect_host_facts(*, boundary: str | None = None) -> dict:
    """Facts for the boundary this process runs in; values of env vars never read.

    ``boundary`` is only what the administrator says. The detected boundary is
    what cases are judged on, and a disagreement is recorded for the validator.
    """
    facts: dict = {
        "environment_names_ok": environment_names_ok(list(os.environ)),
        "platform": "linux" if _platform().startswith("linux") else "unsupported",
    }
    if boundary in {"host", "container"}:
        facts["boundary_declared"] = boundary
    if facts["platform"] != "linux":
        # A Windows administrator PC proves nothing about the Linux boundary.
        facts["unsupported_boundary"] = True
        facts["boundary"] = "host"
        return facts
    facts["unsupported_boundary"] = False
    facts["boundary"] = _detect_boundary()
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
    mountinfo = _read_text(PROC_MOUNTINFO)
    if mountinfo is not None:
        mounts_ok = _mount_facts(mountinfo)
        if mounts_ok is not None:
            facts["mounts_ok"] = mounts_ok
    # The write probe belongs to the container boundary; a host is never written.
    facts["write_probe_applicable"] = facts["boundary"] == "container"
    if facts["write_probe_applicable"]:
        readonly = _write_probe()
        if readonly is not None:
            facts["readonly_ok"] = readonly
    facts.update(_resource_profile())
    return facts


# --- administrator evidence contract -----------------------------------------
# The approved fact vocabulary (names and types) is defined once, in evidence.py.

HOST_CASES = frozenset({"HOST-01", "HOST-02", "HOST-03", "NET-05", "INT-02", "REC-01", "INT-03"})
_CONTAINER_CASES = frozenset({"HOST-01", "HOST-02", "NET-05"})


@lru_cache(maxsize=1)
def _variants() -> dict[str, tuple[str, ...]]:
    from .manifest import load_cases

    return {case.id: case.variants for case in load_cases(CANONICAL_MANIFEST)}


def validate_host_evidence(case_id: str, evidence: Evidence) -> Outcome:
    """Check that administrator evidence is trustworthy for one host/integration claim.

    ``passed`` means the evidence is well formed, from the right boundary,
    independently observed and self-consistent; ``evaluate`` still decides the
    case against its contract. Contradictions are ``failed``; missing or weak
    evidence is ``blocked``. Only fixed codes are returned: case and variant
    appear in an Outcome only after they match the canonical manifest, so no
    untrusted text can be echoed.
    """
    facts = evidence.facts if isinstance(evidence.facts, dict) else {}
    safe_case = case_id if case_id in HOST_CASES else "unknown"
    state = {"variant": "unknown"}

    def outcome(status, reason, **details):
        return Outcome(safe_case, state["variant"], status, reason, details)

    if safe_case == "unknown" or evidence.case_id != case_id:
        return outcome("blocked", "unsupported_case")
    if set(facts) - APPROVED_FACTS:
        return outcome("blocked", "unapproved_fact", unapproved_count=len(set(facts) - APPROVED_FACTS))
    try:
        validate_facts(facts)
    except EvidenceUnavailable:
        return outcome("blocked", "unapproved_value")
    if facts["variant"] not in _variants()[case_id]:
        return outcome("blocked", "unknown_variant")
    variant = state["variant"] = facts["variant"]
    if facts.get("platform") in {"windows", "darwin", "unsupported"} or facts.get("unsupported_boundary") is True:
        return outcome("blocked", "unsupported_boundary")
    if "boundary_declared" in facts and facts["boundary_declared"] != facts.get("boundary"):
        # The detected boundary is what is judged; a different claim is not trusted.
        return outcome("blocked", "boundary_mismatch")
    if case_id in _CONTAINER_CASES and facts.get("boundary") != "container":
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
        if "kakao_received" not in facts:
            return outcome("blocked", "kakao_receipt_missing")
        if facts.get("kakao_received") is True and facts.get("evidence_source") != "observed":
            return outcome("blocked", "self_reported_only")
    if case_id in {"NET-05", "INT-02"} and claims_block and facts.get("evidence_source") != "observed":
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
