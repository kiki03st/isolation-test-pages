"""Administrator CLI: environment check, listing, execution, reporting and host probe.

Execution has two stages. ``observe`` performs the only actions the tool takes
(collector, AI and BE requests) and records what the runner itself saw.
``judge`` correlates that observation with administrator evidence recorded for
the same run_id, case and variant and decides through ``evaluate``. The
observation is stored in the report, so ``report`` can judge again after the
administrator has added evidence for the recorded run_ids.

The CLI never opens the public Pages URL itself; page URLs only go to the
collector. A case's expected values are used for comparison, never as input.
"""

import argparse
import asyncio
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import time
from dataclasses import asdict, dataclass, field, replace
from datetime import timedelta
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from .adapters import ai as ai_adapter
from .adapters import backend as backend_adapter
from .adapters import collector as collector_adapter
from .adapters.collector import PREPARATION_CODES, CollectionError
from .evaluate import MAX_CONCURRENT_TRIALS, combine, evaluate, merge_analysis, merge_recovery, summarize
from .evidence import (
    MAX_CLOCK_OFFSET_SECONDS, EvidenceUnavailable, _read_bounded, load_evidence, parse_utc,
    validate_facts,
)
from .host_probes import HOST_CASES, validate_host_evidence
from .manifest import load_cases
from .model import CaseSpec, CollectedPage, Evidence, Outcome, RuntimeConfig
from .targets import case_url


# Adapter seams. Tests replace them with in-process fakes; nothing else does.
COLLECT = collector_adapter.collect
ANALYZE = ai_adapter.analyze_locally
PROBE_BACKEND = backend_adapter.probe_backend

CANONICAL_MANIFEST = Path(__file__).resolve().parents[1] / "cases.json"
STATIC_ROOT = Path(__file__).resolve().parents[3] / "test-pages"
CONTROL_CASE, CONTROL_VARIANT = "COL-01", "default"
CONCURRENCY_SAMPLE = ("LIM-02", "slow-stream")
RESOURCE_FACTS = ("cpu_limit", "memory_limit_mib", "pids_limit", "shm_mib", "tmpfs_mib")
# The boundary whose host-probe output a HOST case is judged on.
PROBE_BOUNDARY = {"HOST-01": "container", "HOST-02": "container", "HOST-03": "host"}
PROBE_CASES = frozenset(PROBE_BOUNDARY)
# A probe must be collected after the run issued its batch id, and soon after.
MAX_PROBE_DELAY = timedelta(hours=24)
_BATCH = re.compile(r"r[0-9a-f]{32}\Z")
# Administrator evidence only; the runner takes no action for these.
EVIDENCE_ONLY = frozenset({
    ("NET-05", None), ("HOST-01", None), ("HOST-02", None), ("HOST-03", None),
    ("INT-02", None), ("REC-01", None), ("INT-04", "callback-failure"),
})
# Collector errors that are the observation a variant expects (a rejection).
# Any other error after the runner acted leaves the trial inconclusive.
EXPECTED_ERRORS = {
    ("INT-01", "missing"): frozenset({"authentication_failed"}),
    ("INT-01", "wrong-token"): frozenset({"authentication_failed"}),
    ("INT-01", "untrusted-ca"): frozenset({"tls_verification_failed"}),
}
ANALYSIS_CASES = frozenset({f"ANA-0{n}" for n in range(1, 8)})
PAIRED = {"ANA-07": {"baseline": "injection", "injection": "baseline"}}
_BLOCKING_CODES = PREPARATION_CODES | {"stub_not_collected"}
_TOKEN_MODES = {"valid": "valid", "missing": "missing", "wrong_token": "wrong"}
_COMMIT = re.compile(r"[0-9a-f]{7,40}\Z")


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def new_run_id() -> str:
    """An unguessable per-(case, variant) id: receiver events are forgeable by id alone."""
    return "r" + secrets.token_hex(16)


def host_run_id(batch: str, case_id: str, variant: str) -> str:
    """HOST variants of one run share the unguessable batch id the host probe records."""
    return f"{batch}-{case_id.lower()}-{variant}"


def probe_batch_id(case_id: str, variant: str, run_id: str) -> str | None:
    """The batch id a host probe must carry for this HOST trial, or None."""
    suffix = f"-{case_id.lower()}-{variant}"
    if case_id not in PROBE_CASES or not isinstance(run_id, str) or not run_id.endswith(suffix):
        return None
    batch = run_id[:-len(suffix)]
    return batch if _BATCH.fullmatch(batch) else None


@lru_cache(maxsize=1)
def _canonical() -> dict[str, CaseSpec]:
    return {case.id: case for case in load_cases(CANONICAL_MANIFEST)}


def _contract(case: CaseSpec, variant: str) -> dict:
    variants = case.expected_observations.get("variants", {})
    contract = variants.get(variant) if isinstance(variants, dict) else None
    return contract if isinstance(contract, dict) else {}


def _required(case: CaseSpec, variant: str) -> set[str]:
    contract = _contract(case, variant)
    return (set(case.required_evidence) | set(contract.get("required_evidence", ()))
            | set(contract.get("assertions", {}).get("required_facts", {})))


# --- observation -----------------------------------------------------------------

@dataclass
class Observation:
    run_id: str
    started_at: str
    ended_at: str = ""
    facts: dict = field(default_factory=dict)
    page: CollectedPage | None = None
    error: str | None = None
    preblocked: str | None = None
    stages_ms: dict = field(default_factory=dict)
    control: dict | None = None
    analysis: Outcome | None = None
    recovery: dict | None = None
    backend: Outcome | None = None
    actions: bool = False
    notes: dict = field(default_factory=dict)

    def to_json(self) -> dict:
        data = asdict(self)
        for key in ("analysis", "backend"):
            value = getattr(self, key)
            data[key] = None if value is None else {
                "status": value.status, "reason": value.reason, "details": dict(value.details)}
        return data

    @classmethod
    def from_json(cls, data: Any, case_id: str, variant: str) -> "Observation":
        if not isinstance(data, dict) or not isinstance(data.get("run_id"), str) \
                or not isinstance(data.get("facts"), dict):
            raise ValueError("observation is malformed")
        values = {key: data[key] for key in cls.__dataclass_fields__ if key in data}
        values["page"] = _page_from(values.get("page"))
        for key in ("analysis", "backend"):
            values[key] = _outcome_from(values.get(key), case_id, variant)
        return cls(**values)


def _page_from(value: Any) -> CollectedPage | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("page is malformed")
    page = CollectedPage(**{name: value[name] for name in CollectedPage.__dataclass_fields__})
    return replace(page, redirect_chain=tuple(page.redirect_chain), failures=tuple(page.failures))


def _outcome_from(value: Any, case_id: str, variant: str) -> Outcome | None:
    if value is None:
        return None
    if not isinstance(value, dict) or not isinstance(value.get("details"), dict) \
            or value.get("status") not in {"passed", "failed", "not_run", "blocked"}:
        raise ValueError("outcome is malformed")
    return Outcome(case_id, variant, value["status"], str(value.get("reason")), value["details"])


async def _collect(config: RuntimeConfig, url: str, token_mode: str = "valid"):
    try:
        return await COLLECT(config, url, token_mode), None
    except CollectionError as error:
        return None, error.code


class _Stage:
    def __init__(self, obs: Observation, name: str):
        self.obs, self.name = obs, name

    def __enter__(self):
        self.start = time.monotonic()
        return self

    def __exit__(self, *_):
        self.obs.stages_ms[self.name] = int((time.monotonic() - self.start) * 1000)


def _runner_evidence(run_id: str, case_id: str, variant: str, started: str, facts: dict) -> Evidence:
    return Evidence(run_id, case_id, started, _now(), {"variant": variant, **facts})


async def _normal_request(config: RuntimeConfig, *, recovery: bool = False) -> dict:
    """One COL-01 collection judged on the runner's own observation.

    After a limit trial (``recovery``) a failed normal request is non-compliance:
    ``failed``, unless the failure is a setup problem.
    """
    case = _canonical()[CONTROL_CASE]
    run_id, started = new_run_id(), _now()
    try:
        url = case_url(case, CONTROL_VARIANT, config, run_id)
    except ValueError:
        return {"run_id": run_id, "status": "blocked", "reason": "target_not_configured", "details": {}}
    begin = time.monotonic()
    page, code = await _collect(config, url)
    details = {"run_id": run_id, "elapsed_ms": int((time.monotonic() - begin) * 1000)}
    if page is None:
        status = "failed" if recovery and code not in _BLOCKING_CODES else "blocked"
        return {"status": status, "reason": code, "details": details}
    outcome = evaluate(case, CONTROL_VARIANT, page,
                       _runner_evidence(run_id, case.id, CONTROL_VARIANT, started, {"collection": True}),
                       config.capabilities)
    return {"status": outcome.status, "reason": outcome.reason, "details": details}


async def _positive_control(config: RuntimeConfig, obs: Observation) -> None:
    with _Stage(obs, "positive_control"):
        result = await _normal_request(config)
    obs.control = {"ok": result["status"] == "passed", "reason": result["reason"], **result["details"]}
    obs.facts["positive_control_ok"] = obs.control["ok"]


async def _recovery(case: CaseSpec, config: RuntimeConfig, obs: Observation) -> None:
    if case.recovery_case is None:
        return
    with _Stage(obs, "recovery"):
        obs.recovery = await _normal_request(config, recovery=True)


def _apply_analysis(obs: Observation, outcome: Outcome) -> None:
    obs.analysis = outcome
    facts = outcome.details.get("facts")
    if isinstance(facts, dict):
        obs.facts.update(facts)


def _timeout_client() -> SimpleNamespace:
    async def parse(**_kwargs):
        raise TimeoutError()

    return SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(parse=parse)))


def _fixed_page(relative: str) -> CollectedPage | None:
    """A committed synthetic sample read locally; no network is involved."""
    path = STATIC_ROOT / relative
    try:
        html = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    url = f"https://example.invalid/{relative}"
    return CollectedPage(url, url, (), 200, "text/html", html, None, 0, ())


async def _analysis_page(case: CaseSpec, variant: str, config: RuntimeConfig, obs: Observation) -> None:
    with _Stage(obs, "analysis"):
        _apply_analysis(obs, await ANALYZE(case, variant, obs.page))
    other = PAIRED.get(case.id, {}).get(variant)
    if other is None:
        return
    pair_id = obs.run_id[:56] + "-pair"
    with _Stage(obs, "pair"):
        page, code = await _collect(config, case_url(case, other, config, pair_id))
        if page is None:
            obs.notes["pair_collection_error"] = code
            return
        paired = await ANALYZE(case, other, page)
    obs.facts["paired_verdict_equal"] = ai_adapter.paired_verdicts_equal(obs.analysis, paired)


async def _int01(case, variant, config, obs, mode) -> None:
    await _positive_control(config, obs)
    url = case_url(_canonical()[CONTROL_CASE], CONTROL_VARIANT, config, obs.run_id)
    with _Stage(obs, "collect"):
        if mode == "untrusted_ca":
            if config.ca_file is None:
                # Without a private CA the default trust store cannot show a rejection.
                obs.preblocked = "untrusted_ca_not_demonstrable"
                return
            obs.page, obs.error = await _collect(replace(config, ca_file=None), url)
            if obs.page is not None or obs.error == "tls_verification_failed":
                obs.facts["tls_rejected"] = obs.error == "tls_verification_failed"
                obs.facts["page_opened"] = obs.page is not None
            return
        obs.page, obs.error = await _collect(config, url, _TOKEN_MODES[mode])
    if obs.page is not None:
        obs.facts["collection"] = True
    if mode == "valid":
        if obs.page is not None or obs.error == "authentication_failed":
            obs.facts["authentication_ok"] = obs.page is not None
    elif obs.page is not None or obs.error == "authentication_failed":
        obs.facts["authentication_rejected"] = obs.error == "authentication_failed"
        obs.facts["page_opened"] = obs.page is not None


async def _concurrency(case, config, obs) -> None:
    limit = config.limits.get("collector_concurrency")
    if type(limit) is not int or limit < 1:
        obs.preblocked = "collector_limit_unknown"
        return
    if limit + 1 > MAX_CONCURRENT_TRIALS:
        obs.preblocked = "concurrency_trial_exceeds_cap"
        return
    sample_id, sample_variant = CONCURRENCY_SAMPLE
    try:
        url = case_url(_canonical()[sample_id], sample_variant, config, obs.run_id)
    except ValueError:
        obs.preblocked = "target_not_configured"
        return
    await _positive_control(config, obs)
    with _Stage(obs, "concurrency"):
        results = await asyncio.gather(*(_collect(config, url) for _ in range(limit + 1)))
    obs.facts["concurrency_limit"] = limit
    obs.facts["limit_plus_one_sent"] = True
    obs.notes["concurrent_results"] = [
        code if page is None else (list(page.failures) or "collected") for page, code in results]
    await _recovery(case, config, obs)


async def _route(case: CaseSpec, variant: str, config: RuntimeConfig, obs: Observation) -> None:
    contract = _contract(case, variant)
    inputs = contract.get("inputs", {})
    needed = set(case.required_capabilities) | set(contract.get("required_capabilities", ()))
    missing = sorted(needed - set(config.capabilities))
    if missing:
        obs.preblocked = "missing_capability"
        obs.notes["capabilities"] = missing
        return
    if (case.id, None) in EVIDENCE_ONLY or (case.id, variant) in EVIDENCE_ONLY:
        return
    obs.actions = True
    if case.id == "INT-03":
        # Both variants submit through the BE with this trial's run_id; a Kakao
        # receipt record must then be bound to that run_id and window.
        with _Stage(obs, "backend"):
            obs.backend = await PROBE_BACKEND(case, config, run_id=obs.run_id)
        if variant == "pipeline":
            obs.facts["backend_result_ok"] = obs.backend.status == "passed"
            if type(obs.backend.details.get("first_response_deadline_ok")) is bool:
                obs.facts["first_response_deadline_ok"] = obs.backend.details["first_response_deadline_ok"]
        return
    if case.id in {"ANA-08", "LIM-04"}:
        with _Stage(obs, "analysis"):
            _apply_analysis(obs, await ANALYZE(case, variant, None))
        return
    if case.id == "INT-04":
        page = _fixed_page("v1/cases/ana-01/index.html")
        if page is None:
            obs.preblocked = "fixed_sample_missing"
            return
        with _Stage(obs, "positive_control"):
            control = await ANALYZE(_canonical()["ANA-01"], "default", page)
        obs.control = {"ok": control.status == "passed", "reason": control.reason}
        obs.facts["positive_control_ok"] = obs.control["ok"]
        with _Stage(obs, "analysis"):
            if variant == "llm-timeout":
                _apply_analysis(obs, await ANALYZE(case, variant, page, client=_timeout_client()))
            else:
                _apply_analysis(obs, await ANALYZE(case, variant, None))
        codes = obs.analysis.details.get("failure_codes")
        if obs.analysis.status != "blocked" and isinstance(codes, list):
            # The trial input (fixed sample, or no page for a collection failure)
            # carrying the failure codes the AI itself reported, never expected ones.
            html = page.html if variant == "llm-timeout" else ""
            obs.page = replace(page, html=html, failures=tuple(str(code) for code in codes))
        return
    if case.id == "INT-01":
        await _int01(case, variant, config, obs, inputs.get("token_mode", "valid"))
        return
    if case.id == "LIM-06":
        await _concurrency(case, config, obs)
        return
    try:
        url = case_url(case, variant, config, obs.run_id)
    except ValueError:
        obs.preblocked = "target_not_configured"
        return
    required = _required(case, variant)
    if "positive_control_ok" in required:
        await _positive_control(config, obs)
    with _Stage(obs, "collect"):
        obs.page, obs.error = await _collect(config, url)
    if obs.page is not None:
        obs.facts["collection"] = True
        if case.id == "NET-07" and obs.page.html:
            obs.facts["page_opened"] = True
    for name in ("collector_deadline_s", "deadline_grace_s"):
        if name in required and name in config.limits:
            obs.facts[name] = config.limits[name]  # the applied profile, recorded as such
    if case.id in ANALYSIS_CASES and obs.page is not None:
        await _analysis_page(case, variant, config, obs)
    await _recovery(case, config, obs)


async def observe(case: CaseSpec, variant: str, config: RuntimeConfig, run_id: str) -> Observation:
    obs = Observation(run_id=run_id, started_at=_now())
    try:
        await _route(case, variant, config, obs)
    finally:
        obs.ended_at = _now()
    return obs


# --- judgement ------------------------------------------------------------------------

def _admin_evidence(case: CaseSpec, variant: str, obs: Observation, config: RuntimeConfig, notes: dict):
    if config.evidence_dir is None:
        notes["admin_evidence"] = "evidence_dir_not_configured"
        return None
    try:
        return load_evidence(config.evidence_dir, obs.run_id, case.id, variant=variant)
    except EvidenceUnavailable as error:
        notes["admin_evidence"] = str(error)
        return None


def _probe_files(directory: Path):
    for entry in sorted(os.scandir(directory), key=lambda item: item.name):
        if not entry.name.endswith(".json"):
            continue
        try:
            info = os.lstat(entry.path)
            if not stat.S_ISREG(info.st_mode):
                continue
            data = json.loads(_read_bounded(Path(entry.path)).decode("utf-8"))
        except (OSError, EvidenceUnavailable, UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            continue
        if isinstance(data, dict) and data.get("schema") == "host-probe-v1" \
                and isinstance(data.get("facts"), dict):
            yield entry.name, data


def _collected_at(value) -> "datetime | None":
    from datetime import datetime, timezone

    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo is not None else None


def _probe_facts(case: CaseSpec, variant: str, obs: Observation, admin: Evidence | None,
                 config: RuntimeConfig, notes: dict):
    """Facts of the one ``host-probe-v1`` output bound to this run, or None.

    A probe counts only when it carries this run's unguessable batch id, was
    collected (timezone-aware) after the run started and within MAX_PROBE_DELAY
    (and inside the administrator record's window when one exists), and comes
    from the boundary the case requires. Anything else is stale or foreign.
    """
    batch = probe_batch_id(case.id, variant, obs.run_id)
    if batch is None or config.evidence_dir is None:
        return None, None
    try:
        found = list(_probe_files(config.evidence_dir))
        run_start = parse_utc(obs.started_at)
        window = (parse_utc(admin.started_at), parse_utc(admin.ended_at)) if admin else None
    except (OSError, EvidenceUnavailable):
        return None, None
    slack = timedelta(seconds=MAX_CLOCK_OFFSET_SECONDS)
    accepted, rejected = [], 0
    for name, data in found:
        at = _collected_at(data.get("collected_at"))
        ok = (data.get("run_id") == batch and at is not None
              and run_start - slack <= at <= run_start + MAX_PROBE_DELAY
              and (window is None or window[0] - slack <= at <= window[1] + slack)
              and data["facts"].get("boundary") == PROBE_BOUNDARY[case.id])
        if ok:
            accepted.append((name, data["facts"]))
        else:
            rejected += 1
    if rejected:
        notes["host_probe_rejected"] = rejected
    if len(accepted) != 1:
        if accepted:
            notes["host_probe_ambiguous"] = len(accepted)
        return None, None
    name, facts = accepted[0]
    notes["host_probe"] = name
    return {k: v for k, v in facts.items() if k != "variant"}, name


def _overlaps(admin: Evidence, obs: Observation) -> bool:
    slack = timedelta(seconds=MAX_CLOCK_OFFSET_SECONDS)
    try:
        start, end = parse_utc(admin.started_at), parse_utc(admin.ended_at)
        run_start, run_end = parse_utc(obs.started_at), parse_utc(obs.ended_at)
    except EvidenceUnavailable:
        return False
    return start <= run_end + slack and end >= run_start - slack


def _merge(*sources: dict | None):
    merged: dict = {}
    for source in sources:
        for key, value in (source or {}).items():
            if key in merged and (type(merged[key]), merged[key]) != (type(value), value):
                return None, key
            merged[key] = value
    return merged, None


def judge(case: CaseSpec, variant: str, obs: Observation, config: RuntimeConfig) -> Outcome:
    notes = dict(obs.notes)
    base = {
        "run_id": obs.run_id, "started_at": obs.started_at, "ended_at": obs.ended_at,
        "stages_ms": dict(obs.stages_ms), "positive_control": obs.control,
        "observed_facts": dict(obs.facts), "collection_error": obs.error,
        "observation": obs.to_json(),
    }

    def finish(outcome: Outcome) -> Outcome:
        return Outcome(case.id, variant, outcome.status, outcome.reason,
                       {**outcome.details, **base, "notes": notes})

    if obs.preblocked:
        return finish(Outcome(case.id, variant, "blocked", obs.preblocked))
    if obs.error in _BLOCKING_CODES:
        return finish(Outcome(case.id, variant, "blocked", obs.error))
    if obs.actions and obs.error is not None and obs.error not in EXPECTED_ERRORS.get((case.id, variant), ()):
        # A transport failure the runner saw is not a block; admin facts cannot override it.
        return finish(Outcome(case.id, variant, "blocked", "runner_observation_inconclusive"))
    admin = _admin_evidence(case, variant, obs, config, notes)
    if admin is not None and obs.actions and not _overlaps(admin, obs):
        return finish(Outcome(case.id, variant, "blocked", "evidence_window_mismatch"))
    probe, probe_name = _probe_facts(case, variant, obs, admin, config, notes)
    merged, conflict = _merge({"variant": variant}, obs.facts, admin.facts if admin else None, probe)
    if merged is None:
        return finish(Outcome(case.id, variant, "blocked", "evidence_conflict", {"conflict": conflict}))
    starts, ends = [obs.started_at], [obs.ended_at]
    if admin is not None:
        starts.append(admin.started_at)
        ends.append(admin.ended_at)
    try:
        start = min(starts, key=parse_utc)
        end = max(ends, key=parse_utc)
        validate_facts(merged)
    except EvidenceUnavailable:
        return finish(Outcome(case.id, variant, "blocked", "malformed_evidence"))
    references = (admin.references if admin else ()) + ((probe_name,) if probe_name else ())
    evidence = Evidence(obs.run_id, case.id, start, end, merged, references)
    outcome = evaluate(case, variant, obs.page, evidence, config.capabilities)
    if case.id in HOST_CASES and (admin is not None or probe is not None):
        outcome = combine(outcome, validate_host_evidence(case.id, evidence), "host_evidence")
    outcome = merge_analysis(case, variant, outcome, obs.analysis)
    outcome = combine(outcome, obs.backend, "backend")
    if case.recovery_case is not None and obs.actions:
        recovery = None if obs.recovery is None else Outcome(
            case.recovery_case, CONTROL_VARIANT, obs.recovery["status"], str(obs.recovery["reason"]),
            dict(obs.recovery.get("details", {})))
        outcome = merge_recovery(outcome, recovery)
    profile = {name: merged[name] for name in RESOURCE_FACTS if name in merged}
    if profile:
        base["resource_profile"] = profile
    base["evidence_references"] = list(references)
    return finish(outcome)


async def run_case(case: CaseSpec, variant: str, config: RuntimeConfig, run_id: str) -> Outcome:
    """Observe one variant and judge it against the runner's and the administrator's evidence."""
    return judge(case, variant, await observe(case, variant, config, run_id), config)


# --- CLI -------------------------------------------------------------------------------

def _host_probe(output: Path, boundary: str | None, run_id: str) -> int:
    from datetime import datetime, timezone

    from .host_probes import collect_host_facts
    from .receiver import RUN_ID

    if not RUN_ID.fullmatch(run_id):
        print("error: --run-id must be the batch id issued by the run", file=sys.stderr)
        return 2
    facts = collect_host_facts(boundary=boundary)
    document = {"schema": "host-probe-v1", "run_id": run_id,
                "collected_at": datetime.now(timezone.utc).isoformat(), "facts": facts}
    try:
        # Exclusive create: never overwrite an existing evidence file.
        with output.open("x", encoding="utf-8") as handle:
            json.dump(document, handle,
                      ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
    except OSError:
        print("error: cannot create the output file", file=sys.stderr)
        return 2
    print(f"wrote {len(facts)} facts")
    return 0 if not facts.get("unsupported_boundary") else 2


def _secrets(config: RuntimeConfig) -> tuple[str, ...]:
    values = []
    if config.token_env and os.environ.get(config.token_env):
        values.append(os.environ[config.token_env])
    if config.backend_contract is not None:
        try:
            contract = backend_adapter.load_contract(config.backend_contract, config.allow_loopback_http)
        except Exception:  # an unreadable contract has no secret to remove
            contract = {}
        name = contract.get("auth_env")
        if name and os.environ.get(name):
            values.append(os.environ[name])
    return tuple(values)


def _select(cases: tuple[CaseSpec, ...], arguments) -> tuple[tuple[CaseSpec, ...], str]:
    if arguments.all:
        return cases, "all"
    if arguments.case or arguments.group:
        ids, groups = set(arguments.case or ()), set(arguments.group or ())
        unknown = (ids - {c.id for c in cases}) | (groups - {c.group for c in cases})
        if unknown:
            raise ValueError("unknown case or group selection")
        return tuple(c for c in cases if c.id in ids or c.group in groups), "subset"
    # Network, load, host and recovery trials run only when selected explicitly.
    return tuple(c for c in cases if c.risk_level == "basic"), "subset"


def _metadata(run_id, started, ended, manifest: Path, cases, config, scope, pages_commit) -> dict:
    try:
        version = json.loads(manifest.read_text(encoding="utf-8")).get("version")
    except (OSError, ValueError, AttributeError):
        version = None
    hashes = {case.id: hashlib.sha256(json.dumps(asdict(case), ensure_ascii=False, sort_keys=True)
                                      .encode("utf-8")).hexdigest() for case in cases}
    return {"run_id": run_id, "started_at": started, "ended_at": ended, "manifest_version": version,
            "pages_commit": pages_commit, "case_hashes": hashes, "limits": dict(config.limits),
            "required_ids": sorted(_canonical()), "scope": scope}


def _fill_not_run(outcomes: list[Outcome], cases: tuple[CaseSpec, ...]) -> tuple[Outcome, ...]:
    """One item per canonical (case, variant), ordered by the manifest; nothing is hidden."""
    done = {(item.case_id, item.variant): item for item in outcomes}
    ordered = []
    known = {case.id: case for case in cases}
    for case_id, case in _canonical().items():
        known.setdefault(case_id, case)
    for case in known.values():
        for variant in case.variants:
            ordered.append(done.pop((case.id, variant), None)
                           or Outcome(case.id, variant, "not_run", "not_selected"))
    return tuple(ordered) + tuple(done.values())


def _write(outcomes, output, metadata, config) -> int:
    from .report import write_reports

    json_path, html_path = write_reports(outcomes, output, metadata, secrets=_secrets(config))
    status, code = summarize(outcomes, frozenset(_canonical()))
    print(f"overall\t{status}\t{json_path.name}\t{html_path.name}")
    return code


async def _run_all(trials, config, results: list, batch: str) -> None:
    for case, variant in trials:
        run_id = host_run_id(batch, case.id, variant) if case.id in PROBE_CASES else new_run_id()
        try:
            results.append(await run_case(case, variant, config, run_id))
        except Exception:  # one broken trial must not lose the report; no exception text
            results.append(Outcome(case.id, variant, "blocked", "runner_internal_error",
                                   {"run_id": run_id}))


def _run(arguments) -> int:
    from .config import load_config

    try:
        cases = load_cases(arguments.manifest)
        config = load_config(arguments.config)
        selected, scope = _select(cases, arguments)
        if arguments.pages_commit is not None and not _COMMIT.fullmatch(arguments.pages_commit):
            raise ValueError("pages commit must be a hexadecimal commit id")
        if arguments.collector_limit is not None:
            if arguments.collector_limit < 1:
                raise ValueError("collector limit must be at least 1")
            config = replace(config, limits={**config.limits,
                                             "collector_concurrency": arguments.collector_limit})
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    run_id = "run-" + _now().replace(":", "").replace("-", "").replace(".", "")[:15] + "-" + secrets.token_hex(4)
    started = _now()
    trials = [(case, variant) for case in selected for variant in case.variants]
    results: list[Outcome] = []
    batch = new_run_id()  # shared by this run's HOST variants; `host-probe --run-id` records it
    if any(case.id in PROBE_CASES for case, _ in trials):
        print(f"host_batch	{batch}")
    try:
        asyncio.run(_run_all(trials, config, results, batch))
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("interrupted: unfinished items are recorded as not_run", file=sys.stderr)
    finished = {(item.case_id, item.variant) for item in results}
    first = True
    for case, variant in trials:
        if (case.id, variant) not in finished:
            # Cancelling the API call does not prove the remote job ended.
            results.append(Outcome(case.id, variant, "not_run", "interrupted",
                                   {"remote_job_unconfirmed": first}))
            first = False
    outcomes = _fill_not_run(results, cases)
    metadata = _metadata(run_id, started, _now(), arguments.manifest, cases, config, scope,
                         arguments.pages_commit)
    try:
        return _write(outcomes, arguments.output, metadata, config)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


def _report(arguments) -> int:
    from .config import load_config
    from .report import load_report

    try:
        outcomes, metadata = load_report(arguments.input)
        config = load_config(arguments.config) if arguments.config else None
        cases = {case.id: case for case in load_cases(arguments.manifest)}
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    if config is not None:
        rejudged = []
        for item in outcomes:
            case = cases.get(item.case_id)
            data = item.details.get("observation")
            if case is None or item.variant not in case.variants or data is None:
                rejudged.append(item)
                continue
            try:
                obs = Observation.from_json(data, case.id, item.variant)
            except (TypeError, ValueError, KeyError):
                rejudged.append(Outcome(item.case_id, item.variant, "blocked", "observation_unreadable"))
                continue
            rejudged.append(judge(case, item.variant, obs, config))
        outcomes = tuple(rejudged)
    target = Path(arguments.output) / f"isolation-report-{metadata.get('run_id', 'report')}.json"
    if target.resolve() == Path(arguments.input).resolve():
        print("error: choose an output directory other than the input report's", file=sys.stderr)
        return 2
    try:
        return _write(outcomes, arguments.output, metadata, config or RuntimeConfig(
            {}, None, None, None, {}, frozenset(), None, None))
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


async def _check_collection(config: RuntimeConfig) -> tuple[str, str]:
    if not config.collector_url:
        return "blocked", "collector_not_configured"
    result = await _normal_request(config)
    return result["status"], str(result["reason"])


def _check_env(arguments) -> int:
    from .config import load_config

    try:
        load_cases(arguments.manifest)
        config = load_config(arguments.config)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    checks = []
    for key in ("pages", "http_fixture", "forbidden_receiver"):
        checks.append((f"base:{key}", *(("passed", "configured") if key in config.bases
                                         else ("blocked", "base_not_configured"))))
    token = bool(config.token_env and os.environ.get(config.token_env))
    checks.append(("token", *(("passed", "present") if token else ("blocked", "token_missing"))))
    evidence = config.evidence_dir is not None and config.evidence_dir.is_dir()
    checks.append(("evidence_dir", *(("passed", "present") if evidence else ("blocked", "evidence_dir_missing"))))
    contract = config.backend_contract is not None and config.backend_contract.is_file()
    checks.append(("backend_contract", *(("passed", "present") if contract
                                          else ("blocked", "backend_contract_missing"))))
    try:
        status, reason = asyncio.run(_check_collection(config))
    except KeyboardInterrupt:
        status, reason = "not_run", "interrupted"
    checks.append(("collection", status, reason))
    if reason == "stub_not_collected":
        checks.append(("collection_groups", "blocked", "stub_not_collected"))
    for name, status, reason in checks:
        print(f"{name}\t{status}\t{reason}")
    statuses = {status for _, status, _ in checks}
    return 1 if "failed" in statuses else 0 if statuses == {"passed"} else 2


def _list(arguments) -> int:
    try:
        cases = load_cases(arguments.manifest)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for case in cases:
        print(f"{case.id}\t{case.group}\t{case.execution_kind}\t{case.title}\t{','.join(case.variants)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="isolation-tests")
    commands = parser.add_subparsers(dest="command", required=True)

    list_command = commands.add_parser("list", help="list cases without executing them")
    list_command.add_argument("--manifest", type=Path, required=True)

    check = commands.add_parser("check-env", help="check configuration and one real collection")
    check.add_argument("--manifest", type=Path, default=CANONICAL_MANIFEST)
    check.add_argument("--config", type=Path, required=True)

    run = commands.add_parser("run", help="run selected cases (default: basic cases only)")
    run.add_argument("--manifest", type=Path, default=CANONICAL_MANIFEST)
    run.add_argument("--config", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    selection = run.add_mutually_exclusive_group()
    selection.add_argument("--all", action="store_true",
                           help="explicitly include network, load, host and recovery cases")
    selection.add_argument("--case", action="append", metavar="ID")
    run.add_argument("--group", action="append", metavar="GROUP")
    run.add_argument("--collector-limit", type=int,
                     help="the remote collector's configured active limit (LIM-06 sends limit+1)")
    run.add_argument("--pages-commit", help="deployed Pages commit to record in the report")

    report = commands.add_parser("report", help="re-render (and re-judge with evidence) a JSON report")
    report.add_argument("--manifest", type=Path, default=CANONICAL_MANIFEST)
    report.add_argument("--input", type=Path, required=True)
    report.add_argument("--output", type=Path, required=True)
    report.add_argument("--config", type=Path, help="re-judge stored observations with evidence_dir")

    probe = commands.add_parser(
        "host-probe", help="collect host facts; run by the administrator on the inspected host")
    probe.add_argument("--output", type=Path, required=True)
    probe.add_argument("--boundary", choices=("host", "container"))
    probe.add_argument("--run-id", required=True,
                       help="the batch id printed by `run` for the HOST cases of that run")

    arguments = parser.parse_args(argv)
    if arguments.command == "host-probe":
        return _host_probe(arguments.output, arguments.boundary, arguments.run_id)
    if arguments.command == "list":
        return _list(arguments)
    if arguments.command == "check-env":
        return _check_env(arguments)
    if arguments.command == "run":
        if arguments.all and arguments.group:
            parser.error("--all cannot be combined with --group")
        return _run(arguments)
    return _report(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
