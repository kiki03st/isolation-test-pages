"""Shared contracts for cases, configuration, observations, and results."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal


Status = Literal["passed", "failed", "not_run", "blocked"]
Kind = Literal["page", "http_fixture", "host_probe", "integration"]


@dataclass(frozen=True)
class CaseSpec:
    id: str
    group: str
    title: str
    description: str
    execution_kind: Kind
    target_key: str | None
    relative_path: str | None
    variants: tuple[str, ...]
    required_capabilities: tuple[str, ...]
    message: str
    expected_observations: dict[str, Any]
    expected_analysis: dict[str, Any]
    required_evidence: tuple[str, ...]
    risk_level: Literal["basic", "explicit"]
    max_requests: int
    recovery_case: str | None


@dataclass(frozen=True)
class RuntimeConfig:
    bases: dict[str, str]
    collector_url: str | None
    token_env: str | None
    ca_file: Path | None
    limits: dict[str, int | float]
    capabilities: frozenset[str]
    evidence_dir: Path | None
    backend_contract: Path | None
    allow_loopback_http: bool = False


@dataclass(frozen=True)
class CollectedPage:
    input_url: str
    final_url: str | None
    redirect_chain: tuple[str, ...]
    status_code: int | None
    content_type: str | None
    html: str
    title: str | None
    elapsed_ms: int
    failures: tuple[str, ...]


@dataclass(frozen=True)
class Evidence:
    run_id: str
    case_id: str
    started_at: str
    ended_at: str
    facts: dict[str, Any] = field(default_factory=dict)
    references: tuple[str, ...] = ()


@dataclass(frozen=True)
class Outcome:
    case_id: str
    variant: str
    status: Status
    reason: str
    details: dict[str, Any] = field(default_factory=dict)
