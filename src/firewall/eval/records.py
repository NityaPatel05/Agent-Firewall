"""Episode results, run manifests and JSONL persistence (resumable)."""

from __future__ import annotations

import json
import threading
from pathlib import Path

from pydantic import BaseModel, Field

from firewall.core.models import Verdict
from firewall.settings import get_settings


class DecisionLite(BaseModel):
    call_id: str
    tool: str
    verdict: Verdict
    shadow_verdict: Verdict | None = None
    rule_ids: list[str] = Field(default_factory=list)
    origins: dict[str, str] = Field(default_factory=dict)
    eval_us: float = 0.0
    induced: bool | None = None


class EpisodeResult(BaseModel):
    run_id: str
    scenario_id: str
    kind: str
    suite: str
    category: str
    defense: str
    mode: str
    model: str
    approver: str
    seed: int
    attack_success: bool | None
    # AgentDojo only: the benchmark's own security verdict, which for some tasks counts *proposed* calls
    attack_success_native: bool | None = None
    utility: bool
    intermediate: bool | None
    error: str | None = None
    n_tool_calls: int = 0
    n_consequential: int = 0
    n_allow: int = 0
    n_review: int = 0
    n_block: int = 0
    n_review_approved: int = 0
    n_omitted: int = 0
    decisions: list[DecisionLite] = Field(default_factory=list)
    wall_ms: float = 0.0
    llm_calls: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    twin: str | None = None
    tags: list[str] = Field(default_factory=list)
    livepi_family: str | None = None
    livepi_goal: str | None = None
    final_answer: str = ""


class RunManifest(BaseModel):
    run_id: str
    created: str
    git_sha: str | None = None
    policy_hash: str = ""
    registry_hash: str = ""
    argv: list[str] = Field(default_factory=list)
    versions: dict[str, str] = Field(default_factory=dict)
    defenses: list[str] = Field(default_factory=list)
    mode: str = "offline"
    models: dict[str, str] = Field(default_factory=dict)
    seed: int = 0
    notes: str = ""


_LOCK = threading.Lock()


def run_dir(run_id: str) -> Path:
    return get_settings().runs_dir / run_id


def write_manifest(path: Path, manifest: RunManifest) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")


def append_episode(path: Path, ep: EpisodeResult) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = ep.model_dump_json()
    with _LOCK, path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def read_episodes(path: Path) -> list[EpisodeResult]:
    if not path.exists():
        return []
    return [EpisodeResult.model_validate(json.loads(line))
            for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def done_keys(path: Path) -> set[tuple[str, str, str, int]]:
    """(scenario, defense, approver, seed) already recorded (for --resume)."""
    return {(e.scenario_id, e.defense, e.approver, e.seed) for e in read_episodes(path)}
