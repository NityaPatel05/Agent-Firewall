"""Process-parallel offline episodes (LangGraph's per-step thread pools are GIL-bound, so threads do not scale).

Each worker loads the scenarios once and runs a chunk of (scenario id, RunConfig) jobs. HF-detector defenses
should not use this (each process would load its own model); the CLI keeps them on threads.
"""

from __future__ import annotations

from collections.abc import Sequence
from concurrent.futures import ProcessPoolExecutor
from typing import Any

from firewall.eval.records import EpisodeResult
from firewall.eval.runner import RunConfig

_SCENARIOS: dict[str, Any] = {}


def _init(include: tuple[str, ...], seed: int, audit_dir: str | None) -> None:
    from firewall.eval.loader import load_scenarios

    _SCENARIOS.update({s.id: s for s in load_scenarios(include=include, seed=seed)})  # type: ignore[arg-type]
    if audit_dir is not None:
        import os
        from pathlib import Path

        from firewall.core.audit import JsonlAuditSink

        _SCENARIOS["__audit__"] = JsonlAuditSink(Path(audit_dir) / f"audit-{os.getpid()}.jsonl", background=False)


def _scenario(sid: str) -> Any:
    """`A07` or a mutated variant `A07~<op>` (see firewall.eval.mutations)."""
    if "~" in sid:
        from firewall.eval.mutations import mutate_scenario

        base, op = sid.split("~", 1)
        return mutate_scenario(_SCENARIOS[base], op)
    return _SCENARIOS[sid]


def _run_chunk(jobs: list[tuple[str, dict[str, Any]]]) -> list[EpisodeResult]:
    from firewall.eval.runner import run_scenario

    audit = _SCENARIOS.get("__audit__")
    out = [run_scenario(_scenario(sid), RunConfig(**cfg), audit=audit) for sid, cfg in jobs]
    if audit is not None:
        audit.flush()
    return out


def run_parallel(jobs: Sequence[tuple[str, RunConfig]], *, include: Sequence[str], seed: int = 0, workers: int = 4,
                 audit_dir: str | None = None) -> list[EpisodeResult]:
    """Run offline jobs in `workers` processes; results keep the input order."""
    payload = [(sid, cfg.model_dump()) for sid, cfg in jobs]
    n = max(1, workers)
    size = max(1, -(-len(payload) // (n * 4)))   # ~4 chunks per worker for load balancing
    chunks = [payload[i:i + size] for i in range(0, len(payload), size)]
    with ProcessPoolExecutor(max_workers=n, initializer=_init, initargs=(tuple(include), seed, audit_dir)) as pool:
        return [ep for part in pool.map(_run_chunk, chunks) for ep in part]
