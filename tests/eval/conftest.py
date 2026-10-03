"""Shared offline suite results (run once per session; GW and B0 with the oracle approver)."""

from __future__ import annotations

import time

import pytest
from eval_helpers import mutation_ids

from firewall.eval.loader import ALL_INCLUDES, load_scenarios
from firewall.eval.parallel import run_parallel
from firewall.eval.records import EpisodeResult
from firewall.eval.runner import RunConfig
from firewall.eval.scenario import Scenario


class SuiteRun:
    def __init__(self, scenarios: list[Scenario], episodes: list[EpisodeResult], seconds: float) -> None:
        self.scenarios = {s.id: s for s in scenarios}
        self.episodes = episodes
        self.seconds = seconds

    def get(self, scenario_id: str, defense: str) -> EpisodeResult:
        return next(e for e in self.episodes if e.scenario_id == scenario_id and e.defense == defense)

    def of(self, defense: str, prefix: str | None = None) -> list[EpisodeResult]:
        return [e for e in self.episodes if e.defense == defense
                and (prefix is None or _in(e.scenario_id, prefix))]


def _in(sid: str, prefix: str) -> bool:
    if prefix in ("A", "B"):
        return sid[0] == prefix and sid[1:].isdigit()
    if prefix == "T":
        return sid[0] == "T"
    return sid.startswith(prefix + "-")


@pytest.fixture(scope="session")
def suite_run() -> SuiteRun:
    """Whole offline suite under GW and B0 with 4 worker processes (the acceptance gate's `--workers 4`)."""
    scenarios = load_scenarios()
    jobs = [(sc.id, RunConfig(run_id="pytest", defense=d)) for d in ("GW", "B0") for sc in scenarios]
    jobs += [(mid, RunConfig(run_id="pytest", defense="GW")) for mid in mutation_ids(scenarios)]
    t0 = time.perf_counter()
    eps = run_parallel(jobs, include=ALL_INCLUDES, workers=4)
    return SuiteRun(scenarios, eps, time.perf_counter() - t0)
