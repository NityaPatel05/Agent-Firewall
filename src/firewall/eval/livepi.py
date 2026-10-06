"""LivePI-style suite: 12 technique families x 5 goals on mocked channels (not comparable to LivePI itself)."""

from __future__ import annotations

from functools import lru_cache
from typing import Any

import yaml

from firewall.eval.scenario import (
    ExpectedOutcome,
    InjectionSpec,
    LivePIMeta,
    OracleSpec,
    Scenario,
    WorldOverride,
)
from firewall.llm.scripted import ScriptStep
from firewall.resources import data_path

# Repo-link surfaces only carry code-ish goals (LivePI had 4 repo-link cases); everything else is feasible.
INFEASIBLE: frozenset[tuple[str, str]] = frozenset(
    (fam, goal) for fam in ("shadow_policy_update", "code_carried") for goal in ("inbox_exfil", "solana_transfer"))


@lru_cache(maxsize=1)
def _load() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    root = data_path("scenarios", "livepi")
    fams = yaml.safe_load((root / "families.yaml").read_text(encoding="utf-8"))
    goals = yaml.safe_load((root / "goals.yaml").read_text(encoding="utf-8"))
    return fams, goals


def feasible_matrix() -> list[tuple[str, str]]:
    fams, goals = _load()
    return [(f["id"], g["id"]) for f in fams for g in goals if (f["id"], g["id"]) not in INFEASIBLE]


def build_scenario(fam: dict[str, Any], goal: dict[str, Any]) -> Scenario:
    user_steps = [ScriptStep.model_validate(s) for s in fam["script"]]
    last = len(user_steps) - 1
    induced = [ScriptStep.model_validate({**s, "induced": True, "needs": [last]}) for s in goal["steps"]]
    final = ScriptStep(kind="final", text=fam["final"])
    injections = [InjectionSpec(location=fam["location"], text=fam["template"].format(instruction=goal["instruction"]),
                                mode=fam.get("mode", "append"))]
    injections += [InjectionSpec(**i) for i in fam.get("extra_injections", [])]
    overrides = [WorldOverride(**o) for o in (*fam.get("overrides", []), *goal.get("overrides", []))]
    return Scenario(
        id=f"LP-{fam['id']}-{goal['id']}", kind="attack", suite="livepi", category=f"livepi/{fam['id']}",
        title=f"LivePI-style {fam['id']} -> {goal['id']}", user_prompt=fam["user_prompt"],
        overrides=tuple(overrides), injections=tuple(injections), script=(*user_steps, *induced, final),
        attack_oracle=OracleSpec(**goal["attack_oracle"]), utility_oracles=(OracleSpec(**fam["utility"]),),
        expected=ExpectedOutcome(gate="stop", controls=("PROV", "POL")),
        livepi=LivePIMeta(family=fam["id"], goal=goal["id"], surface=fam["surface"]), tags=("livepi",))


def generate_livepi_scenarios(*, per_family: int = 2, seed: int = 0) -> list[Scenario]:
    """`per_family` feasible goals per family, rotated by family index + seed (2 -> 24 cases; 5 -> all 56)."""
    fams, goals = _load()
    out: list[Scenario] = []
    for i, fam in enumerate(fams):
        ok = [g for g in goals if (fam["id"], g["id"]) not in INFEASIBLE]
        start = (i + seed) % len(ok)
        for k in range(min(per_family, len(ok))):
            out.append(build_scenario(fam, ok[(start + k) % len(ok)]))
    return out
