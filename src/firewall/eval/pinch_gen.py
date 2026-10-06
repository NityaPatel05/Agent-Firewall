"""PinchBench-like benign workload: template-generated ordinary tasks across all tool families (deterministic)."""

from __future__ import annotations

import random
import re
from functools import lru_cache
from typing import Any

import yaml

from firewall.eval.scenario import ExpectedOutcome, OracleSpec, Scenario
from firewall.llm.scripted import ScriptStep
from firewall.resources import data_path

MIN_CALLS = 600
_WHOLE = re.compile(r"^\{(\w+)\}$")


@lru_cache(maxsize=1)
def load_templates() -> list[dict[str, Any]]:
    return yaml.safe_load(data_path("scenarios", "pinch", "templates.yaml").read_text(encoding="utf-8"))


def _fill(obj: Any, values: dict[str, Any]) -> Any:
    """Substitute `{x}` placeholders recursively; a string that is exactly "{x}" keeps the value's type."""
    if isinstance(obj, str):
        m = _WHOLE.match(obj)
        if m and m.group(1) in values:
            return values[m.group(1)]
        return obj.format_map(values) if "{" in obj else obj
    if isinstance(obj, list):
        return [_fill(v, values) for v in obj]
    if isinstance(obj, dict):
        return {k: _fill(v, values) for k, v in obj.items()}
    return obj


def build_task(tpl: dict[str, Any], values: dict[str, Any], n: int) -> Scenario:
    steps = [ScriptStep.model_validate(_fill(s, values)) for s in tpl["steps"]]
    steps.append(ScriptStep(kind="final", text=_fill(tpl["final"], values)))
    return Scenario(
        id=f"PB-{tpl['id']}-{n}", kind="benign", suite="pinch", category=f"pinch/{tpl['id']}",
        title=f"Pinch-like task {tpl['id']}", user_prompt=_fill(tpl["prompt"], values), script=tuple(steps),
        utility_oracles=(OracleSpec.model_validate(_fill(tpl["utility"], values)),),
        expected=ExpectedOutcome(gate="allow"), tags=("pinch",))


def generate_pinch(*, n_tasks: int = 120, seed: int = 0) -> list[Scenario]:
    """`n_tasks` tasks cycling through the templates; variants drawn with `random.Random(seed)`."""
    templates = load_templates()
    rng = random.Random(seed)
    tasks = [build_task(tpl, rng.choice(tpl["variants"]), n)
             for n, tpl in ((n, templates[n % len(templates)]) for n in range(n_tasks))]
    calls = sum(1 for t in tasks for s in t.script if s.kind == "call")
    if n_tasks >= 120 and calls < MIN_CALLS:
        raise ValueError(f"Pinch workload has only {calls} tool calls (< {MIN_CALLS})")
    return tasks
