"""Our tool registry / policy for the pinned AgentDojo suites (Appendix G) and oracle legit values."""

from __future__ import annotations

from collections.abc import Sequence
from functools import lru_cache
from typing import Any

from firewall.core.models import ArgRole
from firewall.core.policy.loader import CompiledPolicy, load_policy
from firewall.core.registry import ToolRegistry
from firewall.resources import data_path

SUITES = ("banking", "slack", "travel", "workspace")


def load_agentdojo_registry(suite: str) -> ToolRegistry:
    return ToolRegistry.from_yaml([data_path("registry", f"agentdojo_{suite}.yaml")])


@lru_cache(maxsize=8)
def agentdojo_policy(suite: str) -> CompiledPolicy:
    return load_policy(data_path("policies", "agentdojo", f"ad_{suite}.yaml"), registry=load_agentdojo_registry(suite))


def coverage(suite: str) -> tuple[list[str], list[str]]:
    """(suite tools missing from the registry, registry tools missing from the suite)."""
    from firewall.eval.agentdojo.compat import get_suite

    tools = {f.name for f in get_suite(suite).tools}
    have = {s.name for s in load_agentdojo_registry(suite).specs()}
    return sorted(tools - have), sorted(have - tools)


def _flat(v: Any) -> list[str]:
    if isinstance(v, (list, tuple)):
        return [s for x in v for s in _flat(x)]
    if isinstance(v, dict):
        return [s for x in v.values() for s in _flat(x)]
    return [] if v is None else [str(v)]


def legit_values_from_ground_truth(calls: Sequence[Any], registry: ToolRegistry) -> dict[str, tuple[str, ...]]:
    """"tool.arg" -> values of AUTHORITY / BOUNDED / SELECTOR args in the user task's ground-truth calls; derived
    destinations of call-level reviews use the same key (see core.pipeline review items)."""
    out: dict[str, list[str]] = {}
    for c in calls:
        spec = registry.get(c.function)
        if spec is None:
            continue
        out.setdefault(f"call:{c.function}", []).append("1")   # the user wanted this tool called at all
        for name, a in spec.args.items():
            if name in c.args and a.role in (ArgRole.AUTHORITY, ArgRole.BOUNDED, ArgRole.SELECTOR):
                out.setdefault(f"{c.function}.{name}", []).extend(_flat(c.args[name]))
    return {k: tuple(dict.fromkeys(v)) for k, v in out.items()}
