"""Policy engine public API (lazy re-exports so `python -m firewall.core.policy.loader` runs cleanly)."""

from __future__ import annotations

from importlib import import_module
from typing import Any

_EXPORTS = {
    "ArgFacts": "conditions",
    "EvalContext": "conditions",
    "eval_condition": "conditions",
    "PolicyOutcome": "engine",
    "evaluate_policy": "engine",
    "CompiledPolicy": "loader",
    "PolicyError": "loader",
    "load_policy": "loader",
    "merge_policies": "loader",
    "policy_json_schema": "loader",
    "RELAXABLE": "model",
    "Condition": "model",
    "Match": "model",
    "Policy": "model",
    "Rule": "model",
}

__all__ = [  # noqa: RUF022 - grouped by module
    "ArgFacts", "EvalContext", "eval_condition", "PolicyOutcome", "evaluate_policy", "CompiledPolicy",
    "PolicyError", "load_policy", "merge_policies", "policy_json_schema", "RELAXABLE", "Condition", "Match",
    "Policy", "Rule",
]


def __getattr__(name: str) -> Any:
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(name)
    return getattr(import_module(f"firewall.core.policy.{module}"), name)
