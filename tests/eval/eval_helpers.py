"""Mutation selection shared by the eval conftest and test_mutations."""

from __future__ import annotations

from firewall.eval.mutations import SPLIT_MUTATORS, TEXT_MUTATORS, VALUE_MUTATORS
from firewall.eval.scenario import Scenario

TEXT_OPS = [*TEXT_MUTATORS, *SPLIT_MUTATORS]
VALUE_OPS = list(VALUE_MUTATORS)


def mutation_ops(idx: int) -> tuple[list[str], str]:
    """Rotating pair of text/split mutators + one value mutator for the idx-th A scenario (all ops covered)."""
    return [TEXT_OPS[idx % len(TEXT_OPS)], TEXT_OPS[(idx + 5) % len(TEXT_OPS)]], VALUE_OPS[idx % len(VALUE_OPS)]


def mutation_ids(scenarios: list[Scenario]) -> list[str]:
    attacks = [s for s in scenarios if s.id[0] == "A" and s.id[1:].isdigit()]
    out = []
    for i, sc in enumerate(attacks):
        text_ops, value_op = mutation_ops(i)
        out += [f"{sc.id}~{op}" for op in (*text_ops, value_op)]
    return out
