"""Policy engine: evaluate all matching rules; defaults by side effect when nothing matched."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from firewall.core.models import Finding, Stage, Verdict
from firewall.core.policy.conditions import EvalContext, eval_condition
from firewall.core.policy.model import STRICT_UPGRADE


class PolicyOutcome(BaseModel):
    model_config = ConfigDict(frozen=True)
    findings: tuple[Finding, ...]
    relaxed: frozenset[str]
    matched_rule_ids: tuple[str, ...]


def evaluate_policy(ctx: EvalContext, *, strict: bool | None = None) -> PolicyOutcome:
    """Emit one finding per matching rule (effect as verdict); collect `relax` sets from allow rules.

    `strict` overrides the policy's strictness (GatewayOptions.strictness).
    """
    policy = ctx.policy.policy
    if strict is None:
        strict = policy.strictness == "strict"
    findings: list[Finding] = []
    relaxed: set[str] = set()
    matched: list[str] = []
    for rule in ctx.policy.rules_for(ctx.spec):
        if rule.when is not None and not eval_condition(rule.when, ctx):
            continue
        matched.append(rule.id)
        effect = rule.effect
        if strict and effect == Verdict.REVIEW and rule.id in STRICT_UPGRADE:
            effect = Verdict.BLOCK
        evidence: dict[str, object] = {"fallback": rule.fallback}
        if rule.relax:
            relaxed.update(rule.relax)
            evidence["relax"] = list(rule.relax)
        findings.append(Finding.model_construct(rule_id=rule.id, arg=None, stage=Stage.POLICY, verdict=effect,
                                reason=rule.message or rule.description, evidence=evidence))
    if not matched:
        se = ctx.spec.side_effect
        findings.append(Finding.model_construct(arg=None, evidence={}, rule_id=f"DEFAULT-{se.value.upper().replace('_', '-')}", stage=Stage.POLICY,
                                verdict=policy.defaults.verdict_for(se), reason="default for side effect"))
    return PolicyOutcome(findings=tuple(findings), relaxed=frozenset(relaxed), matched_rule_ids=tuple(matched))
