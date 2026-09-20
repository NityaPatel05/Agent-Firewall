"""Pure decision pipeline: `evaluate(EvalInputs) -> Decision` (PLAN §6, steps 0–9). No I/O, no mutation."""

from __future__ import annotations

import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Literal

from firewall.core.canonical import canon_amount
from firewall.core.exec_guard import exec_findings
from firewall.core.labels import Integrity, SourceRef
from firewall.core.models import (
    ORIGIN_RANK,
    TRUSTED_ORIGINS,
    ArgOrigin,
    ArgRole,
    Decision,
    DestinationInfo,
    Finding,
    OriginClass,
    ReviewItem,
    ReviewRequest,
    Stage,
    ToolCall,
    Verdict,
    max_verdict,
)
from firewall.core.policy.conditions import ArgFacts, EvalContext
from firewall.core.policy.engine import evaluate_policy
from firewall.core.policy.loader import CompiledPolicy, _iter_conditions
from firewall.core.provenance import resolve_origin
from firewall.core.registry import ResolveStatus, ToolRegistry, ToolSpec
from firewall.core.rule_of_two import rule_of_two_finding
from firewall.core.schema_validation import SchemaValidator
from firewall.core.session import SessionView
from firewall.core.sinks import classify_destinations, compute_facts, sink_findings
from firewall.core.task_spec import TaskSpec

ABLATIONS = frozenset({"provenance", "roles", "task_spec", "sinks", "schema", "rule_of_two", "registry_pin",
                       "policy"})
_REG_RULES: dict[ResolveStatus, str] = {
    ResolveStatus.UNKNOWN: "SYS-REG-UNKNOWN",
    ResolveStatus.AMBIGUOUS: "SYS-REG-SHADOW",
    ResolveStatus.PIN_MISMATCH: "SYS-REG-PIN",
    ResolveStatus.UNAPPROVED: "SYS-REG-UNAPPROVED",
}
_REG_REASONS: dict[ResolveStatus, str] = {
    ResolveStatus.UNKNOWN: "unknown tool",
    ResolveStatus.AMBIGUOUS: "tool name is exposed by more than one server (possible shadowing); use the "
                             "qualified name",
    ResolveStatus.PIN_MISMATCH: "tool definition changed since it was pinned (possible rug pull); re-approval needed",
    ResolveStatus.UNAPPROVED: "tool or server is not approved",
}
DETECTOR_THRESHOLD = 0.5


@dataclass(frozen=True, slots=True)
class GatewayOptions:
    mode: Literal["enforce", "shadow"] | None = None
    strictness: Literal["standard", "strict"] | None = None
    ablate: frozenset[str] = frozenset()
    detector_escalation: bool | None = None

    def __post_init__(self) -> None:
        unknown = set(self.ablate) - ABLATIONS
        if unknown:
            raise ValueError(f"unknown ablations: {sorted(unknown)}")


@dataclass(frozen=True, slots=True)
class EvalInputs:
    policy: CompiledPolicy
    registry: ToolRegistry
    validator: SchemaValidator
    session: SessionView
    call: ToolCall
    options: GatewayOptions = field(default_factory=GatewayOptions)
    approved_by: str | None = None   # call-level approval from the approver channel (record_approval)


@dataclass(frozen=True, slots=True)
class EvalDetail:
    decision: Decision
    spec: ToolSpec | None
    facts: ArgFacts
    args: Mapping[str, Any]


def _f(rule: str, stage: Stage, verdict: Verdict, reason: str, arg: str | None = None, **ev: Any) -> Finding:
    return Finding.model_construct(rule_id=rule, stage=stage, verdict=verdict, reason=reason, arg=arg, evidence=ev)


# ------------------------------------------------------------------ provenance stage

_BOUND_CACHE: dict[tuple[str, str, str], Decimal | None] = {}


def _policy_bound(policy: CompiledPolicy, spec: ToolSpec, arg: str) -> Decimal | None:
    """Smallest `{arg: <arg>, op: gt|gte, value: X}` bound among the policy rules matching this tool."""
    key = (policy.hash, spec.qualified_name, arg)
    if key in _BOUND_CACHE:
        return _BOUND_CACHE[key]
    bounds: list[Decimal] = []
    for rule in policy.rules_for(spec):
        for cond in _iter_conditions(rule.when):
            if cond.arg == arg and cond.op in ("gt", "gte"):
                b = canon_amount(cond.value)
                if b is not None:
                    bounds.append(b)
    result = min(bounds) if bounds else None
    _BOUND_CACHE[key] = result
    return result


def _describe_origin(name: str, o: ArgOrigin) -> str:
    src = next((m for m in o.matches if m.origin_class == o.origin_class), None)
    where = ""
    if src is not None and src.source is not None:
        where = f" ({src.source.tool or src.source.kind.value} {src.entry_id})"
    if o.origin_class == OriginClass.USER_NAMED_SOURCE:
        return f"{name} came from a source the user named{where}; confirm the exact value once"
    if o.origin_class == OriginClass.UNTRUSTED_ONLY:
        return f"{name} came from untrusted content{where}; ask the user to confirm or provide it"
    return f"{name} does not appear in any trusted source (model-generated or transformed); ask the user to provide it"


def _provenance_findings(spec: ToolSpec, args: Mapping[str, Any], origins: Mapping[str, ArgOrigin],
                         policy: CompiledPolicy, strict: bool, task_spec: TaskSpec | None) -> list[Finding]:
    if not spec.consequential:
        return []
    untrusted_verdict = Verdict.BLOCK if strict else Verdict.REVIEW
    out: list[Finding] = []
    authority_ok = True
    for name, a in spec.args.items():
        o = origins.get(name)
        if a.role != ArgRole.AUTHORITY or o is None or not a.origin_required:
            continue
        cls = o.origin_class
        if cls in TRUSTED_ORIGINS:
            continue
        authority_ok = authority_ok and cls == OriginClass.USER_NAMED_SOURCE
        reason = _describe_origin(name, o)
        ev = {"origin": cls.value}
        if cls == OriginClass.USER_NAMED_SOURCE:
            out.append(_f("SYS-PROV-NAMED", Stage.PROVENANCE, policy.policy.named_effect(spec.side_effect), reason,
                          name, **ev))
        elif cls == OriginClass.UNTRUSTED_ONLY:
            out.append(_f("SYS-PROV-UNTRUSTED", Stage.PROVENANCE, untrusted_verdict, reason, name, **ev))
        else:
            out.append(_f("SYS-PROV-UNKNOWN", Stage.PROVENANCE, untrusted_verdict, reason, name, **ev))
    for name, a in spec.args.items():
        o = origins.get(name)
        if a.role != ArgRole.BOUNDED or o is None or o.origin_class in TRUSTED_ORIGINS:
            continue
        value = canon_amount(args.get(name))
        bound = _policy_bound(policy, spec, name)
        if bound is None and task_spec is not None:
            bound = task_spec.max_amount
        within = value is not None and (bound is None or value <= bound)
        if not (authority_ok and within):
            out.append(_f("SYS-PROV-BOUNDED", Stage.PROVENANCE, Verdict.REVIEW,
                          f"{name} is not from a trusted source and is not within bounds with trusted authority "
                          f"arguments", name, origin=o.origin_class.value,
                          bound=None if bound is None else str(bound)))
    return out


# ------------------------------------------------------------------ helpers

def _detector_flagged(session: SessionView) -> bool:
    for e in session.ledger.entries():
        if e.label.integrity == Integrity.UNTRUSTED:
            for s in e.signals:
                if s.source.startswith("detector") and (s.detail == "flagged" or s.score >= DETECTOR_THRESHOLD):
                    return True
    return False


def _as_list(v: Any) -> list[Any]:
    return list(v) if isinstance(v, (list, tuple)) else [v]


def _review_request(session: SessionView, call: ToolCall, spec: ToolSpec, args: Mapping[str, Any],
                    origins: Mapping[str, ArgOrigin], findings: list[Finding],
                    destinations: tuple[DestinationInfo, ...] = ()) -> ReviewRequest:
    review = [f for f in findings if f.verdict == Verdict.REVIEW]
    global_ids = tuple(dict.fromkeys(f.rule_id for f in review if f.arg is None))
    wanted: dict[str, list[str]] = {}
    for f in review:
        if f.arg is not None:
            wanted.setdefault(f.arg, []).append(f.rule_id)
    if global_ids:
        for name, a in spec.args.items():
            if a.role in (ArgRole.AUTHORITY, ArgRole.BOUNDED) and name in origins:
                wanted.setdefault(name, [])
    items: list[ReviewItem] = []
    for name, ids in wanted.items():
        o = origins.get(name)
        if o is None:
            continue
        chain = _order_chain(o)
        values = _as_list(args.get(name))
        canon = o.value_canonical if isinstance(o.value_canonical, list) else [o.value_canonical]
        for i, v in enumerate(values):
            cls = o.item_classes[i] if o.item_classes and i < len(o.item_classes) else o.origin_class
            items.append(ReviewItem.model_construct(
                arg=name, value=v, value_canonical=canon[i] if i < len(canon) else None, origin_class=cls,
                provenance_chain=chain, rule_ids=tuple(dict.fromkeys((*ids, *global_ids)))))
    if global_ids:   # call-level review: show derived destinations (e.g. the sender a reply goes to)
        for d in destinations:
            if d.arg not in wanted:
                items.append(ReviewItem.model_construct(
                    arg=d.arg, value=d.value, value_canonical=d.value, origin_class=d.origin_class,
                    provenance_chain=(), rule_ids=global_ids))
    all_ids =tuple(dict.fromkeys(f.rule_id for f in review))
    return ReviewRequest.model_construct(session_id=session.session_id, call_id=call.call_id, tool=spec.qualified_name,
                                         args_raw=dict(call.args), items=tuple(items), rule_ids=all_ids)


def _order_chain(o: ArgOrigin) -> tuple[SourceRef, ...]:
    """Distinct sources of the matches, most trusted first (matches are already rank-sorted)."""
    seen: dict[SourceRef, None] = {}
    for m in sorted(o.matches, key=lambda m: -ORIGIN_RANK[m.origin_class]):
        if m.source is not None:
            seen.setdefault(m.source, None)
    return tuple(seen)


def _message(verdict: Verdict, findings: list[Finding]) -> str:
    if verdict == Verdict.ALLOW:
        return ""
    bad = [f for f in findings if f.verdict == verdict]
    ids = ", ".join(dict.fromkeys(f.rule_id for f in bad))
    if verdict == Verdict.BLOCK:
        return f"Blocked by policy [{ids}]: {bad[0].reason}. Do not retry with the same arguments."
    prov = next((f for f in bad if f.stage == Stage.PROVENANCE), None)
    detail = f": {prov.reason}" if prov is not None else ""
    return f"Awaiting user confirmation [{ids}]{detail}"


def _finish(inputs: EvalInputs, spec: ToolSpec | None, findings: list[Finding], args: Mapping[str, Any],
            origins: Mapping[str, ArgOrigin], destinations: tuple[DestinationInfo, ...], facts: ArgFacts,
            t0: int) -> EvalDetail:
    opts, pol, call = inputs.options, inputs.policy.policy, inputs.call
    verdict = max_verdict(*(f.verdict for f in findings))
    mode = opts.mode or pol.mode
    review = None
    if verdict == Verdict.REVIEW and spec is not None:
        review = _review_request(inputs.session, call, spec, args, origins, findings, destinations)
    message = _message(verdict, findings)
    shadow = None
    if mode == "shadow":
        shadow, verdict, message = verdict, Verdict.ALLOW, ""
    eval_us = (time.perf_counter_ns() - t0) / 1000.0
    decision = Decision.model_construct(
        call_id=call.call_id, tool=spec.qualified_name if spec is not None else call.tool, verdict=verdict,
        findings=tuple(findings), arg_origins=dict(origins), destinations=destinations, normalized_args=dict(args),
        review=review, shadow_verdict=shadow, message_to_agent=message, eval_us=eval_us,
        policy_hash=inputs.policy.hash, registry_hash=inputs.registry.registry_hash())
    return EvalDetail(decision=decision, spec=spec, facts=facts, args=args)


# ------------------------------------------------------------------ main entry points

def evaluate_detailed(inputs: EvalInputs) -> EvalDetail:
    t0 = time.perf_counter_ns()
    opts, cp, session, call = inputs.options, inputs.policy, inputs.session, inputs.call
    pol = cp.policy
    ablate = opts.ablate
    strict = (opts.strictness or pol.strictness) == "strict"
    findings: list[Finding] = []
    empty_facts = ArgFacts()

    # 1 registry
    res = inputs.registry.resolve(call.tool, call.server)
    spec = res.spec
    skip_pin = "registry_pin" in ablate and res.status in (ResolveStatus.PIN_MISMATCH, ResolveStatus.UNAPPROVED)
    if res.status != ResolveStatus.OK and not (skip_pin and spec is not None):
        verdict = pol.defaults.unknown_tool if res.status == ResolveStatus.UNKNOWN else Verdict.BLOCK
        findings.append(_f(_REG_RULES[res.status], Stage.REGISTRY, verdict, _REG_REASONS[res.status],
                           candidates=list(res.candidates)))
        return _finish(inputs, None, findings, dict(call.args), {}, (), empty_facts, t0)
    assert spec is not None

    # 0 circuit breaker (needs the spec to know whether the call is consequential)
    if session.circuit_open and spec.consequential:
        findings.append(_f("POL-CB-001", Stage.SESSION, Verdict.BLOCK, "circuit breaker open after repeated blocks"))

    # 2 schema
    if "schema" in ablate:
        args: dict[str, Any] = dict(call.args)
    else:
        vr = inputs.validator.validate_args(spec, call.args)
        findings.extend(vr.findings)
        args = vr.normalized_args

    # 3 task spec (scope/read-only rules are evaluated by the policy engine)
    task_spec = None if "task_spec" in ablate else session.task_spec

    # 4 provenance
    origins: dict[str, ArgOrigin] = {}
    for name, value in args.items():
        a = spec.args.get(name)
        if a is None or a.role in (ArgRole.CONTENT, ArgRole.META) or value in (None, "", [], {}):
            continue
        origins[name] = resolve_origin(session.ledger, arg=name, spec=a, value=value, task_spec=task_spec,
                                       approvals=session.approvals, side_effect=spec.side_effect,
                                       constants=session.constants())
    if "provenance" in ablate:
        origins = {k: o.model_copy(update={"origin_class": OriginClass.USER_TYPED,
                                           "item_classes": tuple(OriginClass.USER_TYPED for _ in o.item_classes)})
                   for k, o in origins.items()}
    elif "roles" in ablate:
        if spec.consequential and session.ledger.ctx_label().integrity == Integrity.UNTRUSTED:
            findings.append(_f("SYS-PROV-CTX", Stage.PROVENANCE, Verdict.REVIEW,
                               "consequential call in a session that ingested untrusted content"))
    else:
        findings.extend(_provenance_findings(spec, args, origins, cp, strict, task_spec))

    # 5 policy (destinations and facts are inputs to the policy conditions)
    destinations = classify_destinations(spec, args, origins, session, cp)
    facts = compute_facts(spec, args, session, cp)
    relax_by: dict[str, str] = {}
    if "policy" not in ablate:
        ctx = EvalContext(call=call, spec=spec, args=args, origins=origins, destinations=destinations, facts=facts,
                          session=session, task_spec=task_spec, policy=cp)
        outcome = evaluate_policy(ctx, strict=strict)
        findings.extend(outcome.findings)
        for f in outcome.findings:
            for r in f.evidence.get("relax", ()):
                relax_by.setdefault(r, f.rule_id)

    # 6 sinks + exec context
    if "sinks" not in ablate:
        findings.extend(sink_findings(spec, args, origins, destinations, facts, session, cp))
        findings.extend(exec_findings(spec, args, origins, cp))

    # 7 Rule-of-Two
    if "rule_of_two" not in ablate:
        r2 = rule_of_two_finding(spec, session.flags, origins, destinations)
        if r2 is not None:
            findings.append(r2)

    # 8 detector escalation (ALLOW -> REVIEW only)
    det = opts.detector_escalation if opts.detector_escalation is not None else pol.detector_escalation
    if det and spec.consequential and _detector_flagged(session):
        findings.append(_f("DET-ESC-001", Stage.DETECTOR, Verdict.REVIEW,
                           "a detector flagged untrusted content in this session"))

    # 9 combine: relaxations, call-level approval
    findings = _apply_relaxations(findings, relax_by)
    if inputs.approved_by is not None:
        findings = [f if f.verdict != Verdict.REVIEW else
                    _f(f.rule_id, f.stage, Verdict.ALLOW, f.reason, f.arg, **{**f.evidence,
                                                                              "approved_by": inputs.approved_by})
                    for f in findings]
    return _finish(inputs, spec, findings, args, origins, destinations, facts, t0)


def _apply_relaxations(findings: Iterable[Finding], relax_by: Mapping[str, str]) -> list[Finding]:
    out: list[Finding] = []
    for f in findings:
        if f.rule_id.startswith("SYS-") and f.rule_id in relax_by and f.verdict != Verdict.ALLOW:
            out.append(_f(f.rule_id, f.stage, Verdict.ALLOW, f.reason, f.arg,
                          **{**f.evidence, "relaxed_by": relax_by[f.rule_id]}))
        else:
            out.append(f)
    return out


def evaluate(inputs: EvalInputs) -> Decision:
    """Pure evaluation of one proposed tool call."""
    return evaluate_detailed(inputs).decision
