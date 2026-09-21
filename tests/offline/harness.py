"""Offline corpus harness: YAML fixtures -> session -> call -> expectations (C-a1 … C-a4)."""

from __future__ import annotations

import functools
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from firewall.core.gateway import Gateway
from firewall.core.labels import Confidentiality, Integrity, Label, SourceKind, SourceRef, join_all
from firewall.core.models import (
    ArgOrigin,
    ArgRole,
    ArgType,
    DestinationInfo,
    OriginClass,
    SideEffect,
    Stage,
    ToolCall,
    Verdict,
)
from firewall.core.pipeline import GatewayOptions
from firewall.core.policy.conditions import ArgFacts, EvalContext
from firewall.core.policy.loader import CompiledPolicy, compile_policy, load_policy
from firewall.core.provenance import compute_output_labels, resolve_origin
from firewall.core.registry import ResolveStatus, ToolRegistry, ToolSpec
from firewall.core.session import SessionState
from firewall.core.task_spec import RuleBasedTaskSpecExtractor, TaskSpec

FIXTURE_ROOT = Path(__file__).parent / "fixtures"
MILESTONES = ("M2", "M3", "M4", "M5", "M6")
DEFAULT_OWN_EMAILS = ("emma.johnson@bluesparrowtech.com", "emma.j.personal@gmail.com")
DEFAULT_OWN_IBANS = ("DE89370400440532013000",)


class SessionSetup(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user_handle: str = "@emma"
    own_emails: list[str] = Field(default_factory=lambda: list(DEFAULT_OWN_EMAILS))
    own_ibans: list[str] = Field(default_factory=lambda: list(DEFAULT_OWN_IBANS))
    flags: dict[str, bool] = Field(default_factory=dict)
    counters: dict[str, Any] = Field(default_factory=dict)
    circuit_open: bool = False


class GivenFacts(BaseModel):
    model_config = ConfigDict(extra="forbid")
    secret_in_args: bool = False
    canary_in_args: bool = False
    content_confidentiality: Literal["public", "private", "secret"] = "public"
    private_bytes: int = 0
    detector_flagged: bool = False


class GivenDestination(BaseModel):
    model_config = ConfigDict(extra="forbid")
    arg: str
    kind: ArgType
    value: str
    internal: bool = False
    own: bool = False
    allowlisted: bool = False
    host: str | None = None
    origin_class: OriginClass


class Given(BaseModel):
    """M3 policy fixtures: provenance/sink results supplied directly instead of computed."""

    model_config = ConfigDict(extra="forbid")
    origins: dict[str, OriginClass] = Field(default_factory=dict)
    destinations: list[GivenDestination] = Field(default_factory=list)
    facts: GivenFacts = Field(default_factory=GivenFacts)
    ctx_untrusted: bool = False


class Expect(BaseModel):
    model_config = ConfigDict(extra="forbid")
    origins: dict[str, OriginClass] | None = None
    verdict: Verdict | None = None
    policy_verdict: Verdict | None = None
    rule_ids_include: list[str] = Field(default_factory=list)
    rule_ids_exclude: list[str] = Field(default_factory=list)
    findings_stage: list[Stage] = Field(default_factory=list)
    relaxed: list[str] = Field(default_factory=list)
    schema_ok: bool | None = None
    normalized_args: dict[str, Any] | None = None
    sink_rule_ids: list[str] | None = None          # M5: exact set of SYS-SINK-*/SYS-EXEC-*/SYS-R2-* ids
    destinations: dict[str, dict[str, Any]] | None = None  # M5: value -> expected DestinationInfo fields
    facts: dict[str, Any] | None = None              # M5: expected ArgFacts fields
    signals: list[str] | None = None                 # M5 decoders: expected signal kinds
    decoded: list[str] | None = None                 # M5 decoders: substrings expected in decoded texts
    sanitized: str | None = None                     # M5 markdown: expected sanitized final answer


class Fixture(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    description: str
    since: Literal["M2", "M3", "M4", "M5", "M6"] = "M6"
    policy: str = "all"
    strictness: Literal["standard", "strict"] | None = None
    task_spec: TaskSpec | None = None
    session: SessionSetup = Field(default_factory=SessionSetup)
    events: list[dict[str, Any]] = Field(default_factory=list)
    call: ToolCall | None = None
    text: str | None = None                          # decoder / markdown fixtures: input text
    given: Given | None = None
    expect: Expect
    source_file: str = ""


def load_fixtures(kind: str) -> list[Fixture]:
    """Load every fixture under fixtures/<kind>/*.yaml (each file holds a list of fixtures); cached per kind."""
    return list(_load_fixtures_cached(kind))


@functools.lru_cache(maxsize=16)
def _load_fixtures_cached(kind: str) -> tuple[Fixture, ...]:
    out: list[Fixture] = []
    for path in sorted((FIXTURE_ROOT / kind).glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        items = data if isinstance(data, list) else [data]
        for item in items:
            item = dict(item)
            item["source_file"] = path.name
            out.append(Fixture.model_validate(item))
    ids = [f.id for f in out]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"duplicate fixture ids in {kind}: {sorted(dupes)}")
    return tuple(out)


def milestone_reached(since: str, current: str) -> bool:
    return MILESTONES.index(since) <= MILESTONES.index(current)


def resolve_spec(registry: ToolRegistry, tool: str, server: str | None = None) -> ToolSpec:
    res = registry.resolve(tool, server)
    if res.spec is None or res.status not in (ResolveStatus.OK,):
        raise KeyError(f"fixture tool {tool!r} does not resolve cleanly: {res.status}")
    return res.spec


def _approval_label() -> Label:
    return Label(integrity=Integrity.TRUSTED, confidentiality=Confidentiality.PRIVATE,
                 sources=frozenset({SourceRef(kind=SourceKind.APPROVAL)}))


def apply_event(session: SessionState, registry: ToolRegistry, event: dict[str, Any], fx: Fixture) -> None:
    """Apply one fixture event directly to the session (M2–M5 harness)."""
    (kind, body), = event.items()
    ledger = session.ledger
    if kind == "user":
        ledger.append(kind=SourceKind.USER, text=body, label=Label.user())
        if session.task_spec is None:
            session.task_spec = RuleBasedTaskSpecExtractor().extract(body, task_id=fx.id)
    elif kind == "system":
        ledger.append(kind=SourceKind.SYSTEM, text=body, label=Label.system())
    elif kind == "tool_output":
        spec = resolve_spec(registry, body["tool"], body.get("server"))
        call = ToolCall(call_id=body.get("call_id", f"c{len(ledger) + 1}"), tool=spec.qualified_name,
                        args=body.get("args", {}))
        frags = compute_output_labels(spec, call, body["output"], user_handle=session.user_handle)
        entries = ledger.extend_fragments(frags, kind=SourceKind.TOOL_OUTPUT, call_id=call.call_id,
                                          tool=spec.qualified_name)
        for e in entries:
            if not e.label.trusted:
                session.flags.ingested_untrusted = True
            if e.label.confidentiality >= Confidentiality.PRIVATE:
                session.flags.read_private = True
            if e.label.confidentiality >= Confidentiality.SECRET:
                session.flags.read_secret = True
    elif kind == "tool_description":
        label = Label.tool(trusted=False, conf=Confidentiality.PUBLIC, tool=body["tool"], call_id=None,
                           server=body.get("server"), kind=SourceKind.TOOL_DESCRIPTION)
        ledger.append(kind=SourceKind.TOOL_DESCRIPTION, text=body["text"], label=label, tool=body["tool"])
        session.flags.ingested_untrusted = True
    elif kind == "approval":
        se, at, value = SideEffect(body["side_effect"]), ArgType(body["arg_type"]), str(body["value"])
        session.approvals.add(se, at, value)
        ledger.append(kind=SourceKind.APPROVAL, text=value, label=_approval_label())
    elif kind == "summary":
        covered = [ledger.get(eid).label for eid in body.get("covers", [])]
        ledger.append(kind=SourceKind.SUMMARY, text=body["text"], label=join_all(covered) if covered
                      else Label.system())
    elif kind == "write":
        pass  # resource labels are applied by the Gateway from M6 on
    else:
        raise ValueError(f"unknown fixture event: {kind}")


def build_session(fx: Fixture, registry: ToolRegistry) -> SessionState:
    """Build a session by applying events directly (M2–M5)."""
    s = fx.session
    session = SessionState(session_id=fx.id, user_handle=s.user_handle, own_emails=s.own_emails,
                           own_ibans=s.own_ibans, task_spec=fx.task_spec)
    for event in fx.events:
        apply_event(session, registry, event, fx)
    for k, v in s.flags.items():
        setattr(session.flags, k, v)
    for k, v in s.counters.items():
        setattr(session.counters, k, v)
    session.circuit_open = s.circuit_open
    return session


def compute_origins(fx: Fixture, session: SessionState, spec: ToolSpec) -> dict[str, ArgOrigin]:
    assert fx.call is not None
    view = session.view()
    return {
        name: resolve_origin(view.ledger, arg=name, spec=spec.args[name], value=value, task_spec=view.task_spec,
                             approvals=view.approvals, side_effect=spec.side_effect, constants=view.constants())
        for name, value in fx.call.args.items()
        if name in spec.args
    }


def given_destinations(fx: Fixture) -> tuple[DestinationInfo, ...]:
    if fx.given is None:
        return ()
    return tuple(DestinationInfo(**d.model_dump()) for d in fx.given.destinations)


def build_gateway_session(fx: Fixture, registry: ToolRegistry | None = None) -> tuple[Gateway, str]:
    """M6+: apply fixture events through the public Gateway API."""
    reg = registry or ToolRegistry.from_yaml()
    pol = fixture_policy(fx, reg)
    options = GatewayOptions(strictness=fx.strictness) if fx.strictness else GatewayOptions()
    gw = Gateway(policy=pol, registry=reg, options=options)
    s = fx.session
    sid = gw.new_session(fx.id, user_handle=s.user_handle, own_emails=s.own_emails, own_ibans=s.own_ibans)
    if fx.task_spec is not None:
        gw.set_task_spec(sid, fx.task_spec)
    for i, event in enumerate(fx.events):
        (kind, body), = event.items()
        if kind == "user":
            gw.record_user_message(sid, body)
        elif kind == "system":
            gw.record_system_message(sid, body)
        elif kind == "tool_output":
            spec = resolve_spec(reg, body["tool"], body.get("server"))
            call = ToolCall(call_id=body.get("call_id", f"ev{i}"), tool=spec.qualified_name, args=body.get("args", {}))
            gw.label_output(sid, call, body["output"])
        elif kind == "tool_description":
            gw.record_tool_description(sid, body["tool"], body.get("server"), body["text"])
        elif kind == "approval":
            gw.pin_approval(sid, SideEffect(body["side_effect"]), ArgType(body["arg_type"]), body["value"])
        elif kind == "summary":
            gw.record_summary(sid, body["text"], body.get("covers", []))
        elif kind == "write":
            call = ToolCall(call_id=f"ev{i}", tool=body["tool"], args=body.get("args", {}))
            gw.commit(sid, call, gw.evaluate(sid, call), executed=True)
        else:
            raise ValueError(f"unknown fixture event: {kind}")
    state = gw.session_state(sid)
    for k, v in s.flags.items():
        setattr(state.flags, k, v)
    for k, v in s.counters.items():
        setattr(state.counters, k, v)
    state.circuit_open = s.circuit_open
    return gw, sid


_POLICY_CACHE: dict[tuple[str, str | None], CompiledPolicy] = {}


def fixture_policy(fx: Fixture, registry: ToolRegistry) -> CompiledPolicy:
    key = (fx.policy, fx.strictness)
    cp = _POLICY_CACHE.get(key)
    if cp is None:
        cp = load_policy(fx.policy, registry=registry)
        if fx.strictness is not None and fx.strictness != cp.policy.strictness:
            cp = compile_policy(cp.policy.model_copy(update={"strictness": fx.strictness}))
        _POLICY_CACHE[key] = cp
    return cp


def build_policy_context(fx: Fixture, registry: ToolRegistry) -> EvalContext:
    """M3 policy fixtures: computed origins overridden by `given`, plus given destinations and facts."""
    assert fx.call is not None
    spec = resolve_spec(registry, fx.call.tool, fx.call.server)
    session = build_session(fx, registry)
    given = fx.given or Given()
    if given.ctx_untrusted:
        session.ledger.append(kind=SourceKind.TOOL_OUTPUT, text="(untrusted content)",
                              label=Label(integrity=Integrity.UNTRUSTED, confidentiality=Confidentiality.PUBLIC))
        session.flags.ingested_untrusted = True
    origins = compute_origins(fx, session, spec)
    for arg, cls in given.origins.items():
        base = origins.get(arg)
        arg_spec = spec.args.get(arg)
        origins[arg] = ArgOrigin(
            arg=arg,
            role=arg_spec.role if arg_spec else ArgRole.AUTHORITY,
            arg_type=arg_spec.value_type if arg_spec else ArgType.TEXT,
            value_canonical=base.value_canonical if base else None,
            origin_class=cls,
            label=base.label if base else Label.user(),
        )
    f = given.facts
    facts = ArgFacts(secret_in_args=f.secret_in_args, canary_in_args=f.canary_in_args,
                     content_confidentiality=Confidentiality[f.content_confidentiality.upper()],
                     private_bytes=f.private_bytes, detector_flagged=f.detector_flagged)
    view = session.view()
    return EvalContext(call=fx.call, spec=spec, args=fx.call.args, origins=origins,
                       destinations=given_destinations(fx), facts=facts, session=view, task_spec=view.task_spec,
                       policy=fixture_policy(fx, registry))
