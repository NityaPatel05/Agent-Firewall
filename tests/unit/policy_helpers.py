"""Helpers to build policy EvalContexts in unit tests."""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from firewall.core.labels import Confidentiality, Integrity, Label, SourceKind
from firewall.core.models import ArgOrigin, ArgType, DestinationInfo, OriginClass, ToolCall
from firewall.core.policy.conditions import ArgFacts, EvalContext
from firewall.core.policy.loader import CompiledPolicy, load_policy
from firewall.core.registry import ToolRegistry
from firewall.core.session import SessionState
from firewall.core.task_spec import TaskSpec

REG = ToolRegistry.from_yaml()


@lru_cache(maxsize=8)
def policy(name: str = "all") -> CompiledPolicy:
    return load_policy(name, registry=REG)


def origin(arg: str, cls: OriginClass, arg_type: ArgType = ArgType.TEXT) -> ArgOrigin:
    from firewall.core.models import ArgRole

    return ArgOrigin(arg=arg, role=ArgRole.AUTHORITY, arg_type=arg_type, value_canonical=None, origin_class=cls,
                     label=Label.user())


def dest(value: str, cls: OriginClass, *, internal: bool = False, own: bool = False, kind: ArgType = ArgType.EMAIL,
         arg: str = "to", allowlisted: bool = False) -> DestinationInfo:
    return DestinationInfo(arg=arg, kind=kind, value=value, internal=internal, own=own, allowlisted=allowlisted,
                           origin_class=cls)


def ctx(
    tool: str,
    args: dict[str, Any] | None = None,
    *,
    origins: dict[str, OriginClass] | None = None,
    destinations: list[DestinationInfo] | None = None,
    facts: ArgFacts | None = None,
    session: SessionState | None = None,
    task_spec: TaskSpec | None = None,
    pol: CompiledPolicy | None = None,
    untrusted_ctx: bool = False,
) -> EvalContext:
    res = REG.resolve(tool)
    assert res.spec is not None, tool
    spec = res.spec
    args = args or {}
    s = session or SessionState("t")
    if untrusted_ctx:
        s.ledger.append(kind=SourceKind.TOOL_OUTPUT, text="untrusted",
                        label=Label(integrity=Integrity.UNTRUSTED, confidentiality=Confidentiality.PUBLIC))
    if task_spec is not None:
        s.task_spec = task_spec
    view = s.view()
    return EvalContext(
        call=ToolCall(call_id="c1", tool=spec.qualified_name, args=args),
        spec=spec,
        args=args,
        origins={k: origin(k, v) for k, v in (origins or {}).items()},
        destinations=tuple(destinations or ()),
        facts=facts or ArgFacts(),
        session=view,
        task_spec=view.task_spec,
        policy=pol or policy(),
    )
