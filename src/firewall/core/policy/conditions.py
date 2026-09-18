"""Condition evaluation over an `EvalContext` (pure, deterministic)."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from firewall.core.canonical import canon_amount, canon_host, normalize_text, url_parts
from firewall.core.labels import Confidentiality, Integrity
from firewall.core.models import ArgOrigin, DestinationInfo, ToolCall
from firewall.core.policy.model import Condition, SessionCond
from firewall.core.registry import ToolSpec
from firewall.core.session import SessionView
from firewall.core.task_spec import TaskSpec

if TYPE_CHECKING:
    from firewall.core.policy.loader import CompiledPolicy

_CONF = {"private": Confidentiality.PRIVATE, "secret": Confidentiality.SECRET}
_MISSING = object()
_ARG_PATH_RE = re.compile(r"([^.\[\]]+)|\[(\d+)\]")


@dataclass(frozen=True, slots=True)
class ArgFacts:
    secret_in_args: bool = False
    canary_in_args: bool = False
    content_confidentiality: Confidentiality = Confidentiality.PUBLIC
    private_bytes: int = 0
    detector_flagged: bool = False


@dataclass(frozen=True, slots=True)
class EvalContext:
    call: ToolCall
    spec: ToolSpec
    args: Mapping[str, Any]
    origins: Mapping[str, ArgOrigin]
    destinations: tuple[DestinationInfo, ...]
    facts: ArgFacts
    session: SessionView
    task_spec: TaskSpec | None
    policy: CompiledPolicy


def get_arg(args: Mapping[str, Any], path: str) -> Any:
    """Look up `name`, `name[0]` or `name.key`; returns _MISSING if absent."""
    cur: Any = args
    for name, idx in _ARG_PATH_RE.findall(path):
        if name:
            if not isinstance(cur, Mapping) or name not in cur:
                return _MISSING
            cur = cur[name]
        else:
            i = int(idx)
            if not isinstance(cur, (list, tuple)) or i >= len(cur):
                return _MISSING
            cur = cur[i]
    return cur


def _is_empty(v: Any) -> bool:
    return v is None or v is _MISSING or v == "" or v == [] or v == {} or v == ()


def _resolve_value(value: Any, ctx: EvalContext) -> Any:
    if isinstance(value, str) and value.startswith("@allowlists."):
        return sorted(ctx.policy.allowlist(value.removeprefix("@allowlists.")))
    return value


def _as_list(v: Any) -> list[Any]:
    return list(v) if isinstance(v, (list, tuple, set, frozenset)) else [v]


def _text(v: Any) -> str:
    return normalize_text(v if isinstance(v, str) else str(v)).casefold()


def _host_of(v: Any) -> str | None:
    if not isinstance(v, str):
        return None
    if "://" in v:
        p = url_parts(v)
        return p.host if p else None
    if "@" in v:
        return canon_host(v.rsplit("@", 1)[1])
    return canon_host(v)


def _host_in(v: Any, hosts: list[Any]) -> bool:
    h = _host_of(v)
    if h is None:
        return False
    for allowed in hosts:
        a = str(allowed).lower().strip(".")
        if h == a or h.endswith("." + a):
            return True
    return False


def _num(v: Any) -> Decimal | None:
    return canon_amount(v)


def _cmp(op: str, a: Any, b: Any) -> bool:
    x, y = _num(a), _num(b)
    if x is None or y is None:
        return False
    return {"gt": x > y, "gte": x >= y, "lt": x < y, "lte": x <= y}[op]


def _eq(a: Any, b: Any) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b or _text(a) == _text(b)
    x, y = _num(a), _num(b)
    if x is not None and y is not None and not (isinstance(a, str) and isinstance(b, str)):
        return x == y
    return _text(a) == _text(b)


def _element_op(op: str, element: Any, value: Any, ctx: EvalContext) -> bool:
    match op:
        case "eq":
            return _eq(element, value)
        case "ne":
            return not _eq(element, value)
        case "in":
            return any(_eq(element, v) for v in _as_list(value))
        case "not_in":
            return not any(_eq(element, v) for v in _as_list(value))
        case "gt" | "gte" | "lt" | "lte":
            return _cmp(op, element, value)
        case "regex":
            return any(ctx.policy.regex(str(p)).search(str(element)) is not None for p in _as_list(value))
        case "glob":
            return any(ctx.policy.glob(str(p)).match(_text(element)) is not None for p in _as_list(value))
        case "host_in" | "domain_in":
            return _host_in(element, _as_list(value))
        case "contains":
            return _text(value) in _text(element)
    raise ValueError(f"unknown op {op}")


def _eval_arg(cond: Condition, ctx: EvalContext) -> bool:
    assert cond.arg is not None and cond.op is not None
    actual = get_arg(ctx.args, cond.arg)
    if actual is _MISSING or actual is None:
        return False
    value = _resolve_value(cond.value, ctx)
    if cond.op == "len_gt":
        try:
            return len(actual) > int(value)
        except TypeError:
            return False
    if cond.op == "contains" and isinstance(actual, (list, tuple)):
        return any(_eq(e, value) for e in actual)
    # List-valued arguments: the condition holds if ANY element satisfies it (conservative for restrictions).
    return any(_element_op(cond.op, e, value, ctx) for e in _as_list(actual))


def _eval_session(sc: SessionCond, ctx: EvalContext) -> bool:
    c = ctx.session.counters
    f = ctx.session.flags
    if sc.blocks_gte is not None and c.blocks < sc.blocks_gte:
        return False
    if sc.calls_of_tool_gte is not None:
        tc = sc.calls_of_tool_gte
        if c.calls_by_tool.get(tc.tool, 0) < tc.n:
            return False
    if sc.calls_to_same_dest_gte is not None:
        tool = ctx.spec.qualified_name
        if not any(c.calls_by_dest.get(f"{tool}|{d.value}", 0) >= sc.calls_to_same_dest_gte
                   for d in ctx.destinations):
            return False
    if sc.transfer_total_gt is not None and not c.transfer_total > Decimal(str(sc.transfer_total_gt)):
        return False
    if sc.ingested_untrusted is not None and f.ingested_untrusted != sc.ingested_untrusted:
        return False
    return sc.read_private is None or f.read_private == sc.read_private


def _dest_class(d: DestinationInfo, kind: str) -> bool:
    if kind == "own":
        return d.own
    if kind == "internal":
        return d.internal or d.own
    return not (d.internal or d.own)


def _origin_of(ctx: EvalContext, arg: str) -> Any:
    origin = ctx.origins.get(arg)
    return None if origin is None else origin.origin_class


_HEAD_EVAL: dict[str, Callable[[Condition, EvalContext], bool]] = {
    "all": lambda c, x: all(eval_condition(s, x) for s in c.all or ()),
    "any": lambda c, x: any(eval_condition(s, x) for s in c.any or ()),
    "not_": lambda c, x: not eval_condition(c.not_, x),  # type: ignore[arg-type]
    "arg": _eval_arg,
    "arg_present": lambda c, x: not _is_empty(get_arg(x.args, c.arg_present or "")),
    "arg_origin": lambda c, x: (
        (o := _origin_of(x, c.arg_origin or "")) is not None
        and ((o in c.in_) if c.in_ is not None else (o not in (c.not_in or ())))
    ),
    "session": lambda c, x: _eval_session(c.session, x),  # type: ignore[arg-type]
    "task_read_only": lambda c, x: x.task_spec is not None and x.task_spec.read_only == c.task_read_only,
    "task_allows_tool": lambda c, x: (x.task_spec is None or x.task_spec.allows_tool(x.spec)) == c.task_allows_tool,
    "destination": lambda c, x: any(_dest_class(d, c.destination or "") for d in x.destinations),
    "dest_origin_in": lambda c, x: any(d.origin_class in (c.dest_origin_in or ()) for d in x.destinations),
    "dest_origin_not_in": lambda c, x: any(d.origin_class not in (c.dest_origin_not_in or ())
                                           for d in x.destinations),
    "secret_in_args": lambda c, x: x.facts.secret_in_args == c.secret_in_args,
    "canary_in_args": lambda c, x: x.facts.canary_in_args == c.canary_in_args,
    "content_confidentiality_gte": lambda c, x: x.facts.content_confidentiality >= _CONF[
        c.content_confidentiality_gte or "private"],
    "private_bytes_out_gt": lambda c, x: (
        x.session.counters.private_bytes_out + x.facts.private_bytes > (c.private_bytes_out_gt or 0)
    ),
    "ctx_untrusted": lambda c, x: (x.session.ledger.ctx_label().integrity == Integrity.UNTRUSTED) == c.ctx_untrusted,
    "detector_flagged": lambda c, x: x.facts.detector_flagged == c.detector_flagged,
}


def eval_condition(cond: Condition, ctx: EvalContext) -> bool:
    """Evaluate one condition (exactly one head key) against the context."""
    return _HEAD_EVAL[cond.head](cond, ctx)
