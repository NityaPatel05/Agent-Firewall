"""Shared plumbing for mock tools: implementation registry, errors, JSON-safe values."""

from __future__ import annotations

from collections.abc import Callable
from decimal import Decimal
from typing import Any

from firewall.agent.world import MockWorld

Impl = Callable[..., Any]
IMPLS: dict[str, tuple[str, Impl]] = {}


class ToolError(Exception):
    """Domain error: the tool returns {"error": message} instead of raising."""


def impl(family: str, name: str | None = None) -> Callable[[Impl], Impl]:
    """Register `fn(world, **args)` as the implementation of tool `name` (default: function name)."""

    def deco(fn: Impl) -> Impl:
        IMPLS[name or fn.__name__] = (family, fn)
        return fn

    return deco


def num(v: Decimal | float) -> float | int:
    """JSON-friendly number."""
    if isinstance(v, Decimal):
        return int(v) if v == v.to_integral_value() else float(v)
    return v


def dec(v: Any) -> Decimal:
    try:
        return Decimal(str(v).replace(",", "").replace("$", "").replace("€", "").strip())
    except Exception as exc:
        raise ToolError(f"invalid amount: {v!r}") from exc


def next_id(prefix: str, existing: list[str]) -> str:
    n = 1
    while f"{prefix}{n}" in existing:
        n += 1
    return f"{prefix}{n}"


def require(cond: bool, message: str) -> None:
    if not cond:
        raise ToolError(message)


__all__ = ["IMPLS", "MockWorld", "ToolError", "dec", "impl", "next_id", "num", "require"]
