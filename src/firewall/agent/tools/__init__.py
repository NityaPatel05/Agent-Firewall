"""Mock tools as LangChain StructuredTools built from the tool registry (schemas = registry ArgSpecs)."""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from functools import lru_cache
from typing import Any

from langchain_core.tools import BaseTool, StructuredTool
from pydantic import BaseModel, Field, create_model

from firewall.agent.tools import (  # noqa: F401 - imported for their @impl registrations
    banking,
    calendar,
    contacts,
    email,
    exec,
    files,
    mcp,
    memory,
    slack,
    system,
    travel,
    wallet,
    web,
)
from firewall.agent.tools._base import IMPLS, ToolError
from firewall.agent.tools.mcp import call_mcp
from firewall.agent.world import MockWorld
from firewall.core.models import ArgType
from firewall.core.registry import ArgSpec, ToolRegistry, ToolSpec


@lru_cache(maxsize=1)
def default_registry() -> ToolRegistry:
    return ToolRegistry.from_yaml()


def _families() -> dict[str, tuple[str, ...]]:
    fams: dict[str, list[str]] = {}
    for name, (family, _) in IMPLS.items():
        fams.setdefault(family, []).append(name)
    for spec in default_registry().specs():
        if spec.server != "local":
            fams.setdefault("mcp", []).append(spec.qualified_name)
    return {k: tuple(sorted(v)) for k, v in sorted(fams.items())}


TOOL_FAMILIES: dict[str, tuple[str, ...]] = _families()

_PY: dict[ArgType, Any] = {
    ArgType.INT: int,
    ArgType.BOOL: bool,
    ArgType.AMOUNT: float | str,
    ArgType.DICT: dict[str, Any],
    ArgType.COMMAND: list[str],
}


def _py_type(a: ArgSpec) -> Any:
    if a.type == ArgType.LIST:
        return list[_PY.get(a.items or ArgType.TEXT, str)]  # type: ignore[misc]
    return _PY.get(a.type, str)


_ARGS_MODELS: dict[str, type[BaseModel]] = {}


def args_model(spec: ToolSpec) -> type[BaseModel]:
    """Pydantic args schema for the provider, derived from the registry ArgSpecs (cached per definition)."""
    key = f"{spec.qualified_name}#{spec.definition_hash()}"
    cached = _ARGS_MODELS.get(key)
    if cached is None:
        cached = _ARGS_MODELS[key] = _build_args_model(spec)
    return cached


def _build_args_model(spec: ToolSpec) -> type[BaseModel]:
    fields: dict[str, Any] = {}
    for name, a in spec.args.items():
        t = _py_type(a)
        if a.enum:
            desc = f"{a.description} One of: {', '.join(a.enum)}".strip()
        else:
            desc = a.description or f"{a.type.value} ({a.role.value})"
        if a.required:
            fields[name] = (t, Field(..., description=desc))
        else:
            fields[name] = (t | None, Field(None, description=desc))
    return create_model(f"{spec.qualified_name}_args", **fields)


def render_output(raw: Any) -> str:
    """Compact JSON (sorted keys) for structured outputs; strings pass through."""
    return raw if isinstance(raw, str) else json.dumps(raw, sort_keys=True, ensure_ascii=False, default=str)


def make_tool(world: MockWorld, spec: ToolSpec, fn: Callable[[dict[str, Any]], Any]) -> StructuredTool:
    name = spec.qualified_name

    def run(**kwargs: Any) -> tuple[str, Any]:
        args = {k: v for k, v in kwargs.items() if v is not None}
        try:
            raw, ok, note = fn(args), True, ""
        except ToolError as exc:
            raw, ok, note = {"error": str(exc)}, False, str(exc)
        world.record(name, args, ok=ok, note=note)
        return render_output(raw), raw

    return StructuredTool.from_function(func=run, name=name, description=spec.description or name,
                                        args_schema=args_model(spec), response_format="content_and_artifact")


def build_tools(world: MockWorld, families: Sequence[str] | None = None,
                registry: ToolRegistry | None = None) -> list[BaseTool]:
    """All mock tools (or only the given families) bound to `world`."""
    reg = registry or default_registry()
    wanted = set(families) if families is not None else set(TOOL_FAMILIES)
    tools: list[BaseTool] = []
    for name, (family, impl) in sorted(IMPLS.items()):
        if family not in wanted:
            continue
        spec = reg.get(name)
        if spec is None:
            raise KeyError(f"tool {name} has an implementation but no registry entry")
        tools.append(make_tool(world, spec, lambda args, _impl=impl: _impl(world, **args)))
    if "mcp" in wanted:
        for server in sorted(world.mcp):
            for tdef in world.mcp[server].tools:
                spec = reg.get(f"{server}__{tdef.name}")
                if spec is None:
                    continue
                tools.append(make_tool(world, spec,
                                       lambda args, _s=server, _t=tdef.name: call_mcp(world, _s, _t, args)))
    return tools


__all__ = ["TOOL_FAMILIES", "args_model", "build_tools", "default_registry", "make_tool", "render_output"]
