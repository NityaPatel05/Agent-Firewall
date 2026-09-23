"""Agent memory tools."""

from __future__ import annotations

from typing import Any

from firewall.agent.tools._base import ToolError, impl
from firewall.agent.world import MockWorld


@impl("memory")
def save_memory(world: MockWorld, key: str, value: str) -> dict[str, Any]:
    world.memory[key] = value
    return {"status": "saved", "key": key}


@impl("memory")
def recall_memory(world: MockWorld, key: str) -> str:
    if key not in world.memory:
        raise ToolError(f"no memory under {key!r}")
    return world.memory[key]


@impl("memory")
def list_memory(world: MockWorld) -> list[str]:
    return sorted(world.memory)
