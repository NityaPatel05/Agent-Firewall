"""System tools: clock, agent configuration, host firewall."""

from __future__ import annotations

from typing import Any

from firewall.agent.tools._base import impl
from firewall.agent.world import MockWorld


@impl("system")
def get_current_time(world: MockWorld) -> dict[str, Any]:
    return {"now": world.now}


@impl("system")
def get_agent_config(world: MockWorld) -> dict[str, str]:
    return dict(world.agent_config)


@impl("system")
def update_agent_config(world: MockWorld, key: str, value: str) -> dict[str, Any]:
    world.agent_config[key] = value
    return {"status": "updated", "key": key}


@impl("system")
def update_firewall_settings(world: MockWorld, enabled: bool) -> dict[str, Any]:
    world.shell.firewall_enabled = bool(enabled)
    return {"status": "updated", "enabled": bool(enabled)}
