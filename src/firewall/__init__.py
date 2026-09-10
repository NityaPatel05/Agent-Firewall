"""Agent Firewall: provenance-aware tool-call gateway against indirect prompt injection."""

from __future__ import annotations

from typing import Any

__version__ = "0.1.0"

__all__ = ["Gateway", "ToolRegistry", "__version__", "load_policy"]


def __getattr__(name: str) -> Any:
    """Lazy re-exports keep `import firewall` cheap."""
    if name == "Gateway":
        from firewall.core.gateway import Gateway

        return Gateway
    if name == "load_policy":
        from firewall.core.policy.loader import load_policy

        return load_policy
    if name == "ToolRegistry":
        from firewall.core.registry import ToolRegistry

        return ToolRegistry
    raise AttributeError(name)
