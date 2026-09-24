"""Helpers for agent tests: scripted agents against a real Gateway."""

from __future__ import annotations

from typing import Any

from langchain_core.messages import HumanMessage

from firewall.agent.graph import build_agent
from firewall.agent.world import MockWorld
from firewall.core.approvals import AutoDenyApprover
from firewall.core.gateway import Gateway
from firewall.core.models import Decision
from firewall.core.policy.loader import load_policy
from firewall.core.registry import ToolRegistry
from firewall.llm.scripted import ScriptedChatModel, ScriptStep

REG = ToolRegistry.from_yaml()
POLICY = load_policy("all", registry=REG)


def make_gateway(fresh_registry: bool = False) -> Gateway:
    """Shared registry by default; pass `fresh_registry=True` if the test mutates it (rug pulls)."""
    return Gateway(policy=POLICY, registry=ToolRegistry.from_yaml() if fresh_registry else REG)


def run(prompt: str, steps: list[ScriptStep], *, world: MockWorld | None = None, approver: Any = None,
        thread: str = "t1", fresh_registry: bool = False,
        **kw: Any) -> tuple[dict[str, Any], MockWorld, Gateway, list[Decision], Any, Any]:
    world = world or MockWorld.load()
    gw = make_gateway(fresh_registry)
    decisions: list[Decision] = []
    model = ScriptedChatModel(steps=steps)
    graph = build_agent(model=model, world=world, gateway=gw,
                        approver=approver if approver is not None else AutoDenyApprover(),
                        on_decision=decisions.append, session_id=thread, **kw)
    config = {"configurable": {"thread_id": thread}}
    state = graph.invoke({"messages": [HumanMessage(prompt)]}, config)
    return state, world, gw, decisions, graph, model


def call(tool: str, **args: Any) -> ScriptStep:
    return ScriptStep(tool=tool, args=args)


def final(text: str = "Done.") -> ScriptStep:
    return ScriptStep(kind="final", text=text)
