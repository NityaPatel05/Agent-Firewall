"""Run one agent episode (offline with a scripted model) and print the firewall decision trail."""

from __future__ import annotations

import argparse
import os
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml
from langchain.agents.middleware.types import AgentMiddleware, ToolCallRequest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
from langgraph.errors import GraphRecursionError
from langgraph.types import Command
from pydantic import BaseModel, ConfigDict, Field

from firewall.agent.demos import DEMOS
from firewall.agent.graph import build_agent
from firewall.agent.world import MockWorld
from firewall.core.approvals import Approver, AutoDenyApprover, OracleApprover
from firewall.core.gateway import Gateway
from firewall.core.models import Decision, ToolCall
from firewall.llm.scripted import ScriptedChatModel, ScriptStep


class ToolCallLimitExceeded(RuntimeError):
    pass


class ToolCallCap(AgentMiddleware):
    """Stops runaway episodes after `max_calls` tool calls."""

    def __init__(self, max_calls: int) -> None:
        super().__init__()
        self.max_calls = max_calls
        self.count = 0

    def wrap_tool_call(self, request: ToolCallRequest, handler: Callable[[ToolCallRequest], Any]) -> Any:
        self.count += 1
        if self.count > self.max_calls:
            raise ToolCallLimitExceeded(f"more than {self.max_calls} tool calls")
        return handler(request)


class EpisodeConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    episode_id: str
    user_prompt: str
    world: MockWorld
    model: BaseChatModel
    gateway: Any = None  # GatewayProtocol | None (Protocol is not usable as a pydantic type)
    approver: Any = Field(default_factory=AutoDenyApprover)  # Approver | "interrupt"
    families: list[str] | None = None
    extra_middleware: list[Any] = Field(default_factory=list)
    outer_middleware: list[Any] = Field(default_factory=list)   # baseline defenses (wrap the firewall)
    enforce: bool = True
    spotlight: str = "off"
    recursion_limit: int = 60
    max_tool_calls: int = 25
    system_prompt: str | None = None   # None -> DEFAULT_SYSTEM_PROMPT
    interrupt_handler: Callable[[dict[str, Any]], dict[str, Any]] | None = None


class EpisodeTrace(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    episode_id: str
    messages: list[BaseMessage]
    final_answer: str
    decisions: list[Decision]
    world_after: MockWorld
    wall_ms: float
    llm_calls: int
    tokens_in: int
    tokens_out: int
    error: str | None = None
    proposed_calls: list[ToolCall] = Field(default_factory=list)


def run_episode(cfg: EpisodeConfig) -> EpisodeTrace:
    """Invoke the agent once (resuming interrupts through `interrupt_handler`)."""
    decisions: list[Decision] = []
    cap = ToolCallCap(cfg.max_tool_calls)
    graph = build_agent(model=cfg.model, world=cfg.world, gateway=cfg.gateway, approver=cfg.approver,
                        families=cfg.families, extra_middleware=[cap, *cfg.extra_middleware],
                        outer_middleware=cfg.outer_middleware, enforce=cfg.enforce,
                        spotlight=cfg.spotlight, session_id=cfg.episode_id,  # type: ignore[arg-type]
                        on_decision=decisions.append,
                        **({"system_prompt": cfg.system_prompt} if cfg.system_prompt else {}))
    # max_concurrency=1: parallel tool calls from one model turn run in order (MockWorld is not thread-safe and
    # order-dependent state such as new ids must be reproducible for the response cache / replay).
    config: dict[str, Any] = {"configurable": {"thread_id": cfg.episode_id}, "recursion_limit": cfg.recursion_limit,
                              "max_concurrency": 1}
    t0 = time.perf_counter()
    error: str | None = None
    state: dict[str, Any] = {"messages": []}
    try:
        state = graph.invoke({"messages": [HumanMessage(cfg.user_prompt)]}, config)
        while state.get("__interrupt__"):
            if cfg.interrupt_handler is None:
                error = "interrupted"
                break
            payload = state["__interrupt__"][0].value
            state = graph.invoke(Command(resume=cfg.interrupt_handler(payload)), config)
    except GraphRecursionError:
        error = "recursion"
    except ToolCallLimitExceeded:
        error = "tool_call_limit"
    if error in ("recursion", "tool_call_limit"):
        state = graph.get_state(config).values or state
    messages: list[BaseMessage] = list(state.get("messages", []))
    ais = [m for m in messages if isinstance(m, AIMessage)]
    final = next((m.text for m in reversed(ais) if not m.tool_calls), "")
    proposed = [ToolCall(call_id=tc["id"], tool=tc["name"], args=dict(tc["args"])) for m in ais
                for tc in m.tool_calls]
    usage = [m.usage_metadata or {} for m in ais]
    return EpisodeTrace(
        episode_id=cfg.episode_id, messages=messages, final_answer=final, decisions=decisions,
        world_after=cfg.world, wall_ms=(time.perf_counter() - t0) * 1000.0, llm_calls=len(ais),
        tokens_in=sum(int(u.get("input_tokens", 0)) for u in usage),
        tokens_out=sum(int(u.get("output_tokens", 0)) for u in usage), error=error, proposed_calls=proposed)


def console_handler(payload: dict[str, Any]) -> dict[str, Any]:
    """Interactive REVIEW card: raw values, origin class, provenance chain, rule IDs (no agent-written text)."""
    review = payload.get("review", {})
    print(f"\nREVIEW required for {review.get('tool')} [{', '.join(review.get('rule_ids', []))}]")
    for item in review.get("items", []):
        chain = " <- ".join(f"{s.get('kind')}:{s.get('tool') or ''}{(' ' + s['ref']) if s.get('ref') else ''}"
                            for s in item.get("provenance_chain", []))
        print(f"  {item['arg']} = {item['value']!r}  origin={item['origin_class']}  via {chain or '-'}")
    answer = input("Approve? [y/N] ").strip().lower()
    return {"approved": answer in ("y", "yes")}


def print_decisions(decisions: list[Decision]) -> None:
    rows = [(d.tool, d.verdict.value, ", ".join(d.rule_ids) or "-",
             ", ".join(f"{k}={o.origin_class.value}" for k, o in d.arg_origins.items()) or "-", f"{d.eval_us:.0f}")
            for d in decisions]
    try:
        from rich.console import Console
        from rich.table import Table

        table = Table(title="Firewall decisions")
        for col in ("tool", "verdict", "rule IDs", "origins", "eval µs"):
            table.add_column(col)
        for r in rows:
            table.add_row(*r)
        Console().print(table)
    except ImportError:  # pragma: no cover
        for r in rows:
            print(" | ".join(r))


def _approver(name: str, legit: dict[str, list[str]]) -> Approver | str:
    if name == "oracle":
        return OracleApprover(legit)
    if name == "console":
        return "interrupt"
    return AutoDenyApprover()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m firewall.agent.run")
    parser.add_argument("--demo", choices=sorted(DEMOS), help="run a built-in offline demo")
    parser.add_argument("--prompt", help="user prompt (with --script)")
    parser.add_argument("--script", type=Path, help="YAML list of ScriptStep dicts for the scripted model")
    parser.add_argument("--policy", default="all")
    parser.add_argument("--approver", choices=["autodeny", "oracle", "console"], default="autodeny")
    parser.add_argument("--offline", action="store_true", help="force FIREWALL_MODE=offline (scripted model)")
    parser.add_argument("--no-firewall", action="store_true", help="undefended baseline (B0)")
    args = parser.parse_args(argv)
    if args.offline:
        os.environ["FIREWALL_MODE"] = "offline"
    if args.demo:
        demo = DEMOS[args.demo]
        prompt, world, steps, legit = demo.prompt, demo.world(), list(demo.script), demo.legit
    elif args.prompt and args.script:
        prompt, world = args.prompt, MockWorld.load()
        steps = [ScriptStep.model_validate(s) for s in yaml.safe_load(args.script.read_text(encoding="utf-8"))]
        legit = {}
    else:
        parser.error("use --demo NAME or --prompt TEXT --script FILE")
    gateway = None if args.no_firewall else Gateway.from_config(policy=args.policy)
    approver = _approver(args.approver, legit)
    cfg = EpisodeConfig(episode_id=args.demo or "cli", user_prompt=prompt, world=world,
                        model=ScriptedChatModel(steps=steps), gateway=gateway, approver=approver,
                        interrupt_handler=console_handler if approver == "interrupt" else None)
    trace = run_episode(cfg)
    print(f"prompt: {prompt}")
    print_decisions(trace.decisions)
    print(f"final answer: {trace.final_answer}")
    executed = [r for r in trace.world_after.log if r.ok]
    print(f"executed tool calls: {[r.tool for r in executed]}")
    if trace.error:
        print(f"episode error: {trace.error}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
