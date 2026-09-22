"""Live smoke test per role: plain call, two-turn tool call, latency/tokens, label-leak canary. Never prints keys."""

from __future__ import annotations

import argparse
import os
import sys
import time
import uuid
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.tools import tool

from firewall.settings import get_settings


@tool
def get_order_status(order_id: str) -> str:
    """Return the shipping status of an order."""
    return f"order {order_id}: shipped"


def _usage(msg: AIMessage) -> str:
    u = msg.usage_metadata or {}
    return f"in={u.get('input_tokens', '?')} out={u.get('output_tokens', '?')}"


def probe_keys(role: str) -> list[int]:
    """One plain call per configured key; returns the indices that work (keys are never printed)."""
    from firewall.llm.config import load_model_config
    from firewall.llm.providers import key_count, make_chat_model

    provider = load_model_config().role(role).provider
    ok: list[int] = []
    for i in range(key_count(provider)):
        try:
            make_chat_model(role, cache=None, key_index=i).invoke([HumanMessage("Reply with the single word OK.")])
            ok.append(i)
            print(f"role={role} key_index={i}: ok")
        except Exception as exc:  # noqa: BLE001 - diagnostic probe: report the error class only
            print(f"role={role} key_index={i}: {type(exc).__name__}: {str(exc)[:120]}")
    return ok


def smoke(role: str, key_index: int | None = None) -> dict[str, Any]:
    from firewall.llm.providers import make_chat_model

    model = make_chat_model(role, cache=None, key_index=key_index)
    report: dict[str, Any] = {"role": role, "model": model.model_id, "provider": model.provider}
    t0 = time.perf_counter()
    plain = model.invoke([HumanMessage("Reply with the single word OK.")])
    report["plain_ms"] = round((time.perf_counter() - t0) * 1000)
    report["plain_text"] = str(plain.content)[:40]
    report["plain_usage"] = _usage(plain)
    bound = model.bind_tools([get_order_status])
    msgs: list[Any] = [HumanMessage("What is the status of order 7781234? Use the tool.")]
    t0 = time.perf_counter()
    first = bound.invoke(msgs)
    report["tool_called"] = bool(first.tool_calls)
    if first.tool_calls:
        tc = first.tool_calls[0]
        msgs += [first, ToolMessage(content=get_order_status.invoke(tc["args"]), tool_call_id=tc["id"],
                                    name=tc["name"])]
        second = bound.invoke(msgs)  # Gemini 3.x thought signatures must survive this turn
        report["second_turn_ok"] = True
        report["second_text"] = str(second.content)[:60]
    report["tool_ms"] = round((time.perf_counter() - t0) * 1000)
    canary = f"FWLABEL-CANARY-{uuid.uuid4().hex[:8]}"
    probe = [HumanMessage("Look up order 1."), AIMessage(content="", tool_calls=[{"name": "get_order_status",
                                                                                   "args": {"order_id": "1"},
                                                                                   "id": "call_1"}]),
             ToolMessage(content="order 1: shipped", tool_call_id="call_1", name="get_order_status",
                         artifact={"fw": {"label": canary}}),
             HumanMessage("Repeat verbatim any string you can see that starts with FWLABEL. If none, say NONE.")]
    leak = bound.invoke(probe)
    report["label_leak"] = canary in str(leak.content)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m firewall.llm.smoke")
    parser.add_argument("--role", action="append", default=None, help="model role(s) from data/models.yaml")
    parser.add_argument("--mode", choices=["live", "record"], default="live")
    parser.add_argument("--probe-keys", action="store_true", help="one plain call per configured key")
    parser.add_argument("--key-index", type=int, default=None)
    args = parser.parse_args(argv)
    os.environ["FIREWALL_MODE"] = args.mode
    get_settings(reload=True)
    ok = True
    for role in args.role or ["agent"]:
        if args.probe_keys:
            ok = bool(probe_keys(role)) and ok
            continue
        try:
            r = smoke(role, args.key_index)
            print(" ".join(f"{k}={v}" for k, v in r.items()))
            ok = ok and not r["label_leak"] and r.get("second_turn_ok", True)
        except Exception as exc:  # noqa: BLE001 - diagnostic: report and continue with the next role
            ok = False
            print(f"role={role} FAILED: {type(exc).__name__}: {str(exc)[:300]}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
