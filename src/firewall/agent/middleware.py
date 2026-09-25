"""FirewallMiddleware: enforces Gateway decisions inside a LangChain 1.x `create_agent` graph."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any, Literal, NotRequired

from langchain.agents.middleware.types import (
    AgentMiddleware,
    AgentState,
    ModelRequest,
    ModelResponse,
    ToolCallRequest,
)
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langgraph.runtime import Runtime
from langgraph.types import Command, interrupt

from firewall.agent.hygiene import SPOTLIGHT_SYSTEM_NOTE, spotlight
from firewall.core.approvals import Approver
from firewall.core.gateway import GatewayProtocol
from firewall.core.models import ApprovalResult, Decision, ToolCall, Verdict
from firewall.core.registry import ToolSpec

DECLINED = "Not executed: the user declined this action."


class FirewallState(AgentState):
    fw_session_id: NotRequired[str]


def _fw_artifact(d: Decision, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"verdict": d.verdict.value, "rule_ids": list(d.rule_ids), "call_id": d.call_id, **(extra or {})}


class FirewallMiddleware(AgentMiddleware[FirewallState]):
    """First middleware in the stack: records trusted turns, gates every tool call, labels every output."""

    state_schema = FirewallState

    def __init__(
        self,
        gateway: GatewayProtocol,
        *,
        approver: Approver | Literal["interrupt"],
        session_id: str | None = None,
        enforce: bool = True,
        sanitize_final: bool = True,
        spotlight: Literal["off", "delimit", "datamark"] = "off",
        on_decision: Callable[[Decision], None] | None = None,
        system_prompt: str | None = None,
        definitions: Callable[[], Sequence[ToolSpec]] | None = None,
        user_handle: str = "@emma",
    ) -> None:
        super().__init__()
        self.gateway = gateway
        self.approver = approver
        self.session_id = session_id
        self.enforce = enforce
        self.sanitize_final = sanitize_final
        self.spotlight_mode = spotlight
        self.on_decision = on_decision
        self.system_prompt = system_prompt
        self.definitions = definitions
        self.user_handle = user_handle
        self._known_sessions: set[str] = set()
        self._recorded: set[str] = set()

    # ------------------------------------------------------------------ hooks
    def before_agent(self, state: FirewallState, runtime: Runtime) -> dict[str, Any] | None:
        sid = state.get("fw_session_id") or self.session_id
        if sid is None or sid not in self._known_sessions:
            try:
                sid = self.gateway.new_session(sid, user_handle=self.user_handle)
            except ValueError:  # session already exists on the gateway (e.g. resumed thread)
                assert sid is not None
            self._known_sessions.add(sid)
            if self.system_prompt:
                self.gateway.record_system_message(sid, self.system_prompt)
            if self.definitions is not None:
                self.gateway.observe_tool_definitions(sid, list(self.definitions()))
        for m in state["messages"]:
            if isinstance(m, HumanMessage):
                key = f"{sid}:{m.id or id(m)}"
                if key not in self._recorded:
                    self._recorded.add(key)
                    self.gateway.record_user_message(sid, str(m.content), message_id=m.id)
        self.session_id = sid
        return {"fw_session_id": sid}

    def wrap_model_call(self, request: ModelRequest, handler: Callable[[ModelRequest], ModelResponse]) -> Any:
        if self.spotlight_mode == "off":
            return handler(request)
        msgs = []
        for m in request.messages:
            fw = m.artifact.get("fw") if isinstance(m, ToolMessage) and isinstance(m.artifact, dict) else None
            if fw and fw.get("label", {}).get("integrity") == 0:
                m = m.model_copy(update={"content": spotlight(str(m.content), mode=self.spotlight_mode)})
            msgs.append(m)
        base = request.system_message.content if request.system_message is not None else ""
        system = SystemMessage(content=f"{base}\n\n{SPOTLIGHT_SYSTEM_NOTE}".strip())
        return handler(request.override(messages=msgs, system_message=system))

    def wrap_tool_call(self, request: ToolCallRequest,
                       handler: Callable[[ToolCallRequest], ToolMessage | Command]) -> ToolMessage | Command:
        tc = request.tool_call
        sid = (request.state or {}).get("fw_session_id") or self.session_id
        if sid is None:
            raise RuntimeError("FirewallMiddleware: no gateway session (before_agent did not run)")
        step = len((request.state or {}).get("messages", []))
        call = ToolCall(call_id=tc["id"], tool=tc["name"], args=dict(tc.get("args") or {}), step=step)
        if self.definitions is not None and "__" in call.tool:
            self.gateway.observe_tool_definitions(sid, list(self.definitions()))
        # Everything up to interrupt() is idempotent: on resume this node re-runs from the top.
        d = self.gateway.evaluate(sid, call)
        if self.on_decision:
            self.on_decision(d)
        if d.verdict == Verdict.REVIEW and d.review is not None:
            if self.approver == "interrupt":
                resume = interrupt({"type": "fw_review", "review": d.review.model_dump(mode="json")})
                result = ApprovalResult(**(resume or {}), approver="human")
            else:
                result = self.approver.decide(d.review)
            d = self.gateway.record_approval(sid, d, result)
            if self.on_decision:
                self.on_decision(d)
            if result.approved and result.edited_args:
                call = call.model_copy(update={"args": {**call.args, **result.edited_args}})
                request = request.override(tool_call={**tc, "args": call.args})
        if d.verdict == Verdict.ALLOW or not self.enforce:
            if self.enforce and d.normalized_args and d.normalized_args != call.args:
                request = request.override(tool_call={**request.tool_call, "args": dict(d.normalized_args)})
            msg = handler(request)
            if not isinstance(msg, ToolMessage):
                return msg
            raw = msg.artifact if msg.artifact is not None else msg.content
            lo = self.gateway.label_output(sid, call, raw)
            self.gateway.commit(sid, call, d, executed=True)
            fw = _fw_artifact(d, {"label": lo.label.model_dump(mode="json"), "entry_ids": list(lo.entry_ids)})
            return ToolMessage(content=lo.content, tool_call_id=call.call_id, name=call.tool, status=msg.status,
                               artifact={"raw": raw, "fw": fw})
        self.gateway.commit(sid, call, d, executed=False)
        text = d.message_to_agent if d.verdict == Verdict.BLOCK else (d.message_to_agent or DECLINED)
        return ToolMessage(content=text or DECLINED, tool_call_id=call.call_id, name=call.tool, status="error",
                           artifact={"fw": _fw_artifact(d)})

    def after_model(self, state: FirewallState, runtime: Runtime) -> dict[str, Any] | None:
        if not self.sanitize_final or not self.enforce:   # shadow mode measures, never alters
            return None
        msgs = state["messages"]
        last = msgs[-1] if msgs else None
        if not isinstance(last, AIMessage) or last.tool_calls:
            return None
        sid = state.get("fw_session_id") or self.session_id
        if sid is None:
            return None
        out = self.gateway.sanitize_final_answer(sid, last.text)
        if not out.changed:
            return None
        return {"messages": [AIMessage(content=out.text, id=last.id)]}
