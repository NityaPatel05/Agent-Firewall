"""GatewayToolsExecutor: AgentDojo tool execution through our gateway (one instance per episode)."""

from __future__ import annotations

from ast import literal_eval
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, FunctionsRuntime

from firewall.core.approvals import Approver, AutoDenyApprover
from firewall.core.gateway import Gateway
from firewall.core.models import Decision, ToolCall, Verdict
from firewall.eval.agentdojo.compat import jsonable, make_tool_result_message

MAX_TOOL_CALLS = 25


def _fix_list_args(args: Mapping[str, Any]) -> dict[str, Any]:
    """Same coercion as AgentDojo's ToolsExecutor: list-looking strings become lists."""
    out = dict(args)
    for k, v in out.items():
        if isinstance(v, str) and v.startswith("["):
            try:
                parsed = literal_eval(v)
            except (ValueError, SyntaxError):
                continue
            if isinstance(parsed, list):
                out[k] = parsed
    return out


class GatewayToolsExecutor(BasePipelineElement):
    """Evaluates every pending tool call; ALLOW (or approved REVIEW) runs it, BLOCK/denied returns a policy text.

    Arguments are executed as the model wrote them (normalized values are only used for the decision), so
    AgentDojo's own utility/security checks see the agent's real calls.
    """

    def __init__(self, *, gateway: Gateway, approver: Approver | None = None, enforce: bool = True,
                 system_message: str = "", output_formatter: Callable[[Any], str] = tool_result_to_str) -> None:
        self.gateway = gateway
        self.approver = approver or AutoDenyApprover()
        self.enforce = enforce
        self.system_message = system_message
        self.output_formatter = output_formatter
        self.session_id: str | None = None
        self.decisions: list[Decision] = []
        self.n_calls = 0

    def _session(self, query: str) -> str:
        if self.session_id is None:
            self.session_id = self.gateway.new_session()
            if self.system_message:
                self.gateway.record_system_message(self.session_id, self.system_message)
            self.gateway.record_user_message(self.session_id, query)
        return self.session_id

    def query(self, query: str, runtime: FunctionsRuntime, env: Any = EmptyEnv(),  # noqa: B008 - AgentDojo API
              messages: Sequence[Any] = (),
              extra_args: dict | None = None) -> tuple[str, FunctionsRuntime, Any, Sequence[Any], dict]:
        extra = extra_args if extra_args is not None else {}
        if not messages or messages[-1]["role"] != "assistant" or not messages[-1].get("tool_calls"):
            return query, runtime, env, messages, extra
        sid = self._session(query)
        results = []
        for tc in messages[-1]["tool_calls"]:
            self.n_calls += 1
            if tc.id is None:
                tc.id = f"gt_{self.n_calls}"
            if self.n_calls > MAX_TOOL_CALLS:
                results.append(make_tool_result_message(tc, "", "Tool call limit reached"))
                continue
            if tc.function not in runtime.functions:
                results.append(make_tool_result_message(tc, "", f"Invalid tool {tc.function} provided."))
                continue
            tc.args = _fix_list_args(tc.args)
            results.append(self._one(sid, tc, runtime, env))
        extra["fw"] = {"session_id": sid, "decisions": [d.model_dump(mode="json") for d in self.decisions]}
        return query, runtime, env, [*messages, *results], extra

    def _one(self, sid: str, tc: Any, runtime: FunctionsRuntime, env: Any) -> dict[str, Any]:
        call = ToolCall(call_id=str(tc.id), tool=tc.function, args=dict(tc.args))
        d = self.gateway.evaluate(sid, call)
        self.decisions.append(d)
        if d.verdict == Verdict.REVIEW and d.review is not None:
            d = self.gateway.record_approval(sid, d, self.approver.decide(d.review))
            self.decisions.append(d)
        if d.verdict == Verdict.ALLOW or not self.enforce:
            result, error = runtime.run_function(env, tc.function, tc.args)
            # Label the structured result (provenance); the model sees AgentDojo's own YAML rendering.
            self.gateway.label_output(sid, call, jsonable(result) if error is None else {"error": error})
            self.gateway.commit(sid, call, d, executed=True)
            return make_tool_result_message(tc, self.output_formatter(result), error)
        self.gateway.commit(sid, call, d, executed=False)
        text = f"Blocked by policy [{', '.join(d.rule_ids)}]: {d.message_to_agent or 'not allowed'}"
        return make_tool_result_message(tc, text, text)
