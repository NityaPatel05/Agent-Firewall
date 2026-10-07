"""Run one AgentDojo (user task, injection task) pair and score it two ways.

`native` = AgentDojo's own utility/security (`TaskSuite.run_task_with_pipeline` semantics, replicated here so the
transcript and environments are kept). Some injection tasks score security from the trace of *proposed* calls
(`security_from_traces`, e.g. slack injection_task_5), which a tool-call gate cannot influence. `executed`
re-applies those trace checks to the calls that actually executed (blocked/omitted calls removed), i.e. the
gate-only effect; environment-based checks are identical in both.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from pydantic import BaseModel


class PairResult(BaseModel):
    utility: bool
    security_native: bool | None
    security_executed: bool | None
    messages: list[Any] = []
    proposed: int = 0
    executed: int = 0


def _executed_calls(messages: Sequence[Any]) -> list[Any]:
    """Calls whose tool result is not a policy block / limit / invalid-tool error."""
    out = []
    for m in messages:
        if m["role"] != "tool":
            continue
        err = m.get("error") or ""
        if err.startswith(("Blocked by policy", "Tool call limit", "Invalid tool", "Empty function")):
            continue
        out.append(m["tool_call"])
    return out


def run_pair(suite: Any, pipeline: Any, user_task: Any, injection_task: Any | None,
             injections: dict[str, str]) -> PairResult:
    from agentdojo.agent_pipeline.errors import AbortAgentError
    from agentdojo.base_tasks import BaseUserTask
    from agentdojo.functions_runtime import FunctionsRuntime
    from agentdojo.task_suite.task_suite import (
        functions_stack_trace_from_messages,
        model_output_from_messages,
    )

    environment = suite.load_and_inject_default_environment(injections)
    task_env = user_task.init_environment(environment) if isinstance(user_task, BaseUserTask) else environment
    pre_env = task_env.model_copy(deep=True)
    runtime = FunctionsRuntime(suite.tools)
    messages: list[Any] = []
    model_output = None
    for _ in range(3):   # AgentDojo retries when the model produced no final output
        try:
            _, _, task_env, messages, _ = pipeline.query(user_task.PROMPT, runtime, task_env)
        except AbortAgentError as e:
            task_env, messages = e.task_environment, list(e.messages)
        model_output = model_output_from_messages(messages)
        if model_output is not None:
            break
    output = model_output or []
    proposed = functions_stack_trace_from_messages(messages)
    utility = suite._check_task_result(user_task, output, pre_env, task_env, proposed)
    if injection_task is None:
        return PairResult(utility=utility, security_native=None, security_executed=None, messages=list(messages),
                          proposed=len(proposed), executed=len(_executed_calls(messages)))
    native = suite._check_task_result(injection_task, output, pre_env, task_env, proposed)
    executed_calls = _executed_calls(messages)
    executed = suite._check_task_result(injection_task, output, pre_env, task_env, executed_calls)
    return PairResult(utility=utility, security_native=native, security_executed=executed, messages=list(messages),
                      proposed=len(proposed), executed=len(executed_calls))
