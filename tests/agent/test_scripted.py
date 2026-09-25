from __future__ import annotations

import pytest
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from firewall.llm.scripted import ScriptedChatModel, ScriptError, ScriptStep

STEPS = [
    ScriptStep(tool="read_email", args={"email_id": "e1"}),
    ScriptStep(tool="send_email", args={"to": ["a@b.com"], "subject": "s", "body": "b"}, induced=True,
               call_id="custom"),
    ScriptStep(kind="final", text="All done."),
]


def _ai_with_call(i: int) -> AIMessage:
    return AIMessage(content="", tool_calls=[{"name": "x", "args": {}, "id": f"c{i}"}])


def test_step_order_and_final() -> None:
    m = ScriptedChatModel(steps=STEPS)
    h = [HumanMessage("hi")]
    r1 = m.invoke(h)
    assert r1.tool_calls[0]["name"] == "read_email" and r1.tool_calls[0]["id"] == "call_0"
    h += [r1, ToolMessage("out", tool_call_id="call_0")]
    r2 = m.invoke(h)
    assert r2.tool_calls[0]["name"] == "send_email" and r2.tool_calls[0]["id"] == "custom"
    h += [r2, ToolMessage("out", tool_call_id="custom")]
    r3 = m.invoke(h)
    assert r3.content == "All done." and not r3.tool_calls
    assert m.invoke([*h, r3]).content == "Done."
    assert r1.usage_metadata == {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}


def test_skip_predicate() -> None:
    m = ScriptedChatModel(steps=STEPS, skip=lambda i, step, msgs: step.induced)
    h = [HumanMessage("hi"), _ai_with_call(0), ToolMessage("o", tool_call_id="c0")]
    assert m.invoke(h).content == "All done."


def test_bind_tools_validation_and_shared_recording() -> None:
    m = ScriptedChatModel(steps=STEPS)
    with pytest.raises(ScriptError, match="send_email"):
        m.bind_tools([{"name": "read_email"}])
    bound = m.bind_tools([{"name": "read_email"}, {"name": "send_email"}])
    assert bound.bound_tool_names == frozenset({"read_email", "send_email"})
    bound.invoke([HumanMessage("hello")])
    assert len(m.recorded_inputs) == 1 and m.recorded_inputs[0][0].content == "hello"
    assert m._llm_type == "scripted"
