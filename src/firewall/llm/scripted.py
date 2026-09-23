"""ScriptedChatModel: deterministic offline chat model that replays a script of tool calls."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any, Literal

from langchain_core.callbacks import CallbackManagerForLLMRun
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from pydantic import BaseModel, ConfigDict, Field


class ScriptError(ValueError):
    pass


class ScriptStep(BaseModel):
    """One model turn: a single tool call or the final answer.

    `induced`: caused by an injection (compromised trajectory); `needs`: indices of steps whose output it uses.
    """

    model_config = ConfigDict(frozen=True)
    kind: Literal["call", "final"] = "call"
    tool: str | None = None
    args: dict[str, Any] = Field(default_factory=dict)
    text: str | None = None
    induced: bool = False
    needs: tuple[int, ...] = ()
    call_id: str | None = None


SkipPredicate = Callable[[int, ScriptStep, Sequence[BaseMessage]], bool]
_ZERO_USAGE = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}


def _tool_name(t: Any) -> str:
    if isinstance(t, dict):
        return str(t.get("name") or t.get("function", {}).get("name"))
    return str(getattr(t, "name", None) or getattr(t, "__name__", t))


class ScriptedChatModel(BaseChatModel):
    """Stateless position rule: the (k+1)-th non-skipped step is emitted after k AIMessages in the history."""

    model_config = ConfigDict(arbitrary_types_allowed=True)
    steps: list[ScriptStep] = Field(default_factory=list)
    final_text: str = "Done."
    skip: Any = None
    recorded_inputs: list[list[BaseMessage]] = Field(default_factory=list)
    bound_tool_names: frozenset[str] | None = None
    strict_tools: bool = True   # False: allow scripted calls to tools hidden by a tool filter (B2 semantics)

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def __repr__(self) -> str:
        # LangChain serializes the model (via repr) on every invoke; the default repr would include every step
        # and the growing `recorded_inputs`, which dominated offline episode time.
        return f"ScriptedChatModel(steps={len(self.steps)})"

    def bind_tools(self, tools: Sequence[Any], **kwargs: Any) -> ScriptedChatModel:  # type: ignore[override]
        names = frozenset(_tool_name(t) for t in tools)
        missing = sorted({s.tool for s in self.steps if s.kind == "call" and s.tool} - names)
        if missing and self.strict_tools:
            raise ScriptError(f"script uses tools that are not bound: {missing}")
        # Shallow copy: `recorded_inputs` stays shared with the original (tests inspect it).
        return self.model_copy(update={"bound_tool_names": names})

    def _active_steps(self, messages: Sequence[BaseMessage]) -> list[tuple[int, ScriptStep]]:
        skip: SkipPredicate | None = self.skip
        return [(i, s) for i, s in enumerate(self.steps) if skip is None or not skip(i, s, messages)]

    def _generate(self, messages: list[BaseMessage], stop: list[str] | None = None,
                  run_manager: CallbackManagerForLLMRun | None = None, **kwargs: Any) -> ChatResult:
        self.recorded_inputs.append(list(messages))
        n_emitted = sum(1 for m in messages if isinstance(m, AIMessage))
        active = self._active_steps(messages)
        if n_emitted < len(active):
            i, step = active[n_emitted]
            if step.kind == "final":
                msg = AIMessage(content=step.text or self.final_text, usage_metadata=_ZERO_USAGE)
            else:
                assert step.tool is not None
                msg = AIMessage(content="", usage_metadata=_ZERO_USAGE,
                                tool_calls=[{"name": step.tool, "args": dict(step.args),
                                             "id": step.call_id or f"call_{i}", "type": "tool_call"}])
        else:
            msg = AIMessage(content=self.final_text, usage_metadata=_ZERO_USAGE)
        return ChatResult(generations=[ChatGeneration(message=msg)])
