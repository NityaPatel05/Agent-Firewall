"""Thin compatibility layer over the pinned AgentDojo version (see bench.lock)."""

from __future__ import annotations

import importlib
from collections.abc import Iterable, Mapping
from pathlib import Path
from types import ModuleType
from typing import Any

BENCHMARK_VERSION = "v1.2.2"


class AgentDojoMissing(ImportError):
    """agentdojo is not installed (install command in bench.lock)."""


def _install_hint() -> str:
    lock = Path(__file__).resolve().parents[4] / "bench.lock"
    if lock.exists():
        for line in lock.read_text(encoding="utf-8").splitlines():
            if line.startswith("install="):
                return line.removeprefix("install=")
    return 'pip install "agentdojo @ git+https://github.com/ethz-spylab/agentdojo"'


def require_agentdojo() -> ModuleType:
    try:
        return importlib.import_module("agentdojo")
    except ImportError as exc:
        raise AgentDojoMissing(f"agentdojo is not installed; run: {_install_hint()}") from exc


def get_suites(version: str = BENCHMARK_VERSION) -> dict[str, Any]:
    require_agentdojo()
    from agentdojo.task_suite.load_suites import get_suites as _get

    return dict(_get(version))


def get_suite(name: str, version: str = BENCHMARK_VERSION) -> Any:
    return get_suites(version)[name]


def register_model_names(model_ids: Iterable[str]) -> None:
    """Make AgentDojo's attacks address our models by name (else `get_model_name_from_pipeline` fails)."""
    require_agentdojo()
    from agentdojo.models import MODEL_NAMES

    for mid in model_ids:
        vendor = "Google" if mid.startswith("gemini") else "OpenAI" if "gpt" in mid else "Groq"
        MODEL_NAMES.setdefault(mid, f"AI model developed by {vendor}")


def text_of(content: Any) -> str:
    """AgentDojo message content (list of blocks, str or None) as text."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    return "\n".join(str(b.get("content") or "") for b in content if isinstance(b, Mapping))


def make_tool_result_message(tool_call: Any, content: str, error: str | None) -> dict[str, Any]:
    from agentdojo.types import ChatToolResultMessage, text_content_block_from_string

    return ChatToolResultMessage(role="tool", content=[text_content_block_from_string(content)],
                                 tool_call_id=tool_call.id, tool_call=tool_call, error=error)


def make_assistant_message(text: str, tool_calls: list[Any] | None) -> dict[str, Any]:
    from agentdojo.types import ChatAssistantMessage, text_content_block_from_string

    return ChatAssistantMessage(role="assistant", content=[text_content_block_from_string(text)],
                                tool_calls=tool_calls or None)


def tool_calls_of(message: Mapping[str, Any]) -> list[Any]:
    return list(message.get("tool_calls") or [])


def functions_to_tool_dicts(runtime: Any) -> list[dict[str, Any]]:
    """AgentDojo Function (pydantic parameters) -> OpenAI-style tool dicts for LangChain `bind_tools`."""
    out = []
    for f in runtime.functions.values():
        schema = f.parameters.model_json_schema()
        schema.pop("title", None)
        out.append({"type": "function", "function": {"name": f.name, "description": f.description,
                                                      "parameters": schema}})
    return out


def jsonable(value: Any) -> Any:
    """Tool results (pydantic models, lists, dicts) as JSON-ready data for the gateway's labeler."""
    from pydantic import BaseModel

    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, (list, tuple)):
        return [jsonable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in value.items()}
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def check_security_sign(suite_name: str = "banking") -> None:
    """Replay one injection task's ground truth undefended on its injected environment; AgentDojo's
    `security` must be True when the goal is achieved (True = attack success). Raises otherwise."""
    from agentdojo.agent_pipeline import AgentPipeline, InitQuery, SystemMessage
    from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline

    suite = get_suite(suite_name)
    user_task = next(iter(suite.user_tasks.values()))
    inj_task = next(iter(suite.injection_tasks.values()))
    pipe = AgentPipeline([SystemMessage("You are a helpful assistant."), InitQuery(),
                          GroundTruthPipeline(inj_task)])
    _, security = suite.run_task_with_pipeline(pipe, user_task, inj_task, {})
    if security is not True:
        raise AssertionError(f"AgentDojo security sign check failed: {security!r} for an achieved injection goal")
