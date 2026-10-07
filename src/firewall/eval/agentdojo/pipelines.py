"""AgentDojo pipelines per defense: B0 (none), B2 (tool_filter), B3 (ProtectAI PI detector), GW (our gateway)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal

from agentdojo.agent_pipeline import (
    AgentPipeline,
    InitQuery,
    SystemMessage,
    ToolsExecutionLoop,
    ToolsExecutor,
)
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.pi_detector import PromptInjectionDetector
from langchain_core.language_models.chat_models import BaseChatModel

from firewall.core.approvals import AutoDenyApprover, OracleApprover
from firewall.core.gateway import Gateway
from firewall.eval.agentdojo.compat import register_model_names
from firewall.eval.agentdojo.executor import GatewayToolsExecutor
from firewall.eval.agentdojo.llm import LangChainLLM, LLMToolFilter
from firewall.eval.agentdojo.registry_map import agentdojo_policy, load_agentdojo_registry

AD_DEFENSES = ("B0", "B2", "B3", "GW")
MAX_ITERS = 30


def system_message() -> str:
    from agentdojo.agent_pipeline.agent_pipeline import load_system_message

    return load_system_message(None)


class DetectorElement(PromptInjectionDetector):
    """AgentDojo's PI-detector element (per tool message, omit on detection) backed by our windowed HF detector
    (same ProtectAI v2 model and 0.5 threshold as AgentDojo's `transformers_pi_detector`, but long outputs are
    scored over 512-token windows instead of being truncated)."""

    def __init__(self, detector: Any) -> None:
        super().__init__(mode="message", raise_on_injection=False)
        self.detector = detector
        self.omissions = 0

    def detect(self, tool_output: str) -> tuple[bool, float]:
        res = self.detector.score(tool_output)
        self.omissions += int(res.flagged)
        return res.flagged, res.score


def make_gateway(suite: str) -> Gateway:
    return Gateway(policy=agentdojo_policy(suite), registry=load_agentdojo_registry(suite))


def build_pipeline(defense: str, *, llm: BasePipelineElement, model_id: str, suite: str,
                   approver_mode: Literal["oracle", "autodeny"] = "oracle",
                   legit: Mapping[str, Any] | None = None, filter_model: BaseChatModel | None = None,
                   detector: Any = None) -> tuple[AgentPipeline, GatewayToolsExecutor | None, Any]:
    """Returns (pipeline, gateway executor or None, detector element or None). Build one per episode."""
    register_model_names([model_id])
    sysmsg = system_message()
    head: list[BasePipelineElement] = [SystemMessage(sysmsg), InitQuery()]
    executor: GatewayToolsExecutor | None = None
    det: DetectorElement | None = None
    if defense == "GW":
        approver = OracleApprover(legit or {}) if approver_mode == "oracle" else AutoDenyApprover()
        executor = GatewayToolsExecutor(gateway=make_gateway(suite), approver=approver, system_message=sysmsg)
        loop = ToolsExecutionLoop([executor, llm], max_iters=MAX_ITERS)
    elif defense == "B3":
        det = DetectorElement(detector)
        loop = ToolsExecutionLoop([ToolsExecutor(), det, llm], max_iters=MAX_ITERS)
    else:
        loop = ToolsExecutionLoop([ToolsExecutor(), llm], max_iters=MAX_ITERS)
    if defense == "B2":
        if filter_model is None:
            raise ValueError("B2 (tool_filter) needs a filter model")
        head.append(LLMToolFilter(filter_model))
    pipe = AgentPipeline([*head, llm, loop])
    pipe.name = f"{model_id}-{defense}"
    return pipe, executor, det


def make_llm(chat_model: BaseChatModel, model_id: str) -> LangChainLLM:
    return LangChainLLM(chat_model, name=model_id)
