"""Request/response models of the gateway HTTP API."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from firewall.core.models import ApprovalResult, Decision, ToolCall
from firewall.core.registry import ToolSpec


class CreateSessionRequest(BaseModel):
    session_id: str | None = None
    user_handle: str = "@emma"
    own_emails: list[str] = Field(default_factory=list)
    own_ibans: list[str] = Field(default_factory=list)
    task_id: str | None = None


class CreateSessionResponse(BaseModel):
    session_id: str
    policy_id: str
    policy_hash: str
    registry_hash: str


class MessageRequest(BaseModel):
    text: str
    message_id: str | None = None


class EvaluateRequest(BaseModel):
    session_id: str
    call: ToolCall


class CommitRequest(BaseModel):
    session_id: str
    call: ToolCall
    decision: Decision
    executed: bool


class ApprovalRequestBody(BaseModel):
    session_id: str
    decision: Decision
    result: ApprovalResult


class LabelRequest(BaseModel):
    session_id: str
    call: ToolCall
    output: Any = None


class SanitizeRequest(BaseModel):
    session_id: str
    text: str


class SummaryRequest(BaseModel):
    text: str
    covered_entry_ids: list[str] = Field(default_factory=list)


class ToolDefinitionsRequest(BaseModel):
    specs: list[ToolSpec]


class PolicyValidateRequest(BaseModel):
    yaml: str


class PolicyValidateResponse(BaseModel):
    ok: bool
    errors: list[str] = Field(default_factory=list)
    policy_hash: str | None = None


class TraceEvent(BaseModel):
    kind: Literal["user", "system", "call", "output"]
    text: str | None = None
    call: ToolCall | None = None
    output: Any = None


class DryRunRequest(BaseModel):
    policy_yaml: str | None = None
    traces: list[list[TraceEvent]]


class DryRunResponse(BaseModel):
    n_calls: int
    allow: int
    review: int
    block: int
    review_rate: float
    block_rate: float
    by_rule: dict[str, int]


class ErrorResponse(BaseModel):
    error: str
    detail: Any = None
