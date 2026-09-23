"""LLM task-spec planner: reads ONLY the trusted user prompt; its draft is merged with the rule-based spec."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Literal

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, Field, ValidationError

from firewall.core.models import ArgType
from firewall.core.task_spec import NamedSource, RuleBasedTaskSpecExtractor, TaskSpec, merge_specs

PLANNER_PROMPT = (
    "You turn a user's request to an AI assistant into a task specification. Answer ONLY with JSON:\n"
    '{"groups": [<capability groups needed, from: email_send, chat_send, payment, banking, files, write, delete, '
    'share, calendar, booking, web, form, exec, install, auth>], "read_only": true|false, '
    '"named_sources": [{"kind": "file|email|url|message|channel|event", "pattern": "<glob of the source the user '
    'named>"}], "values": {"<iban|email|url|amount|path|handle>": ["<values the user typed>"]}}'
)
_AUTH_BY_KIND: dict[str, frozenset[ArgType]] = {
    "file": frozenset({ArgType.IBAN, ArgType.AMOUNT, ArgType.TEXT, ArgType.EMAIL}),
    "email": frozenset({ArgType.IBAN, ArgType.AMOUNT, ArgType.EMAIL, ArgType.TEXT}),
    "url": frozenset({ArgType.TEXT, ArgType.URL}),
}


class NamedSourceDraft(BaseModel):
    kind: Literal["file", "email", "url", "message", "channel", "event", "any"] = "any"
    pattern: str


class LLMTaskSpecDraft(BaseModel):
    groups: list[str] = Field(default_factory=list)
    read_only: bool = False
    named_sources: list[NamedSourceDraft] = Field(default_factory=list)
    values: dict[str, list[str]] = Field(default_factory=dict)


def parse_draft(text: str) -> LLMTaskSpecDraft:
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m is None:
        return LLMTaskSpecDraft(read_only=True)
    try:
        return LLMTaskSpecDraft.model_validate(json.loads(m.group(0)))
    except (json.JSONDecodeError, ValidationError):
        return LLMTaskSpecDraft(read_only=True)


def draft_to_spec(d: LLMTaskSpecDraft, prompt: str, task_id: str | None) -> TaskSpec:
    values: dict[ArgType, frozenset[str]] = {}
    for k, vals in d.values.items():
        try:
            values[ArgType(k)] = frozenset(str(v) for v in vals)
        except ValueError:
            continue
    named = tuple(NamedSource(ref_kind=ns.kind, pattern=ns.pattern.lower(),
                              authorizes=_AUTH_BY_KIND.get(ns.kind, frozenset({ArgType.TEXT})))
                  for ns in d.named_sources)
    return TaskSpec(task_id=task_id, source="llm", prompt_sha256=hashlib.sha256(prompt.encode()).hexdigest(),
                    read_only=d.read_only, allowed_groups=frozenset({*d.groups, "read", "fetch"}),
                    authorized_values=values, named_sources=named)


class LLMTaskSpecPlanner:
    """One planner call per task on the user prompt only (never tool outputs)."""

    def __init__(self, model: BaseChatModel) -> None:
        self.model = model

    def draft(self, prompt: str) -> LLMTaskSpecDraft:
        msg: Any = self.model.invoke([SystemMessage(PLANNER_PROMPT), HumanMessage(prompt)])
        return parse_draft(getattr(msg, "text", None) or str(msg.content))

    def plan(self, prompt: str, *, task_id: str | None = None) -> TaskSpec:
        rule = RuleBasedTaskSpecExtractor().extract(prompt, task_id=task_id)
        return merge_specs(rule, draft_to_spec(self.draft(prompt), prompt, task_id), prompt)


class MergedPlannerExtractor:
    """TaskSpecExtractor adapter for the gateway (`--planner llm`)."""

    def __init__(self, model: BaseChatModel) -> None:
        self.planner = LLMTaskSpecPlanner(model)

    def extract(self, prompt: str, *, task_id: str | None = None) -> TaskSpec:
        return self.planner.plan(prompt, task_id=task_id)
