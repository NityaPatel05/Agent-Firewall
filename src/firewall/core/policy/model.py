"""Policy data model: frozen pydantic models validated at load time (PLAN §5.5)."""

from __future__ import annotations

import re
from functools import cached_property
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from firewall.core.models import OriginClass, SideEffect, Verdict

RULE_ID_RE = re.compile(r"^[A-Z][A-Z0-9]*(-[A-Z0-9]+)+$")
RELAXABLE: frozenset[str] = frozenset(
    {"SYS-PROV-NAMED", "SYS-PROV-UNKNOWN", "SYS-SINK-HOST", "SYS-R2-001", "SYS-SCHEMA-URL-IN-TEXT"}
)
# In `strict` strictness these REVIEW rules become BLOCK.
STRICT_UPGRADE: frozenset[str] = frozenset({"POL-RO-001", "POL-SCOPE-001"})

DEFAULT_SIDE_EFFECT_VERDICTS: dict[SideEffect, Verdict] = {
    SideEffect.READ: Verdict.ALLOW,
    SideEffect.FETCH: Verdict.ALLOW,
    SideEffect.WRITE: Verdict.ALLOW,
    SideEffect.DELETE: Verdict.ALLOW,
    SideEffect.EXTERNAL_COMM: Verdict.ALLOW,
    SideEffect.SHARE: Verdict.ALLOW,
    SideEffect.PAYMENT: Verdict.ALLOW,
    SideEffect.INSTALL: Verdict.REVIEW,
    SideEffect.EXEC: Verdict.REVIEW,
    SideEffect.CONFIG: Verdict.BLOCK,
    SideEffect.SECRETS: Verdict.BLOCK,
    SideEffect.AUTH: Verdict.REVIEW,
}

_STRICT = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

Op = Literal["eq", "ne", "in", "not_in", "gt", "gte", "lt", "lte", "regex", "glob", "host_in", "domain_in",
             "len_gt", "contains"]


class Match(BaseModel):
    """Empty field = wildcard; AND across non-empty fields, OR within a field."""

    model_config = _STRICT
    tools: frozenset[str] = frozenset()
    groups: frozenset[str] = frozenset()
    side_effects: frozenset[SideEffect] = frozenset()
    servers: frozenset[str] = frozenset()


class ToolCount(BaseModel):
    model_config = _STRICT
    tool: str
    n: int


class SessionCond(BaseModel):
    """All set fields must hold."""

    model_config = _STRICT
    blocks_gte: int | None = None
    calls_of_tool_gte: ToolCount | None = None
    calls_to_same_dest_gte: int | None = None
    transfer_total_gt: float | None = None
    ingested_untrusted: bool | None = None
    read_private: bool | None = None

    @model_validator(mode="after")
    def _non_empty(self) -> SessionCond:
        if not self.model_fields_set:
            raise ValueError("session condition needs at least one field")
        return self


_HEADS = (
    "all", "any", "not_", "arg", "arg_present", "arg_origin", "session", "task_read_only", "task_allows_tool",
    "destination", "dest_origin_in", "dest_origin_not_in", "secret_in_args", "canary_in_args",
    "content_confidentiality_gte", "private_bytes_out_gt", "ctx_untrusted", "detector_flagged",
)


class Condition(BaseModel):
    """A condition with exactly one head key (see PLAN §5.5 / IMPLEMENTATION_PLAN M3 semantics table)."""

    model_config = _STRICT
    all: tuple[Condition, ...] | None = None
    any: tuple[Condition, ...] | None = None
    not_: Condition | None = Field(None, alias="not")
    arg: str | None = None
    op: Op | None = None
    value: Any = None
    arg_present: str | None = None
    arg_origin: str | None = None
    in_: tuple[OriginClass, ...] | None = Field(None, alias="in")
    not_in: tuple[OriginClass, ...] | None = None
    session: SessionCond | None = None
    task_read_only: bool | None = None
    task_allows_tool: bool | None = None
    destination: Literal["internal", "external", "own"] | None = None
    dest_origin_in: tuple[OriginClass, ...] | None = None
    dest_origin_not_in: tuple[OriginClass, ...] | None = None
    secret_in_args: bool | None = None
    canary_in_args: bool | None = None
    content_confidentiality_gte: Literal["private", "secret"] | None = None
    private_bytes_out_gt: int | None = None
    ctx_untrusted: bool | None = None
    detector_flagged: bool | None = None

    @model_validator(mode="after")
    def _one_head(self) -> Condition:
        heads = [h for h in _HEADS if getattr(self, h) is not None]
        if len(heads) != 1:
            raise ValueError(f"condition must have exactly one head key, got {heads or 'none'}")
        head = heads[0]
        if head == "arg":
            if self.op is None:
                raise ValueError("`arg` condition needs `op`")
        elif self.op is not None or self.value is not None:
            raise ValueError("`op`/`value` are only valid with `arg`")
        if head == "arg_origin":
            if (self.in_ is None) == (self.not_in is None):
                raise ValueError("`arg_origin` needs exactly one of `in` / `not_in`")
        elif self.in_ is not None or self.not_in is not None:
            raise ValueError("`in`/`not_in` are only valid with `arg_origin`")
        if head in ("all", "any") and not getattr(self, head):
            raise ValueError(f"`{head}` needs at least one condition")
        return self

    @cached_property
    def head(self) -> str:
        return next(h for h in _HEADS if getattr(self, h) is not None)


Condition.model_rebuild()


class Rule(BaseModel):
    model_config = _STRICT
    id: str
    description: str
    effect: Verdict
    match: Match = Match()
    when: Condition | None = None
    relax: tuple[str, ...] = ()
    message: str | None = None
    fallback: Literal["block", "ask_user", "feedback_to_agent"] = "feedback_to_agent"

    @field_validator("id")
    @classmethod
    def _id_format(cls, v: str) -> str:
        if not RULE_ID_RE.match(v):
            raise ValueError(f"invalid rule id {v!r} (expected e.g. POL-SEC-001)")
        if v.startswith("SYS-"):
            raise ValueError("rule ids starting with SYS- are reserved for built-in stages")
        return v

    @model_validator(mode="after")
    def _relax_rules(self) -> Rule:
        if self.relax:
            if self.effect != Verdict.ALLOW:
                raise ValueError(f"{self.id}: `relax` is only allowed on effect=allow rules")
            bad = [r for r in self.relax if not r.startswith("SYS-") or r not in RELAXABLE]
            if bad:
                raise ValueError(f"{self.id}: cannot relax {bad}; relaxable: {sorted(RELAXABLE)}")
        return self


class Defaults(BaseModel):
    """YAML uses flat keys (`unknown_tool`, `read`, `fetch`, …); they are mapped to `per_side_effect`."""

    model_config = _STRICT
    unknown_tool: Verdict = Verdict.BLOCK
    per_side_effect: dict[SideEffect, Verdict] = Field(default_factory=lambda: dict(DEFAULT_SIDE_EFFECT_VERDICTS))

    @model_validator(mode="before")
    @classmethod
    def _flat_keys(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        out: dict[str, Any] = {}
        per: dict[str, Any] = dict(data.get("per_side_effect", {}) or {})
        for key, val in data.items():
            if key in ("unknown_tool", "per_side_effect"):
                if key == "unknown_tool":
                    out[key] = val
                continue
            try:
                SideEffect(key)
            except ValueError as exc:
                raise ValueError(f"unknown side effect in defaults: {key!r}") from exc
            per[key] = val
        if per:
            out["per_side_effect"] = per
        return out

    def verdict_for(self, side_effect: SideEffect) -> Verdict:
        return self.per_side_effect.get(side_effect, DEFAULT_SIDE_EFFECT_VERDICTS[side_effect])


class Allowlists(BaseModel):
    model_config = _STRICT
    internal_email_domains: frozenset[str] = frozenset()
    own_emails: frozenset[str] = frozenset()
    own_ibans: frozenset[str] = frozenset()
    own_handles: frozenset[str] = frozenset()
    own_crypto_addresses: frozenset[str] = frozenset()
    http_hosts: frozenset[str] = frozenset()
    http_path_prefixes: frozenset[str] = frozenset()
    slack_workspace_users: frozenset[str] = frozenset()
    exec_binaries: frozenset[str] = frozenset()
    protected_paths: frozenset[str] = frozenset()
    env_denylist: frozenset[str] = frozenset()
    mcp_trusted_servers: frozenset[str] = frozenset()
    mcp_registry_hosts: frozenset[str] = frozenset()


class CircuitBreaker(BaseModel):
    model_config = _STRICT
    max_blocks: int = 3
    then: Literal["block_consequential"] = "block_consequential"


class EgressBudget(BaseModel):
    model_config = _STRICT
    max_external_fetches_per_host: int = 20
    max_private_bytes_out: int = 20000
    # After private data was read in an untrusted context: fetches per non-allow-listed host whose URL the user
    # did not type (char-by-char exfiltration, CamoLeak / T11).
    max_tainted_fetches_per_host: int = 3


def _default_named_effect() -> dict[str, Verdict]:
    return {"payment": Verdict.REVIEW, "external_comm": Verdict.REVIEW, "share": Verdict.REVIEW,
            "default": Verdict.ALLOW}


class Policy(BaseModel):
    model_config = _STRICT
    version: Literal[1]
    policy_id: str
    description: str = ""
    extends: tuple[str, ...] = ()
    mode: Literal["enforce", "shadow"] = "enforce"
    strictness: Literal["standard", "strict"] = "standard"
    defaults: Defaults = Defaults()
    named_source_effect: dict[str, Verdict] = Field(default_factory=_default_named_effect)
    circuit_breaker: CircuitBreaker = CircuitBreaker()
    egress_budget: EgressBudget = EgressBudget()
    allowlists: Allowlists = Allowlists()
    canaries: tuple[str, ...] = ()
    detector_escalation: bool = False
    rules: tuple[Rule, ...] = ()

    @field_validator("extends", mode="before")
    @classmethod
    def _extends_list(cls, v: Any) -> Any:
        return (v,) if isinstance(v, str) else v

    @field_validator("named_source_effect")
    @classmethod
    def _named_keys(cls, v: dict[str, Verdict]) -> dict[str, Verdict]:
        for key in v:
            if key != "default":
                try:
                    SideEffect(key)
                except ValueError as exc:
                    raise ValueError(f"unknown side effect in named_source_effect: {key!r}") from exc
        return v

    @model_validator(mode="after")
    def _unique_rule_ids(self) -> Policy:
        ids = [r.id for r in self.rules]
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            raise ValueError(f"duplicate rule ids: {dupes}")
        return self

    def named_effect(self, side_effect: SideEffect) -> Verdict:
        return self.named_source_effect.get(side_effect.value, self.named_source_effect.get("default", Verdict.ALLOW))
