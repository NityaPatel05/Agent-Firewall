"""Core enums and value models shared by every gateway stage."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from firewall.core.labels import FastConstructModel, Label, SourceKind, SourceRef


class ArgType(StrEnum):
    EMAIL = "email"
    IBAN = "iban"
    URL = "url"
    HOST = "host"
    AMOUNT = "amount"
    PATH = "path"
    HANDLE = "handle"
    CHANNEL = "channel"
    PHONE = "phone"
    DATE = "date"
    ID = "id"
    CRYPTO_ADDRESS = "crypto_address"
    COMMAND = "command"
    SECRET_TEXT = "secret_text"
    TEXT = "text"
    ENUM = "enum"
    BOOL = "bool"
    INT = "int"
    LIST = "list"
    DICT = "dict"


class ArgRole(StrEnum):
    AUTHORITY = "authority"
    BOUNDED = "bounded"
    SELECTOR = "selector"
    CONTENT = "content"
    META = "meta"


class SideEffect(StrEnum):
    READ = "read"
    FETCH = "fetch"
    WRITE = "write"
    DELETE = "delete"
    EXTERNAL_COMM = "external_comm"
    PAYMENT = "payment"
    SHARE = "share"
    EXEC = "exec"
    CONFIG = "config"
    INSTALL = "install"
    SECRETS = "secrets"
    AUTH = "auth"


class Verdict(StrEnum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


_VERDICT_RANK = {Verdict.ALLOW: 0, Verdict.REVIEW: 1, Verdict.BLOCK: 2}


def verdict_rank(v: Verdict) -> int:
    return _VERDICT_RANK[v]


def max_verdict(*vs: Verdict) -> Verdict:
    """Most restrictive verdict (BLOCK > REVIEW > ALLOW); empty -> ALLOW."""
    best = Verdict.ALLOW
    for v in vs:
        if _VERDICT_RANK[v] > _VERDICT_RANK[best]:
            best = v
    return best


class Stage(StrEnum):
    SESSION = "session"
    REGISTRY = "registry"
    SCHEMA = "schema"
    TASK_SPEC = "task_spec"
    PROVENANCE = "provenance"
    POLICY = "policy"
    SINK = "sink"
    RULE_OF_TWO = "rule_of_two"
    DETECTOR = "detector"
    COMBINE = "combine"


class OriginClass(StrEnum):
    USER_TYPED = "USER_TYPED"
    APPROVED = "APPROVED"
    OWN_RECORD = "OWN_RECORD"
    POLICY_CONST = "POLICY_CONST"
    USER_NAMED_SOURCE = "USER_NAMED_SOURCE"
    UNTRUSTED_ONLY = "UNTRUSTED_ONLY"
    UNKNOWN = "UNKNOWN"


ORIGIN_RANK: dict[OriginClass, int] = {
    OriginClass.USER_TYPED: 6,
    OriginClass.APPROVED: 5,
    OriginClass.OWN_RECORD: 4,
    OriginClass.POLICY_CONST: 3,
    OriginClass.USER_NAMED_SOURCE: 2,
    OriginClass.UNTRUSTED_ONLY: 1,
    OriginClass.UNKNOWN: 0,
}

TRUSTED_ORIGINS: frozenset[OriginClass] = frozenset(
    {OriginClass.USER_TYPED, OriginClass.APPROVED, OriginClass.OWN_RECORD, OriginClass.POLICY_CONST}
)

_FROZEN = ConfigDict(frozen=True)


class ToolCall(FastConstructModel):
    model_config = _FROZEN
    call_id: str
    tool: str
    args: dict[str, Any]
    server: str | None = None
    step: int = 0


class Finding(FastConstructModel):
    model_config = _FROZEN
    rule_id: str
    stage: Stage
    verdict: Verdict
    reason: str
    arg: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)


class OriginMatch(FastConstructModel):
    model_config = _FROZEN
    entry_id: str
    kind: SourceKind
    source: SourceRef | None
    origin_class: OriginClass


class ArgOrigin(FastConstructModel):
    model_config = _FROZEN
    arg: str
    role: ArgRole
    arg_type: ArgType
    value_canonical: str | list[str] | None
    origin_class: OriginClass
    matches: tuple[OriginMatch, ...] = ()
    label: Label
    item_classes: tuple[OriginClass, ...] = ()   # per element, for list-valued args


class DestinationInfo(FastConstructModel):
    model_config = _FROZEN
    arg: str
    kind: ArgType
    value: str
    internal: bool
    own: bool
    allowlisted: bool
    host: str | None = None
    origin_class: OriginClass


class ReviewItem(FastConstructModel):
    model_config = _FROZEN
    arg: str
    value: Any
    value_canonical: str | None
    origin_class: OriginClass
    provenance_chain: tuple[SourceRef, ...]
    rule_ids: tuple[str, ...]


class ReviewRequest(FastConstructModel):
    model_config = _FROZEN
    session_id: str
    call_id: str
    tool: str
    args_raw: dict[str, Any]
    items: tuple[ReviewItem, ...]
    rule_ids: tuple[str, ...]


class ApprovalResult(BaseModel):
    model_config = _FROZEN
    approved: bool
    edited_args: dict[str, Any] | None = None
    approver: str


class Decision(FastConstructModel):
    model_config = _FROZEN
    call_id: str
    tool: str
    verdict: Verdict
    findings: tuple[Finding, ...]
    arg_origins: dict[str, ArgOrigin] = Field(default_factory=dict)
    destinations: tuple[DestinationInfo, ...] = ()
    normalized_args: dict[str, Any] = Field(default_factory=dict)
    review: ReviewRequest | None = None
    shadow_verdict: Verdict | None = None
    message_to_agent: str = ""
    eval_us: float = 0.0
    policy_hash: str = ""
    registry_hash: str = ""

    @property
    def rule_ids(self) -> tuple[str, ...]:
        """Unique rule IDs of non-ALLOW findings plus relaxing rule IDs, in finding order."""
        seen: dict[str, None] = {}
        for f in self.findings:
            if f.verdict != Verdict.ALLOW:
                seen.setdefault(f.rule_id, None)
            relaxed_by = f.evidence.get("relaxed_by")
            if isinstance(relaxed_by, str):
                seen.setdefault(relaxed_by, None)
        return tuple(seen)


class LabeledOutput(FastConstructModel):
    model_config = _FROZEN
    call_id: str
    content: str
    label: Label
    entry_ids: tuple[str, ...]
    findings: tuple[Finding, ...] = ()
    label_us: float = 0.0


class SanitizedText(BaseModel):
    model_config = _FROZEN
    text: str
    changed: bool
    findings: tuple[Finding, ...] = ()


class AuditRecord(BaseModel):
    ts: float
    session_id: str
    seq: int
    event: Literal["decision", "output", "approval", "final_answer", "session"]
    tool: str | None = None
    call_id: str | None = None
    args_sha256: str | None = None
    normalized_args: dict[str, Any] | None = None
    verdict: Verdict | None = None
    rule_ids: list[str] = Field(default_factory=list)
    origins: dict[str, str] = Field(default_factory=dict)
    label: dict[str, Any] | None = None
    eval_us: float | None = None
    policy_hash: str = ""
    registry_hash: str = ""
    mode: str = "enforce"
    scenario_id: str | None = None
    run_id: str | None = None
