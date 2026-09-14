"""Provenance labels: integrity x confidentiality lattice with sources and readers."""

from __future__ import annotations

from collections.abc import Iterable
from enum import IntEnum, StrEnum
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict


class FastConstructModel(BaseModel):
    """BaseModel whose `model_construct` is a lean trusted-input constructor (hot path, values pre-validated).

    Only use `model_construct` with values that already satisfy the field types; normal construction still
    validates.
    """

    @classmethod
    def model_construct(cls, _fields_set: set[str] | None = None, **values: Any) -> Self:  # type: ignore[override]
        fields = cls.model_fields
        if len(values) != len(fields):
            for name, info in fields.items():
                if name not in values:
                    values[name] = info.get_default(call_default_factory=True)
        obj = cls.__new__(cls)
        setattr_ = object.__setattr__
        setattr_(obj, "__dict__", values)
        setattr_(obj, "__pydantic_fields_set__", set(values) if _fields_set is None else _fields_set)
        setattr_(obj, "__pydantic_extra__", None)
        setattr_(obj, "__pydantic_private__", None)
        return obj


class Integrity(IntEnum):
    UNTRUSTED = 0
    TRUSTED = 1


class Confidentiality(IntEnum):
    PUBLIC = 0
    PRIVATE = 1
    SECRET = 2


class SourceKind(StrEnum):
    USER = "user"
    SYSTEM = "system"
    POLICY = "policy"
    APPROVAL = "approval"
    OWN_RECORD = "own_record"
    TOOL_OUTPUT = "tool_output"
    TOOL_DESCRIPTION = "tool_description"
    SUMMARY = "summary"
    DERIVED = "derived"
    QUARANTINE = "quarantine"


class SourceRef(FastConstructModel):
    """Where a piece of text came from."""

    model_config = ConfigDict(frozen=True)

    kind: SourceKind
    tool: str | None = None
    server: str | None = None
    call_id: str | None = None
    author: str | None = None
    ref: str | None = None


Readers = frozenset[str] | Literal["*"]


def _join_readers(a: Readers, b: Readers) -> Readers:
    if a == "*":
        return b
    if b == "*":
        return a
    return a & b  # type: ignore[operator]


class Label(FastConstructModel):
    """Immutable provenance label. `join` is the lattice least upper bound (most restrictive)."""

    model_config = ConfigDict(frozen=True)

    integrity: Integrity
    confidentiality: Confidentiality
    sources: frozenset[SourceRef] = frozenset()
    readers: Readers = "*"

    @property
    def trusted(self) -> bool:
        return self.integrity == Integrity.TRUSTED

    def join(self, other: Label) -> Label:
        if other is self or other == self:
            return self
        sources = self.sources | other.sources
        integrity = min(self.integrity, other.integrity)
        conf = max(self.confidentiality, other.confidentiality)
        readers = _join_readers(self.readers, other.readers)
        if integrity == self.integrity and conf == self.confidentiality and sources == self.sources \
                and readers == self.readers:
            return self
        # All inputs are already-validated labels, so skip re-validation on the hot path.
        return Label.model_construct(integrity=integrity, confidentiality=conf, sources=sources, readers=readers)

    @classmethod
    def user(cls) -> Label:
        return cls(
            integrity=Integrity.TRUSTED,
            confidentiality=Confidentiality.PRIVATE,
            sources=frozenset({SourceRef(kind=SourceKind.USER)}),
        )

    @classmethod
    def system(cls) -> Label:
        return cls(
            integrity=Integrity.TRUSTED,
            confidentiality=Confidentiality.PUBLIC,
            sources=frozenset({SourceRef(kind=SourceKind.SYSTEM)}),
        )

    @classmethod
    def tool(
        cls,
        *,
        trusted: bool,
        conf: Confidentiality,
        tool: str,
        call_id: str | None,
        server: str | None = None,
        ref: str | None = None,
        author: str | None = None,
        kind: SourceKind = SourceKind.TOOL_OUTPUT,
    ) -> Label:
        src = SourceRef(kind=kind, tool=tool, server=server, call_id=call_id, author=author, ref=ref)
        return cls(
            integrity=Integrity.TRUSTED if trusted else Integrity.UNTRUSTED,
            confidentiality=conf,
            sources=frozenset({src}),
        )


BOTTOM = Label(integrity=Integrity.TRUSTED, confidentiality=Confidentiality.PUBLIC)


def join_all(labels: Iterable[Label]) -> Label:
    """Join of many labels; the empty join is TRUSTED/PUBLIC with no sources."""
    result = BOTTOM
    for lab in labels:
        result = result.join(lab)
    return result
