"""Per-session mutable state and the immutable snapshot (`SessionView`) used by the pure pipeline."""

from __future__ import annotations

import threading
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from decimal import Decimal
from types import MappingProxyType
from typing import Any

from pydantic import Field

from firewall.core.canonical import canonicalize, normalize_text
from firewall.core.labels import FastConstructModel, Label
from firewall.core.models import ArgType, SideEffect
from firewall.core.provenance import Ledger, LedgerView
from firewall.core.task_spec import TaskSpec

ApprovalKey = tuple[SideEffect, ArgType, str]


class SessionFlags(FastConstructModel):
    ingested_untrusted: bool = False
    read_private: bool = False
    read_secret: bool = False


class SessionCounters(FastConstructModel):
    calls_by_tool: dict[str, int] = Field(default_factory=dict)
    calls_by_dest: dict[str, int] = Field(default_factory=dict)
    transfer_total: Decimal = Decimal(0)
    blocks: int = 0
    reviews: int = 0
    private_bytes_out: int = 0
    external_fetches_by_host: dict[str, int] = Field(default_factory=dict)


class ApprovalStore:
    """Value-pinned approvals scoped by (side effect, argument type, canonical value)."""

    def __init__(self, items: Iterable[ApprovalKey] = ()) -> None:
        self._items: set[ApprovalKey] = set(items)

    @staticmethod
    def _key(side_effect: SideEffect, arg_type: ArgType, value: str) -> ApprovalKey:
        canonical = canonicalize(value, arg_type) or value
        return (SideEffect(side_effect), ArgType(arg_type), canonical)

    def add(self, side_effect: SideEffect, arg_type: ArgType, canonical: str) -> None:
        self._items.add(self._key(side_effect, arg_type, canonical))

    def is_approved(self, side_effect: SideEffect, arg_type: ArgType, canonical: str) -> bool:
        if not self._items:
            return False
        if (side_effect, arg_type, canonical) in self._items:
            return True
        return self._key(side_effect, arg_type, canonical) in self._items

    def copy(self) -> ApprovalStore:
        return ApprovalStore(self._items)

    def items(self) -> frozenset[ApprovalKey]:
        return frozenset(self._items)

    def __len__(self) -> int:
        return len(self._items)


def resource_key(arg_type: ArgType, value: Any) -> str | None:
    """Key for `resource_labels` (file path / memory key) shared by writers and readers."""
    if value is None:
        return None
    if arg_type == ArgType.PATH:
        canonical = canonicalize(value, ArgType.PATH)
    else:
        canonical = normalize_text(str(value)).casefold() or None
    return None if not canonical else f"{arg_type.value}:{canonical}"


def _canon_set(values: Iterable[str], t: ArgType) -> frozenset[str]:
    return frozenset(c for c in (canonicalize(v, t) for v in values) if c)


class SessionState:
    """Mutable session state. Mutate only while holding `lock`; the pipeline reads `view()`."""

    def __init__(
        self,
        session_id: str | None = None,
        *,
        user_handle: str = "@emma",
        own_emails: Iterable[str] = (),
        own_ibans: Iterable[str] = (),
        task_spec: TaskSpec | None = None,
    ) -> None:
        self.session_id: str = session_id or uuid.uuid4().hex
        self.user_handle: str = canonicalize(user_handle, ArgType.HANDLE) or user_handle
        self.own_emails: frozenset[str] = _canon_set(own_emails, ArgType.EMAIL)
        self.own_ibans: frozenset[str] = _canon_set(own_ibans, ArgType.IBAN)
        self.ledger: Ledger = Ledger()
        self.task_spec: TaskSpec | None = task_spec
        self.flags: SessionFlags = SessionFlags()
        self.counters: SessionCounters = SessionCounters()
        self.approvals: ApprovalStore = ApprovalStore()
        self.resource_labels: dict[str, Label] = {}
        self.seen_message_ids: set[str] = set()
        self.step: int = 0
        self.circuit_open: bool = False
        self.lock: threading.RLock = threading.RLock()

    def constants(self) -> dict[ArgType, frozenset[str]]:
        """Session-level trusted constants (own addresses/accounts) for origin resolution."""
        return {ArgType.EMAIL: self.own_emails, ArgType.IBAN: self.own_ibans}

    def view(self) -> SessionView:
        with self.lock:
            return SessionView(
                session_id=self.session_id,
                user_handle=self.user_handle,
                own_emails=self.own_emails,
                own_ibans=self.own_ibans,
                ledger=self.ledger.snapshot(),
                task_spec=self.task_spec,
                flags=SessionFlags.model_construct(**self.flags.__dict__),
                counters=SessionCounters.model_construct(
                    calls_by_tool=dict(self.counters.calls_by_tool),
                    calls_by_dest=dict(self.counters.calls_by_dest),
                    transfer_total=self.counters.transfer_total,
                    blocks=self.counters.blocks,
                    reviews=self.counters.reviews,
                    private_bytes_out=self.counters.private_bytes_out,
                    external_fetches_by_host=dict(self.counters.external_fetches_by_host),
                ),
                approvals=self.approvals.copy(),
                resource_labels=MappingProxyType(dict(self.resource_labels)),
                circuit_open=self.circuit_open,
                step=self.step,
            )


@dataclass(frozen=True, slots=True)
class SessionView:
    """Read-only snapshot of a session; later mutations of the session are not visible."""

    session_id: str
    user_handle: str
    own_emails: frozenset[str]
    own_ibans: frozenset[str]
    ledger: LedgerView
    task_spec: TaskSpec | None
    flags: SessionFlags
    counters: SessionCounters
    approvals: ApprovalStore
    resource_labels: Mapping[str, Label]
    circuit_open: bool
    step: int

    def constants(self) -> dict[ArgType, frozenset[str]]:
        return {ArgType.EMAIL: self.own_emails, ArgType.IBAN: self.own_ibans}

    def dest_key(self, tool: str, dest_canonical: str) -> str:
        return f"{tool}|{dest_canonical}"

    def counter(self, name: str) -> Any:
        return getattr(self.counters, name)
