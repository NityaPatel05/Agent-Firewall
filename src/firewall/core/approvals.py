"""Approvers for REVIEW decisions. Approval comes only through this channel, never from context text."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Protocol

from firewall.core.canonical import canonicalize
from firewall.core.models import ApprovalResult, ArgType, ReviewItem, ReviewRequest


class Approver(Protocol):
    name: str

    def decide(self, review: ReviewRequest) -> ApprovalResult: ...


class AutoDenyApprover:
    """Worst-case utility: every REVIEW is declined."""

    name = "autodeny"

    def decide(self, review: ReviewRequest) -> ApprovalResult:
        return ApprovalResult(approved=False, approver=self.name)


class AlwaysApprover:
    """Approves everything (tests only)."""

    name = "always"

    def decide(self, review: ReviewRequest) -> ApprovalResult:
        return ApprovalResult(approved=True, approver=self.name)


def _type_of(item: ReviewItem) -> ArgType | None:
    if item.value_canonical is None:
        return None
    for t in (ArgType.IBAN, ArgType.EMAIL, ArgType.URL, ArgType.AMOUNT, ArgType.HANDLE, ArgType.CHANNEL,
              ArgType.CRYPTO_ADDRESS, ArgType.PATH, ArgType.DATE):
        if canonicalize(item.value, t) == item.value_canonical:
            return t
    return None


class OracleApprover:
    """Approves iff every reviewed value is a legit value under some matching key.

    Keys: "tool.arg", "*.arg" or "type:<argtype>"; legit values are canonicalized by the item's type at decide time.
    """

    name = "oracle"

    def __init__(self, legit: Mapping[str, Iterable[str]]) -> None:
        self._legit = {k: [str(v) for v in vals] for k, vals in legit.items()}

    def _is_legit(self, tool: str, item: ReviewItem) -> bool:
        t = _type_of(item)
        keys = [f"{tool}.{item.arg}", f"*.{item.arg}"] + ([f"type:{t.value}"] if t is not None else [])
        target = item.value_canonical if item.value_canonical is not None else str(item.value)
        for key in keys:
            for v in self._legit.get(key, ()):
                canon = canonicalize(v, t) if t is not None else v
                if (canon or v) == target or str(v) == str(item.value):
                    return True
        return False

    def decide(self, review: ReviewRequest) -> ApprovalResult:
        if not review.items:   # call-level review without reviewable values: approve iff the call itself is legit
            return ApprovalResult(approved=f"call:{review.tool}" in self._legit, approver=self.name)
        ok = all(self._is_legit(review.tool, it) for it in review.items)
        return ApprovalResult(approved=ok, approver=self.name)
