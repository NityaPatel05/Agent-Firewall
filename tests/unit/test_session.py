from __future__ import annotations

import dataclasses
from decimal import Decimal

import pytest

from firewall.core.labels import Label, SourceKind
from firewall.core.models import ArgType, SideEffect
from firewall.core.session import ApprovalStore, SessionState


def test_approval_scoping() -> None:
    store = ApprovalStore()
    store.add(SideEffect.PAYMENT, ArgType.IBAN, "GB33 BUKB 2020 1555 5555 55")
    assert store.is_approved(SideEffect.PAYMENT, ArgType.IBAN, "GB33BUKB20201555555555")
    assert not store.is_approved(SideEffect.EXTERNAL_COMM, ArgType.IBAN, "GB33BUKB20201555555555")
    assert not store.is_approved(SideEffect.PAYMENT, ArgType.TEXT, "GB33BUKB20201555555555")
    assert not store.is_approved(SideEffect.PAYMENT, ArgType.IBAN, "US133000000121212121212")
    assert len(store) == 1


def test_approval_copy_independent() -> None:
    store = ApprovalStore()
    clone = store.copy()
    store.add(SideEffect.SHARE, ArgType.EMAIL, "a@b.com")
    assert not clone.is_approved(SideEffect.SHARE, ArgType.EMAIL, "a@b.com")


def test_session_defaults_and_canonical_constants() -> None:
    s = SessionState("s1", user_handle="@Emma", own_emails=["Emma@BlueSparrowTech.com"],
                     own_ibans=["DE89 3704 0044 0532 0130 00"])
    assert s.user_handle == "@emma"
    assert s.own_emails == frozenset({"emma@bluesparrowtech.com"})
    assert s.constants()[ArgType.IBAN] == frozenset({"DE89370400440532013000"})
    assert not s.flags.ingested_untrusted and s.counters.blocks == 0 and not s.circuit_open


def test_counters_mutable() -> None:
    s = SessionState()
    s.counters.calls_by_tool["send_money"] = 1
    s.counters.transfer_total += Decimal("10.50")
    assert s.counters.transfer_total == Decimal("10.50")


def test_view_is_snapshot() -> None:
    s = SessionState("s1")
    s.ledger.append(kind=SourceKind.USER, text="hello", label=Label.user())
    s.counters.calls_by_dest["send_money|X"] = 1
    v = s.view()
    s.ledger.append(kind=SourceKind.USER, text="more", label=Label.user())
    s.counters.calls_by_dest["send_money|X"] = 5
    s.counters.blocks = 2
    s.flags.ingested_untrusted = True
    s.approvals.add(SideEffect.PAYMENT, ArgType.IBAN, "GB33BUKB20201555555555")
    s.resource_labels["file:/a"] = Label.user()
    s.circuit_open = True
    assert len(v.ledger) == 1
    assert v.counters.calls_by_dest["send_money|X"] == 1 and v.counters.blocks == 0
    assert not v.flags.ingested_untrusted
    assert not v.approvals.is_approved(SideEffect.PAYMENT, ArgType.IBAN, "GB33BUKB20201555555555")
    assert "file:/a" not in v.resource_labels
    assert v.circuit_open is False


def test_view_frozen() -> None:
    v = SessionState("s1").view()
    with pytest.raises(dataclasses.FrozenInstanceError):
        v.step = 3  # type: ignore[misc]
    with pytest.raises(TypeError):
        v.resource_labels["x"] = Label.user()  # type: ignore[index]


def test_dest_key() -> None:
    assert SessionState("s").view().dest_key("send_money", "GB33") == "send_money|GB33"
