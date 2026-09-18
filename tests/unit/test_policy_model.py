from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from firewall.core.models import SideEffect, Verdict
from firewall.core.policy.model import Condition, Defaults, Policy, Rule


def _rule(**kw: Any) -> Rule:
    base: dict[str, Any] = {"id": "POL-X-001", "description": "d", "effect": "block"}
    base.update(kw)
    return Rule.model_validate(base)


@pytest.mark.parametrize("rid", ["pol-x-001", "POL", "POL_X_001", "POL-", "-POL-1", "1POL-1"])
def test_invalid_rule_ids(rid: str) -> None:
    with pytest.raises(ValidationError):
        _rule(id=rid)


def test_sys_prefix_reserved() -> None:
    with pytest.raises(ValidationError):
        _rule(id="SYS-PROV-001")


@pytest.mark.parametrize("rid", ["POL-SEC-001", "BANK-AMT-001", "A-1", "LIVEPI-WALLET-001"])
def test_valid_rule_ids(rid: str) -> None:
    assert _rule(id=rid).id == rid


def test_condition_zero_heads() -> None:
    with pytest.raises(ValidationError):
        Condition.model_validate({})


def test_condition_two_heads() -> None:
    with pytest.raises(ValidationError):
        Condition.model_validate({"task_read_only": True, "ctx_untrusted": True})


def test_condition_arg_needs_op_and_op_needs_arg() -> None:
    with pytest.raises(ValidationError):
        Condition.model_validate({"arg": "amount"})
    with pytest.raises(ValidationError):
        Condition.model_validate({"task_read_only": True, "op": "eq"})


def test_condition_arg_origin_needs_exactly_one_list() -> None:
    with pytest.raises(ValidationError):
        Condition.model_validate({"arg_origin": "to"})
    with pytest.raises(ValidationError):
        Condition.model_validate({"arg_origin": "to", "in": ["USER_TYPED"], "not_in": ["UNKNOWN"]})
    ok = Condition.model_validate({"arg_origin": "to", "in": ["USER_TYPED"]})
    assert ok.head == "arg_origin"


def test_condition_nested_and_unknown_key() -> None:
    c = Condition.model_validate({"all": [{"not": {"task_allows_tool": True}}, {"any": [{"ctx_untrusted": True}]}]})
    assert c.head == "all" and c.all is not None and c.all[0].not_ is not None
    with pytest.raises(ValidationError):
        Condition.model_validate({"bogus": 1})
    with pytest.raises(ValidationError):
        Condition.model_validate({"all": []})


def test_relax_only_on_allow_and_sys_ids() -> None:
    with pytest.raises(ValidationError):
        _rule(effect="review", relax=["SYS-PROV-NAMED"])
    with pytest.raises(ValidationError):
        _rule(effect="allow", relax=["POL-SEC-001"])
    with pytest.raises(ValidationError):
        _rule(effect="allow", relax=["SYS-PROV-UNTRUSTED"])  # not relaxable
    r = _rule(effect="allow", relax=["SYS-PROV-NAMED"])
    assert r.relax == ("SYS-PROV-NAMED",)


def test_defaults_flat_keys_and_unknown_side_effect() -> None:
    d = Defaults.model_validate({"unknown_tool": "block", "read": "allow", "exec": "block"})
    assert d.verdict_for(SideEffect.EXEC) == Verdict.BLOCK
    assert d.verdict_for(SideEffect.CONFIG) == Verdict.BLOCK  # falls back to built-in default
    assert d.verdict_for(SideEffect.INSTALL) == Verdict.REVIEW
    with pytest.raises(ValidationError):
        Defaults.model_validate({"teleport": "allow"})


def test_policy_named_effect_and_unknown_key() -> None:
    p = Policy.model_validate({"version": 1, "policy_id": "p"})
    assert p.named_effect(SideEffect.PAYMENT) == Verdict.REVIEW
    assert p.named_effect(SideEffect.WRITE) == Verdict.ALLOW
    with pytest.raises(ValidationError):
        Policy.model_validate({"version": 1, "policy_id": "p", "named_source_effect": {"teleport": "allow"}})
    with pytest.raises(ValidationError):
        Policy.model_validate({"version": 2, "policy_id": "p"})


def test_duplicate_rule_ids_rejected() -> None:
    r = {"id": "POL-X-001", "description": "d", "effect": "block"}
    with pytest.raises(ValidationError):
        Policy.model_validate({"version": 1, "policy_id": "p", "rules": [r, r]})


def test_frozen() -> None:
    p = Policy.model_validate({"version": 1, "policy_id": "p"})
    with pytest.raises(ValidationError):
        p.policy_id = "q"  # type: ignore[misc]
