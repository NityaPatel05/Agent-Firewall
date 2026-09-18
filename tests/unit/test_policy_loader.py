from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest
import yaml
from policy_helpers import REG
from pydantic import ValidationError

from firewall.core.models import SideEffect, Verdict
from firewall.core.policy.loader import (
    PolicyError,
    load_policy,
    main,
    merge_policies,
    packaged_policy_files,
    policy_json_schema,
    schema_text,
)
from firewall.core.policy.model import Policy
from firewall.resources import data_path


def _write(dir_: Path, name: str, body: dict) -> Path:
    p = dir_ / f"{name}.yaml"
    p.write_text(yaml.safe_dump(body, sort_keys=False), encoding="utf-8")
    return p


BASE = {
    "version": 1,
    "policy_id": "base",
    "defaults": {"exec": "review"},
    "allowlists": {"http_hosts": ["a.example"]},
    "canaries": ["C1"],
    "rules": [
        {"id": "P-A-001", "description": "a", "effect": "review", "match": {"tools": ["send_email"]}},
        {"id": "P-B-001", "description": "b", "effect": "block", "match": {"tools": ["send_money"]}},
    ],
}


def test_extends_merge_override_union(tmp_path: Path) -> None:
    _write(tmp_path, "base", BASE)
    child = _write(tmp_path, "child", {
        "version": 1, "policy_id": "child", "extends": "base",
        "defaults": {"exec": "block"},
        "allowlists": {"http_hosts": ["b.example"]},
        "canaries": ["C2"],
        "rules": [
            {"id": "P-A-001", "description": "a2", "effect": "allow", "match": {"tools": ["send_email"]}},
            {"id": "P-C-001", "description": "c", "effect": "review", "match": {"tools": ["delete_file"]}},
        ],
    })
    cp = load_policy(child, registry=REG)
    pol = cp.policy
    assert [r.id for r in pol.rules] == ["P-A-001", "P-B-001", "P-C-001"]
    assert pol.rules[0].effect == Verdict.ALLOW and pol.rules[0].description == "a2"
    assert pol.allowlists.http_hosts == frozenset({"a.example", "b.example"})
    assert pol.canaries == ("C1", "C2")
    assert pol.defaults.verdict_for(SideEffect.EXEC) == Verdict.BLOCK
    assert pol.policy_id == "child"


def test_extends_cycle_detected(tmp_path: Path) -> None:
    _write(tmp_path, "a", {"version": 1, "policy_id": "a", "extends": "b"})
    b = _write(tmp_path, "b", {"version": 1, "policy_id": "b", "extends": "a"})
    with pytest.raises(PolicyError, match="cycle"):
        load_policy(b, registry=REG)


def test_diamond_extends_loads_base_once(tmp_path: Path) -> None:
    _write(tmp_path, "base", BASE)
    _write(tmp_path, "l", {"version": 1, "policy_id": "l", "extends": "base",
                           "rules": [{"id": "L-1", "description": "l", "effect": "review"}]})
    _write(tmp_path, "r", {"version": 1, "policy_id": "r", "extends": "base",
                           "rules": [{"id": "R-1", "description": "r", "effect": "review"}]})
    top = _write(tmp_path, "top", {"version": 1, "policy_id": "top", "extends": ["l", "r"]})
    ids = [r.id for r in load_policy(top, registry=REG).policy.rules]
    assert ids == ["P-A-001", "P-B-001", "L-1", "R-1"]


def test_strict_refs_unknown_tool(tmp_path: Path) -> None:
    p = _write(tmp_path, "bad", {"version": 1, "policy_id": "bad", "rules": [
        {"id": "P-Z-001", "description": "z", "effect": "block", "match": {"tools": ["format_disk"]}}]})
    with pytest.raises(PolicyError, match="format_disk"):
        load_policy(p, registry=REG)
    assert load_policy(p, registry=REG, strict_refs=False).policy.rules[0].id == "P-Z-001"


def test_invalid_policy_file(tmp_path: Path) -> None:
    p = _write(tmp_path, "bad", {"version": 1, "policy_id": "bad", "rules": [{"id": "bad id", "description": "x",
                                                                            "effect": "block"}]})
    with pytest.raises(PolicyError):
        load_policy(p, registry=REG)
    with pytest.raises(PolicyError):
        load_policy("does_not_exist", registry=REG)


def test_bad_regex_rejected(tmp_path: Path) -> None:
    p = _write(tmp_path, "rx", {"version": 1, "policy_id": "rx", "rules": [
        {"id": "P-R-001", "description": "r", "effect": "block",
         "when": {"arg": "body", "op": "regex", "value": "(unclosed"}}]})
    with pytest.raises(PolicyError, match="bad pattern"):
        load_policy(p, registry=REG)


def test_hash_stable_and_sensitive(tmp_path: Path) -> None:
    a = load_policy("all", registry=REG)
    b = load_policy("all", registry=REG)
    assert a.hash == b.hash and len(a.hash) == 64
    _write(tmp_path, "base", BASE)
    h1 = load_policy(tmp_path / "base.yaml", registry=REG).hash
    changed = dict(BASE, canaries=["C9"])
    _write(tmp_path, "base", changed)
    assert load_policy(tmp_path / "base.yaml", registry=REG).hash != h1


def test_compiled_policy_frozen() -> None:
    cp = load_policy("default", registry=REG)
    with pytest.raises(dataclasses.FrozenInstanceError):
        cp.hash = "x"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        cp.policy.mode = "shadow"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        cp.policy.allowlists.http_hosts.add("evil.com")  # type: ignore[attr-defined]


def test_every_packaged_policy_loads() -> None:
    files = packaged_policy_files()
    assert {f.stem for f in files} >= {"default", "banking", "workspace", "slack", "travel", "web", "files", "mcp",
                                       "exec", "livepi", "all"}
    for f in files:
        load_policy(f, registry=REG)


def test_all_contains_every_pack() -> None:
    ids = {r.id for r in load_policy("all", registry=REG).policy.rules}
    for prefix in ("POL-", "BANK-", "WS-", "SLACK-", "TRAVEL-", "WEB-", "FILES-", "MCP-", "EXEC-", "LIVEPI-"):
        assert any(i.startswith(prefix) for i in ids), prefix


def test_default_matches_plan() -> None:
    pol = load_policy("default", registry=REG).policy
    assert [r.id for r in pol.rules] == ["POL-SEC-001", "POL-PRIV-001", "POL-PRIV-002", "POL-EGRESS-BULK-001",
                                         "POL-RO-001", "POL-SCOPE-001", "POL-POLICY-001", "POL-CB-001"]
    assert pol.defaults.verdict_for(SideEffect.CONFIG) == Verdict.BLOCK
    assert pol.circuit_breaker.max_blocks == 3 and pol.egress_budget.max_external_fetches_per_host == 20


def test_rules_for_index() -> None:
    cp = load_policy("all", registry=REG)
    spec = REG.get("send_money")
    assert spec is not None
    ids = {r.id for r in cp.rules_for(spec)}
    assert {"BANK-AMT-001", "BANK-RATE-001", "POL-SEC-001", "POL-RO-001"} <= ids
    assert "BANK-PWD-001" not in ids and "POL-POLICY-001" not in ids
    read = REG.get("read_email")
    assert read is not None and not {r.id for r in cp.rules_for(read)} & {"POL-RO-001", "POL-SEC-001"}


def test_merge_policies_api() -> None:
    parent = Policy.model_validate(BASE)
    child = Policy.model_validate({"version": 1, "policy_id": "c", "allowlists": {"http_hosts": ["z.example"]}})
    merged = merge_policies(parent, child)
    assert merged.allowlists.http_hosts == frozenset({"a.example", "z.example"})
    assert merged.policy_id == "c" and len(merged.rules) == 2


def test_exported_schema_matches_committed() -> None:
    committed = data_path("policies", "policy.schema.json").read_text(encoding="utf-8")
    assert committed == schema_text(), "run: python -m firewall.core.policy.loader --export-schema ..."
    assert json.loads(committed) == policy_json_schema()


def test_cli_validate(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--validate"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("OK ") and "all=" in out
