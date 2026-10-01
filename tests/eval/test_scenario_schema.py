"""Scenario YAML: counts, unique ids, twins, tools and oracle names all resolve."""

from __future__ import annotations

import pytest

from firewall.agent.tools import default_registry
from firewall.agent.world import get_path
from firewall.eval.loader import ScenarioLoadError, load_scenarios, validate
from firewall.eval.oracles import ORACLES
from firewall.eval.scenario import Scenario

TWINS = {"A01": "B34", "A05": "B08", "A07": "B21", "A09": "B35", "A18": "B41", "A22": "B17", "A23": "B14",
         "A33": "B16", "A42": "B18"}


@pytest.fixture(scope="module")
def core() -> list[Scenario]:
    return load_scenarios(include=("core", "extra"))


def test_counts(core: list[Scenario]) -> None:
    a = [s for s in core if s.id[0] == "A"]
    b = [s for s in core if s.id[0] == "B"]
    t = [s for s in core if s.id[0] == "T"]
    assert len(a) >= 42 and all(s.kind == "attack" for s in a)
    assert len(b) >= 42 and all(s.kind == "benign" for s in b)
    assert {s.id for s in t if s.kind == "attack"} == {"T03", "T04", "T06", "T09", "T10", "T11", "T13"}


def test_twins(core: list[Scenario]) -> None:
    by_id = {s.id: s for s in core}
    for a, b in TWINS.items():
        assert by_id[a].twin == b and by_id[b].kind == "benign"


def test_script_tools_exist_and_oracles_known(core: list[Scenario]) -> None:
    reg = default_registry()

    def oracle_names(spec: object) -> list[str]:
        check, params = spec.check, spec.params  # type: ignore[attr-defined]
        nested = [n for c in params.get("checks", []) for n in [c["check"]]] if check in ("all_of", "any_of") else []
        return [check, *nested]

    for sc in core:
        for step in sc.script:
            if step.kind == "call":
                assert reg.get(step.tool) is not None, f"{sc.id}: unknown tool {step.tool}"
        specs = [*sc.utility_oracles, *([sc.attack_oracle] if sc.attack_oracle else [])]
        for spec in specs:
            for name in oracle_names(spec):
                assert name in ORACLES, f"{sc.id}: unknown oracle {name}"


def test_worlds_build_and_injections_land(core: list[Scenario]) -> None:
    for sc in core:
        data = sc.build_world().model_dump(mode="json")
        for inj in sc.injections:
            loc = inj.location
            value = get_path(data, loc[:-3])[-1] if loc.endswith("[+]") else get_path(data, loc)
            assert inj.text in str(value), (sc.id, loc)


def test_validators() -> None:
    base = {"id": "X1", "suite": "s", "category": "c", "title": "t", "user_prompt": "p",
            "expected": {"gate": "allow"}}
    with pytest.raises(ValueError, match="induced"):
        Scenario.model_validate({**base, "kind": "benign", "script": [{"tool": "get_balance", "induced": True}]})
    with pytest.raises(ValueError, match="attack_oracle"):
        Scenario.model_validate({**base, "kind": "attack", "script": [{"tool": "get_balance", "induced": True}]})
    sc = Scenario.model_validate({**base, "kind": "attack", "attack_oracle": {"check": "firewall_disabled"},
                                  "script": [{"tool": "update_firewall_settings", "induced": True}]})
    assert sc.attack_tools == ("update_firewall_settings",)
    with pytest.raises(ScenarioLoadError, match="duplicate"):
        validate([sc, sc])
    with pytest.raises(ScenarioLoadError, match="twin"):
        validate([sc.model_copy(update={"twin": "NOPE"})])


def test_filters() -> None:
    only = load_scenarios(include=("core",), ids=["A07", "B01"])
    assert [s.id for s in only] == ["A07", "B01"]
    assert all(s.suite == "banking" for s in load_scenarios(include=("core",), suites=["banking"]))
