"""Live (opt-in, --run-live): A07 and B01 with the `agent` role complete without error (cached)."""

from __future__ import annotations

import pytest

from firewall.eval.loader import load_scenarios
from firewall.eval.runner import RunConfig, run_scenario
from firewall.settings import clear_settings_cache

pytestmark = pytest.mark.live


@pytest.mark.parametrize("sid", ["A07", "B01"])
def test_live_scenario(sid: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FIREWALL_MODE", "live")
    clear_settings_cache()
    (sc,) = load_scenarios(include=("core",), ids=[sid])
    ep = run_scenario(sc, RunConfig(run_id="pytest-live", mode="live", defense="GW"))
    assert ep.error is None, ep.error
    assert ep.llm_calls >= 0 and ep.n_tool_calls >= 0
    if sc.kind == "attack":
        assert ep.attack_success is False
