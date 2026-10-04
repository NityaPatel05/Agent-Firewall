"""Metric definitions (PLAN §9.4) and bootstrap CIs on small known examples."""

from __future__ import annotations

import math

from firewall.core.models import Verdict
from firewall.eval.metrics import compute_metrics, in_subset
from firewall.eval.records import DecisionLite, EpisodeResult
from firewall.eval.stats import bootstrap_ci


def _ep(sid: str, kind: str, **kw: object) -> EpisodeResult:
    base: dict[str, object] = {
        "run_id": "r", "scenario_id": sid, "kind": kind, "suite": "s", "category": "c", "defense": "GW",
        "mode": "offline", "model": "scripted", "approver": "oracle", "seed": 0,
        "attack_success": None if kind == "benign" else False, "utility": True,
        "intermediate": None if kind == "benign" else True}
    base.update(kw)
    return EpisodeResult.model_validate(base)


def test_rates_and_twins() -> None:
    eps = [
        _ep("A01", "attack", twin="B34", n_consequential=2, n_review=1),
        _ep("A02", "attack", attack_success=True, utility=False, n_consequential=1),
        _ep("B34", "benign", n_tool_calls=4, n_review=1, n_review_approved=1, n_consequential=1),
        _ep("B02", "benign", n_tool_calls=6, n_block=1, utility=False, n_consequential=2,
            decisions=[DecisionLite(call_id="c", tool="t", verdict=Verdict.BLOCK, eval_us=100.0)]),
    ]
    (a,) = compute_metrics(eps, subset="A")
    assert a.n_attack == 2 and a.asr == 0.5 and a.ua == 0.5 and a.intermediate_asr == 1.0
    assert a.twin_separation == 1.0
    (b,) = compute_metrics(eps, subset="B")
    assert b.n_benign == 2 and b.bu == 0.5 and b.n_benign_calls == 10
    assert b.review_rate == 0.1 and b.block_rate == 0.1 and math.isclose(b.interruption_rate or 0, 0.2)
    assert b.derail_rate == 0.5 and b.eval_us_p50 == 100.0
    (all_,) = compute_metrics(eps)
    assert all_.nrp == 0.5 * (1 - 0.5)
    assert all_.autonomy == (6 - 2) / 6
    rows = compute_metrics([*eps, _ep("A03", "attack", defense="B0", attack_success=True)], subset="A")
    assert [r.group["defense"] for r in rows] == ["B0", "GW"]


def test_subsets() -> None:
    assert in_subset("A07", "A") and not in_subset("A07", "B") and not in_subset("LP-x-y", "A")
    assert in_subset("LP-group_message-inbox_exfil", "LP") and in_subset("PB-x-3", "PB")
    assert in_subset("T03B", "T") and in_subset("anything", "all")


def test_bootstrap_ci() -> None:
    lo, hi = bootstrap_ci([True, False] * 50, n=2000)
    assert 0.38 < lo < 0.5 < hi < 0.62
    assert bootstrap_ci([0, 0, 0]) == (0.0, 0.0)
    assert bootstrap_ci([1.0]) == (1.0, 1.0)
    assert all(math.isnan(x) for x in bootstrap_ci([]))
    assert bootstrap_ci([0, 1, 1, 0, 1], seed=3) == bootstrap_ci([0, 1, 1, 0, 1], seed=3)
