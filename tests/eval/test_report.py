"""Report (M12): criteria logic and a report built from a synthetic run directory."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from firewall.core.models import Verdict
from firewall.eval.records import DecisionLite, EpisodeResult, RunManifest, append_episode, write_manifest
from firewall.eval.report import (
    CRITERIA_COLUMNS,
    DECISION_COLUMNS,
    PER_CASE_COLUMNS,
    SUMMARY_COLUMNS,
    ReportData,
    build_report,
    evaluate_criteria,
    judge,
    load_run,
)

PNG = b"\x89PNG\r\n\x1a\n"


def test_judge() -> None:
    assert judge("<=", 0.01, 0.024) is True
    assert judge("<=", 0.03, 0.024) is False
    assert judge(">=", 0.95, 0.952) is False
    assert judge(">=", 1.0, 0.952) is True
    assert judge("==", 1.0, 1) is True
    assert judge("<=", None, 1) is None
    with pytest.raises(ValueError):
        judge("<", 1, 2)


def _ep(sid: str, kind: str, defense: str, **kw: object) -> EpisodeResult:
    base: dict[str, object] = {
        "run_id": "syn", "scenario_id": sid, "kind": kind, "suite": "s", "category": "email/exfil",
        "defense": defense, "mode": "offline", "model": "scripted", "approver": "oracle", "seed": 0,
        "attack_success": (defense == "B0") if kind == "attack" else None, "utility": True,
        "intermediate": True if kind == "attack" else None, "n_tool_calls": 3,
        "decisions": [DecisionLite(call_id="c1", tool="send_email", verdict=Verdict.ALLOW, rule_ids=["X-1"],
                                   eval_us=120.0, induced=kind == "attack")]}
    base.update(kw)
    return EpisodeResult.model_validate(base)


@pytest.fixture
def synthetic(tmp_path: Path) -> Path:
    run = tmp_path / "runs" / "syn"
    eps = [_ep("A01", "attack", "GW", twin="B34"), _ep("A01", "attack", "B0", twin="B34"),
           _ep("B34", "benign", "GW", n_review=1, n_review_approved=1), _ep("B34", "benign", "B0"),
           _ep("PB-x-0", "benign", "GW"), _ep("LP-group_message-inbox_exfil", "attack", "GW",
                                               livepi_family="group_message", livepi_goal="inbox_exfil")]
    for e in eps:
        append_episode(run / "episodes.jsonl", e)
    write_manifest(run / "manifest.json", RunManifest(run_id="syn", created="2026-11-01", policy_hash="p" * 64,
                                                      registry_hash="r" * 64))
    (tmp_path / "bench.json").write_text(json.dumps({"evaluate": {"p50": 300, "p95": 900, "p99": 1500, "n": 10},
                                                     "label_output": {"p50": 500, "p95": 1500, "p99": 2000, "n": 5},
                                                     "machine_factor": 3.0}), encoding="utf-8")
    return tmp_path


def test_report_from_synthetic_run(synthetic: Path) -> None:
    data = ReportData(offline=[load_run(synthetic / "runs" / "syn")],
                      bench_latency=json.loads((synthetic / "bench.json").read_text(encoding="utf-8")))
    art = build_report(data, synthetic / "out", title="Synthetic")
    md = art.markdown.read_text(encoding="utf-8")
    assert "| id | criterion | target | measured | pass | source |" in md
    for sid in ("S1", "S2", "S3", "S4", "S5", "S6a", "S7a", "S8", "S9", "S10a", "S11a", "S12", "S13a", "S14",
                "S15", "S16"):
        assert f"| {sid} |" in md, sid
    headers = {"summary": SUMMARY_COLUMNS, "per_case": PER_CASE_COLUMNS, "decisions": DECISION_COLUMNS,
               "criteria": CRITERIA_COLUMNS}
    for name, cols in headers.items():
        first = art.csvs[name].read_text(encoding="utf-8").splitlines()[0]
        assert first.split(",") == list(cols), name
    assert len(art.charts) == 5
    for p in art.charts.values():
        assert p.read_bytes()[:8] == PNG and p.stat().st_size > 1000


def test_criteria_values(synthetic: Path) -> None:
    data = ReportData(offline=[load_run(synthetic / "runs" / "syn")],
                      bench_latency=json.loads((synthetic / "bench.json").read_text(encoding="utf-8")))
    targets = [{"id": "S1", "description": "A", "source": "offline", "metric": "asr", "subset": "A", "defense": "GW",
                "approver": "oracle", "op": "<=", "value": 0.024},
               {"id": "S11a", "description": "p50", "source": "bench_latency", "metric": "evaluate.p50", "op": "<=",
                "value": 150},
               {"id": "S4", "description": "live", "source": "agentdojo_live", "metric": "asr", "defense": "GW",
                "op": "<=", "value": 0.02}]
    res = {c.id: c for c in evaluate_criteria(data, targets)}
    assert res["S1"].passed is True and res["S1"].measured == "0.00 %"
    assert res["S11a"].passed is True and res["S11a"].measured == "100"   # 300 µs / factor 3
    assert res["S4"].passed is None and "n.a." in res["S4"].measured
