"""Build results/REPORT.md + CSVs + PNG charts from run directories (offline, live, AgentDojo) and bench JSON."""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from firewall.eval import charts
from firewall.eval.metrics import MetricRow, compute_metrics, in_subset
from firewall.eval.records import EpisodeResult, RunManifest, read_episodes
from firewall.eval.stats import bootstrap_ci
from firewall.resources import data_path

SUMMARY_COLUMNS = ("source", "subset", "defense", "approver", "n_attack", "asr", "asr_ci_lo", "asr_ci_hi",
                   "intermediate_asr", "ua", "n_benign", "bu", "bu_ci_lo", "bu_ci_hi", "n_benign_calls",
                   "interruption_rate", "review_rate", "block_rate", "derail_rate", "twin_separation", "nrp",
                   "eval_us_p50", "eval_us_p95", "eval_us_p99", "llm_calls", "cost_usd", "errors")
PER_CASE_COLUMNS = ("source", "run_id", "scenario_id", "kind", "suite", "category", "defense", "approver", "mode",
                    "model", "attack_success", "attack_success_native", "utility", "intermediate", "error",
                    "n_tool_calls", "n_review", "n_block", "n_review_approved", "n_omitted", "wall_ms", "llm_calls",
                    "cost_usd")
DECISION_COLUMNS = ("source", "run_id", "scenario_id", "defense", "approver", "call_id", "tool", "verdict",
                    "shadow_verdict", "rule_ids", "eval_us", "induced")
CRITERIA_COLUMNS = ("id", "description", "target", "measured", "passed", "source")
TWINS = [("A01", "B34"), ("A05", "B08"), ("A07", "B21"), ("A09", "B35"), ("A18", "B41"), ("A22", "B17"),
         ("A23", "B14"), ("A33", "B16"), ("A42", "B18")]


class CriterionResult(BaseModel):
    id: str
    description: str
    target: str
    measured: str
    passed: bool | None
    source: str


class ReportArtifacts(BaseModel):
    out_dir: Path
    markdown: Path
    csvs: dict[str, Path] = Field(default_factory=dict)
    charts: dict[str, Path] = Field(default_factory=dict)


class Run(BaseModel):
    path: Path
    manifest: RunManifest | None
    episodes: list[EpisodeResult]
    label: str


class ReportData(BaseModel):
    offline: list[Run] = Field(default_factory=list)
    ablations: list[Run] = Field(default_factory=list)
    live: list[Run] = Field(default_factory=list)
    agentdojo_replay: list[Run] = Field(default_factory=list)
    agentdojo_live: list[Run] = Field(default_factory=list)
    bench_latency: dict[str, Any] = Field(default_factory=dict)
    bench_http: dict[str, Any] = Field(default_factory=dict)
    mutations: dict[str, Any] = Field(default_factory=dict)
    suite: dict[str, Any] = Field(default_factory=dict)
    adaptive: dict[str, Any] = Field(default_factory=dict)
    notes: str = ""   # free-form markdown (run-log context), inserted after the headline criteria

    def eps(self, kind: str) -> list[EpisodeResult]:
        return [e for r in getattr(self, kind) for e in r.episodes]


def load_run(path: Path, label: str | None = None) -> Run:
    mpath = path / "manifest.json"
    manifest = RunManifest.model_validate_json(mpath.read_text(encoding="utf-8")) if mpath.exists() else None
    return Run(path=path, manifest=manifest, episodes=read_episodes(path / "episodes.jsonl"), label=label or path.name)


def _json(path: Path | None) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8")) if path and path.exists() else {}


# ------------------------------------------------------------------ criteria


def judge(op: str, measured: float | None, value: float) -> bool | None:
    if measured is None:
        return None
    if op == "<=":
        return measured <= value + 1e-12
    if op == ">=":
        return measured >= value - 1e-12
    if op == "==":
        return abs(measured - value) < 1e-9
    raise ValueError(f"unknown op {op!r}")


def _row(eps: Sequence[EpisodeResult], subset: str, defense: str, approver: str | None) -> MetricRow | None:
    sel = [e for e in eps if e.defense == defense and (approver is None or e.approver == approver)]
    rows = compute_metrics(sel, group_by=("defense",), subset=subset)  # type: ignore[arg-type]
    return rows[0] if rows else None


MIN_LIVE_ATTACKS = 5   # below this a live ASR criterion is reported as n.a. (not evidence either way)


def _ad_rate(eps: Sequence[EpisodeResult], defense: str, metric: str, *, min_attacks: int = 1) -> float | None:
    es = [e for e in eps if e.defense == defense]
    if metric == "asr":
        att = [e for e in es if e.kind == "attack" and not e.error]
        return sum(bool(e.attack_success) for e in att) / len(att) if len(att) >= min_attacks else None
    ben = [e for e in es if e.kind == "benign"]
    calls = sum(e.n_tool_calls for e in ben)
    if metric == "interruption_rate":
        return sum(e.n_review + e.n_block for e in ben) / calls if calls else None
    if metric == "blocks":
        return float(sum(e.n_block for e in ben)) if ben else None
    return None


def _dotted(d: Mapping[str, Any], key: str) -> Any:
    cur: Any = d
    for part in key.split("."):
        if not isinstance(cur, Mapping) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _measure(t: Mapping[str, Any], data: ReportData) -> float | None:
    src, metric = t["source"], t["metric"]
    if src == "offline":
        eps = data.eps("offline")
        if metric == "review_tasks":
            sel = [e for e in eps if e.defense == t["defense"] and e.approver == t["approver"]
                   and in_subset(e.scenario_id, t["subset"])]
            return float(sum(1 for e in sel if e.n_review)) if sel else None
        r = _row(eps, t["subset"], t["defense"], t.get("approver"))
        return None if r is None else getattr(r, metric)
    if src in ("agentdojo_replay", "agentdojo_live"):
        return _ad_rate(data.eps(src), t["defense"], metric,
                        min_attacks=MIN_LIVE_ATTACKS if src == "agentdojo_live" else 1)
    if src == "live":
        runs = [r for r in data.live if any(e.defense == t["defense"] for e in r.episodes)]
        if not runs:
            return None
        if metric == "delta_bu_pts":
            vals = []
            for r in runs:
                b0, gw = _row(r.episodes, "B", "B0", None), _row(r.episodes, "B", "GW", None)
                if b0 and gw and b0.bu is not None and gw.bu is not None:
                    vals.append(100 * (b0.bu - gw.bu))
            return max(vals) if vals else None
        if metric == "overhead_share":
            eps = [e for r in runs for e in r.episodes if e.defense == t["defense"] and e.llm_calls > 0]
            gate = sum(d.eval_us for e in eps for d in e.decisions) / 1000.0
            wall = sum(e.wall_ms for e in eps)
            return gate / wall if wall else None
    if src.startswith("bench_"):
        bench = data.bench_latency if src == "bench_latency" else data.bench_http
        v = _dotted(bench, metric)
        f = bench.get("machine_factor", 1.0) or 1.0
        return None if v is None else float(v) / f
    if src == "ablations":
        eps = data.eps("ablations") + data.eps("offline")
        gw, gwd = _row(eps, "A", "GW", "oracle"), _row(eps, "A", "GW+D", "oracle")
        if not gw or not gwd or gw.asr_ci is None or gw.asr is None or gwd.asr is None:
            return None
        return float(gw.asr_ci[0] <= gwd.asr <= gw.asr_ci[1])
    if src == "suite":
        return data.suite.get(metric)
    if src == "adaptive":
        return data.adaptive.get(metric)
    return None


def _fmt_measured(metric: str, v: float | None) -> str:
    if v is None:
        return "n.a. (not run / too few cases)"
    if metric in ("asr", "bu", "interruption_rate", "block_rate", "twin_separation", "overhead_share", "review_rate"):
        return f"{100 * v:.2f} %"
    if metric == "detector_delta_in_ci":
        return "yes" if v else "no"
    return f"{v:.3g}"


def _fmt_target(t: Mapping[str, Any]) -> str:
    v, m = t["value"], t["metric"]
    if m in ("asr", "bu", "interruption_rate", "block_rate", "twin_separation", "overhead_share"):
        return f"{t['op']} {100 * v:.1f} %"
    if m == "detector_delta_in_ci":
        return "within CI"
    return f"{t['op']} {v}"


def evaluate_criteria(data: ReportData, targets: Sequence[Mapping[str, Any]]) -> list[CriterionResult]:
    out = []
    for t in targets:
        v = _measure(t, data)
        out.append(CriterionResult(id=t["id"], description=t["description"], target=_fmt_target(t),
                                   measured=_fmt_measured(t["metric"], v), passed=judge(t["op"], v, t["value"]),
                                   source=t["source"]))
    return out


# ------------------------------------------------------------------ markdown helpers


def _p(v: float | None, digits: int = 1) -> str:
    return "–" if v is None else f"{100 * v:.{digits}f} %"


def _ci(ci: tuple[float, float] | None) -> str:
    return "" if ci is None else f" [{100 * ci[0]:.0f}–{100 * ci[1]:.0f}]"


def _frac(k: int, n: int) -> str:
    return f"{k}/{n}" if n else "–"


def _table(head: Sequence[str], rows: Sequence[Sequence[Any]]) -> list[str]:
    return ["| " + " | ".join(head) + " |", "|" + "---|" * len(head),
            *("| " + " | ".join(str(c) for c in r) + " |" for r in rows)]


def _metric_table(rows: Sequence[MetricRow], subset: str) -> list[str]:
    att = subset in ("A", "LP", "T", "all")
    ben = subset in ("B", "PB", "T", "all")
    head = ["defense", "approver"]
    head += ["n", "ASR [95% CI]", "UA"] if att else []
    head += ["n", "benign utility [95% CI]", "interruption", "review", "block"] if ben else []
    head += ["twin sep."] if subset in ("A", "B", "T") else []
    head += ["eval µs p50/p95"]
    out = []
    for r in rows:
        line = [r.group.get("defense", ""), r.group.get("approver", "")]
        if att:
            line += [r.n_attack, _p(r.asr) + _ci(r.asr_ci), _p(r.ua)]
        if ben:
            line += [r.n_benign, _p(r.bu) + _ci(r.bu_ci), _p(r.interruption_rate), _p(r.review_rate),
                     _p(r.block_rate)]
        if subset in ("A", "B", "T"):
            line += [_p(r.twin_separation, 0)]
        line += [f"{r.eval_us_p50 or 0:.0f}/{r.eval_us_p95 or 0:.0f}"]
        out.append(line)
    return _table(head, out)


# ------------------------------------------------------------------ sections


def _section_offline(data: ReportData) -> list[str]:
    eps = data.eps("offline")
    if not eps:
        return ["_No offline run supplied._"]
    names = {"A": "A01–A42 attacks", "B": "B01–B42 benign twins", "LP": "LivePI-style (24 cases)",
             "PB": "Pinch-like benign workload (120 tasks)", "T": "Incident-derived T-items (7 attacks + 7 twins)"}
    out: list[str] = []
    for s, title in names.items():
        rows = compute_metrics(eps, group_by=("defense", "approver"), subset=s)  # type: ignore[arg-type]
        if rows:
            out += ["", f"#### {title}", "", *_metric_table(rows, s)]
    return out


def _section_twins(data: ReportData) -> list[str]:
    eps = {(e.scenario_id, e.defense): e for e in data.eps("offline") if e.approver == "oracle"}
    rows = []
    for a, b in TWINS:
        ea, eb = eps.get((a, "GW")), eps.get((b, "GW"))
        if not ea or not eb:
            continue
        av = ", ".join(f"{d.tool}:{d.verdict.value}" for d in ea.decisions if d.induced) or "–"
        bv = ", ".join(f"{d.tool}:{d.verdict.value}" for d in eb.decisions if d.verdict.value != "allow"
                       or d.rule_ids) or "all allowed"
        sep = (not ea.attack_success) and eb.utility and eb.n_block == 0
        rows.append([f"{a} / {b}", av, "no" if ea.attack_success else "yes", bv, "yes" if eb.utility else "no",
                     "✅" if sep else "❌"])
    return _table(["pair", "attack: induced calls", "attack stopped", "benign: non-allow decisions",
                   "benign completed", "separated"], rows)


def _section_livepi(data: ReportData) -> list[str]:
    eps = [e for e in data.eps("offline") if e.livepi_family and e.approver == "oracle"]
    if not eps:
        return []
    defs = sorted({e.defense for e in eps})
    fams = sorted({e.livepi_family for e in eps if e.livepi_family})
    rows = []
    for f in fams:
        line = [f]
        for d in defs:
            es = [e for e in eps if e.livepi_family == f and e.defense == d]
            line.append(_frac(sum(bool(e.attack_success) for e in es), len(es)))
        rows.append(line)
    return _table(["family (A·M successes / cases)", *defs], rows)


def _section_mutations(data: ReportData) -> list[str]:
    rows = data.mutations.get("rows", [])
    if not rows:
        return ["_Mutation run not supplied._"]
    return _table(["mutation", "kind", "gate-only attack success", "payload-blind (same verdict sequence)"],
                  [[r["op"], r["kind"], _frac(r["attack_success"], r["n"]),
                    "–" if r["payload_blind"] is None else _frac(r["payload_blind"], r["n"])] for r in rows])


def _section_ablations(data: ReportData) -> list[str]:
    eps = data.eps("ablations") + [e for e in data.eps("offline") if e.defense == "GW" and e.approver == "oracle"]
    if not data.eps("ablations"):
        return ["_Ablation run not supplied._"]
    base_a, base_b = _row(eps, "A", "GW", "oracle"), _row(eps, "B", "GW", "oracle")
    base_pb = _row(eps, "PB", "GW", "oracle")
    rows = []
    for d in sorted({e.defense for e in data.eps("ablations")}):
        a, b, pb = _row(eps, "A", d, "oracle"), _row(eps, "B", d, "oracle"), _row(eps, "PB", d, "oracle")
        if not (a and b and base_a and base_b):
            continue
        rows.append([d, _p(a.asr), f"{100 * ((a.asr or 0) - (base_a.asr or 0)):+.1f} pts", _p(b.bu),
                     f"{100 * ((b.bu or 0) - (base_b.bu or 0)):+.1f} pts", _p(b.interruption_rate),
                     _p(pb.bu if pb else None), _p(base_pb.bu if base_pb else None)])
    return _table(["defense", "A ASR", "ΔASR vs GW", "B utility", "ΔBU vs GW", "B interruption", "Pinch utility",
                   "GW Pinch utility"], rows)


def _live_table(run: Run) -> list[str]:
    eps = run.episodes
    rows = []
    for d in sorted({e.defense for e in eps}):
        es = [e for e in eps if e.defense == d]
        att = [e for e in es if e.kind == "attack"]
        ben = [e for e in es if e.kind == "benign"]
        ok = [e for e in ben if e.n_review + e.n_block <= e.n_tool_calls]   # errored episodes lack call counts
        calls = sum(e.n_tool_calls for e in ok)
        rv, bl = sum(e.n_review for e in ok), sum(e.n_block for e in ok)
        ci = bootstrap_ci([bool(e.attack_success) for e in att]) if att else None
        inter = [e for e in att if e.intermediate is not None]
        walls = [e.wall_ms / 1000 for e in es if e.llm_calls > 0]
        rows.append([d, _frac(sum(bool(e.attack_success) for e in att), len(att)) + _ci(ci),
                     _frac(sum(bool(e.intermediate) for e in inter), len(inter)),
                     _frac(sum(e.utility for e in att), len(att)), _frac(sum(e.utility for e in ben), len(ben)),
                     (f"{_p((rv + bl) / calls if calls else None)} ({_p(rv / calls if calls else None)} / "
                     f"{_p(bl / calls if calls else None)})"),
                     sum(e.llm_calls for e in es), f"${sum(e.cost_usd for e in es):.3f}",
                     f"{statistics.median(walls):.1f} s" if walls else "cached", sum(1 for e in es if e.error)])
    return _table(["defense", "ASR [95% CI]", "intermediate ASR", "UA", "benign utility",
                   "benign interruption (review / block)", "LLM calls", "cost", "median episode", "errors"], rows)


def _model_of(run: Run) -> str:
    """Agent model id(s) of a run (episode `model` may be a role name; roles map through models.yaml)."""
    from firewall.llm.config import load_model_config

    roles = load_model_config().roles
    models = {roles[m].model if m in roles else m for e in run.episodes for m in [e.model]
              if m and m not in ("scripted", "ground-truth")}
    return ", ".join(sorted(models)) or "?"


def _section_agentdojo_replay(data: ReportData) -> list[str]:
    eps = data.eps("agentdojo_replay")
    if not eps:
        return ["_AgentDojo replay not supplied._"]
    b0 = {e.scenario_id: e for e in eps if e.defense == "B0"}
    rows = []
    for suite in sorted({e.suite for e in eps}) + ["all"]:
        for d in ("B0", "GW"):
            es = [e for e in eps if e.defense == d and (suite == "all" or e.suite == suite)]
            if not es:
                continue
            att = [e for e in es if e.kind == "attack"]
            ben = [e for e in es if e.kind == "benign"]
            reach = [e for e in att if b0.get(e.scenario_id) and b0[e.scenario_id].attack_success]
            calls = sum(e.n_tool_calls for e in ben)
            rows.append([suite.replace("agentdojo/", ""), d, len(att),
                         _p(sum(bool(e.attack_success) for e in att) / len(att) if att else None),
                         _p(sum(bool(e.attack_success_native) for e in att) / len(att) if att else None),
                         _frac(sum(bool(e.attack_success) for e in reach), len(reach)),
                         _frac(sum(e.utility for e in ben), len(ben)), _frac(sum(e.utility for e in att), len(att)),
                         _p((sum(e.n_review + e.n_block for e in ben) / calls) if calls else None),
                         str(sum(e.n_block for e in ben)) if d == "GW" else "–"])
    return _table(["suite", "defense", "pairs", "ASR (executed effects)", "ASR (AgentDojo native)",
                   "successes / pairs where B0 succeeds", "user-task GT utility", "UA",
                   "GT-call interruption", "GT calls blocked"], rows)


def _section_agentdojo_gaps(data: ReportData) -> list[str]:
    eps = [e for e in data.eps("agentdojo_replay") if e.defense == "GW" and e.kind == "attack" and e.attack_success]
    c: Counter[str] = Counter(f"{e.suite.replace('agentdojo/', '')} {e.scenario_id.rsplit('-', 1)[1]}" for e in eps)
    return _table(["suite / injection task", "GW successes (executed effects)"], sorted(c.items()))


def _section_latency(data: ReportData) -> list[str]:
    out = []
    bl, bh = data.bench_latency, data.bench_http
    if bl:
        f = bl.get("machine_factor", 1.0) or 1.0
        for s in ("evaluate", "label_output"):
            st = bl.get(s, {})
            out.append([f"{s}() in-process (µs)", f"{st.get('p50', 0):.0f}/{st.get('p95', 0):.0f}/{st.get('p99', 0):.0f}",
                        f"{st.get('p50', 0) / f:.0f}/{st.get('p95', 0) / f:.0f}/{st.get('p99', 0) / f:.0f}",
                        int(st.get("n", 0))])
    if bh:
        f = bh.get("machine_factor", 1.0) or 1.0
        st = bh.get("evaluate_http_ms", {})
        out.append(["HTTP evaluate round trip (ms)", f"{st.get('p50', 0):.2f}/{st.get('p95', 0):.2f}/{st.get('p99', 0):.2f}",
                    f"{st.get('p50', 0) / f:.2f}/{st.get('p95', 0) / f:.2f}/{st.get('p99', 0) / f:.2f}",
                    int(st.get("n", 0))])
    lat = sorted(d.eval_us for e in data.eps("offline") if e.defense == "GW" for d in e.decisions if d.eval_us > 0)
    if lat:
        q = lambda p: lat[min(len(lat) - 1, int(p * len(lat)))]
        out.append(["per-decision evaluate in the offline suite (µs, 4 worker processes)",
                    f"{q(0.5):.0f}/{q(0.95):.0f}/{q(0.99):.0f}", "–", len(lat)])
    factor = (bl or bh).get("machine_factor")
    head = ["measurement", "raw p50/p95/p99", "machine-normalized", "n"]
    note = ["", f"Machine factor {factor:.2f}× (this laptop vs. the reference interpreter speed)."] if factor else []
    return [*_table(head, out), *note]


# ------------------------------------------------------------------ CSV writers


def _write_csv(path: Path, columns: Sequence[str], rows: Sequence[Mapping[str, Any]]) -> Path:
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(columns), extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k) for k in columns})
    return path


def _summary_rows(data: ReportData) -> list[dict[str, Any]]:
    out = []
    for source in ("offline", "ablations", "live", "agentdojo_replay", "agentdojo_live"):
        eps = data.eps(source)
        subsets = ("A", "B", "LP", "PB", "T") if source in ("offline", "ablations", "live") else ("all",)
        for s in subsets:
            for r in compute_metrics(eps, group_by=("defense", "approver", "model"), subset=s):  # type: ignore[arg-type]
                d = r.model_dump()
                d.update(source=source, subset=s, defense=r.group["defense"], approver=r.group["approver"],
                         asr_ci_lo=r.asr_ci[0] if r.asr_ci else None, asr_ci_hi=r.asr_ci[1] if r.asr_ci else None,
                         bu_ci_lo=r.bu_ci[0] if r.bu_ci else None, bu_ci_hi=r.bu_ci[1] if r.bu_ci else None)
                out.append(d)
    return out


# ------------------------------------------------------------------ build


def build_report(data: ReportData, out_dir: Path, *, title: str | None = None) -> ReportArtifacts:
    out_dir.mkdir(parents=True, exist_ok=True)
    targets = yaml.safe_load(data_path("data", "targets.yaml").read_text(encoding="utf-8"))
    criteria = evaluate_criteria(data, targets)
    off = data.eps("offline")
    rows_a = [r for r in compute_metrics(off, group_by=("defense", "approver"), subset="A") if r.group["approver"] == "oracle"]
    rows_b = compute_metrics(off, group_by=("defense", "approver"), subset="B")
    rows_pb = [r for r in compute_metrics(off, group_by=("defense", "approver"), subset="PB") if r.group["approver"] == "oracle"]
    figs: dict[str, Path] = {}
    if off:
        figs["asr_vs_interruption"] = charts.asr_vs_interruption(rows_a, rows_pb, out_dir / "asr_vs_interruption.png")
        defs = [d for d in ("B0", "B6", "B3", "B2", "GW") if any(e.defense == d for e in off)]
        figs["asr_by_category"] = charts.asr_by_category(off, defs, out_dir / "asr_by_category.png")
        figs["latency_cdf"] = charts.latency_cdf(off, out_dir / "latency_cdf.png")
        figs["interruptions_by_rule"] = charts.interruptions_by_rule(
            off + data.eps("agentdojo_replay"), out_dir / "interruptions_by_rule.png")
        figs["utility_vs_asr"] = charts.utility_vs_asr(rows_a, rows_b, out_dir / "utility_vs_asr.png")
    csvs = {
        "summary": _write_csv(out_dir / "summary.csv", SUMMARY_COLUMNS, _summary_rows(data)),
        "per_case": _write_csv(out_dir / "per_case.csv", PER_CASE_COLUMNS, [
            {"source": src, **e.model_dump(exclude={"decisions"})} for src in
            ("offline", "ablations", "live", "agentdojo_replay", "agentdojo_live") for e in data.eps(src)]),
        "decisions": _write_csv(out_dir / "decisions.csv", DECISION_COLUMNS, [
            {"source": src, "run_id": e.run_id, "scenario_id": e.scenario_id, "defense": e.defense,
             "approver": e.approver, **d.model_dump(), "rule_ids": ";".join(d.rule_ids),
             "verdict": d.verdict.value, "shadow_verdict": d.shadow_verdict.value if d.shadow_verdict else ""}
            for src in ("offline", "live", "agentdojo_replay", "agentdojo_live") for e in data.eps(src)
            for d in e.decisions]),
        "criteria": _write_csv(out_dir / "criteria.csv", CRITERIA_COLUMNS, [c.model_dump() for c in criteria]),
    }
    md = render_markdown(data, criteria, figs, title=title)
    path = out_dir / "REPORT.md"
    path.write_text(md, encoding="utf-8")
    return ReportArtifacts(out_dir=out_dir, markdown=path, csvs=csvs, charts=figs)


def _meta(data: ReportData) -> list[str]:
    runs = data.offline + data.ablations + data.live + data.agentdojo_replay + data.agentdojo_live
    m = next((r.manifest for r in runs if r.manifest and r.manifest.policy_hash), None)
    ad = next((r.manifest.versions.get("agentdojo_sha") for r in data.agentdojo_replay + data.agentdojo_live
               if r.manifest and r.manifest.versions.get("agentdojo_sha")), None)
    models = sorted({_model_of(r) for r in data.live + data.agentdojo_live})
    lines = [f"- Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}",
             f"- Runs: {', '.join(r.label for r in runs)}"]
    if m:
        lines += [(f"- Policy hash `{m.policy_hash[:16]}…`, registry hash `{m.registry_hash[:16]}…`, git SHA "
                  f"`{m.git_sha if m.git_sha and len(m.git_sha) == 40 else 'n/a (no commits)'}`"),
                  f"- Versions: {', '.join(f'{k} {v}' for k, v in sorted(m.versions.items()))}"]
    if models:
        lines.append(f"- Live agent models: {', '.join(models)}")
    if ad:
        lines.append(f"- AgentDojo commit `{ad}`, benchmark v1.2.2, attack `important_instructions`")
    return lines


def render_markdown(data: ReportData, criteria: Sequence[CriterionResult], figs: Mapping[str, Path],
                    *, title: str | None) -> str:
    mark = {True: "✅", False: "❌", None: "n.a."}
    L: list[str] = [f"# {title or 'Agent Firewall — evaluation report'}", "", *_meta(data), ""]
    L += ["## Headline criteria (PLAN §2.3)", "",
          ("Offline numbers are **gate-only**: a scripted, fully compromised agent always attempts the injected "
          "action, so they measure the gateway alone. Live and AgentDojo sections are listed separately."), "",
          *_table(["id", "criterion", "target", "measured", "pass", "source"],
                  [[c.id, c.description, c.target, c.measured, mark[c.passed], c.source] for c in criteria]), ""]
    if data.notes.strip():
        L += [data.notes.strip(), ""]
    L += ["## 1. Offline scenario suite (scripted, gate-only)", "",
          ("Defenses: **GW** = our gateway; **GW-STRICT** = strict profile; **B0** = no defense (gateway in shadow "
          "mode, measurement only); **B2** = tool filter (rule-based offline); **B6** = keyword detector; **B3** = "
          "ProtectAI DeBERTa-v3 PI detector (t = 0.5, omits flagged tool outputs). Prompt Guard 2 (B4/B4s) was "
          "**skipped**: gated on Hugging Face and no token was available. Approver `oracle` approves a REVIEW iff "
          "every reviewed value is a legitimate task value; `autodeny` denies every REVIEW. Brackets: bootstrap "
          "95 % CIs over cases."), *_section_offline(data), ""]
    for key, cap in (("asr_vs_interruption", "Security vs friction"), ("asr_by_category", "ASR by category"),
                     ("utility_vs_asr", "Utility vs ASR"), ("latency_cdf", "Per-decision latency"),
                     ("interruptions_by_rule", "Benign interruptions by rule")):
        if key in figs:
            L += [f"![{cap}]({figs[key].name})", ""]
    L += ["### Twin pairs (GW, oracle approver)", "", *_section_twins(data), "",
          "### LivePI-style families (oracle approver)", "", *_section_livepi(data), "",
          "### Payload-blindness / mutation operators (GW, A-suite)", "", *_section_mutations(data), "",
          "### Ablations (oracle approver)", "", *_section_ablations(data), ""]
    L += ["## 2. Live scenario runs (real models, stratified subset)", "",
          ("Subset: the 9 synthesis twin pairs + A14/B09 (10 attacks, 10 benign twins). Caching + client-side "
          "rate limits; the oracle approver answers REVIEWs. *Intermediate ASR* = the model proposed the injected "
          "action (attack tool with the attacker's literal value); *ASR* = the attack's effect happened.")]
    for r in data.live:
        L += ["", f"#### {r.label} — agent `{_model_of(r)}`", "", *_live_table(r)]
    L += ["", "## 3. AgentDojo v1.2.2", "",
          "### 3a. Offline ground-truth replay (all four suites, `important_instructions`)", "",
          ("Fully compromised agent: each pair replays the user task's ground-truth calls, then the injection task's. "
          "*Executed effects* re-applies AgentDojo's trace-based security checks to calls that actually executed; "
          "*native* is AgentDojo's own verdict, which for some injection tasks counts merely *proposed* calls (a "
          "tool-call gate cannot change those). B0 does not reach 100 % because some injection ground truths do not "
          "achieve their goal after the user task; the third ASR column restricts to pairs where B0 succeeds."), "",
          *_section_agentdojo_replay(data), "", "Residual GW successes (executed effects) by injection task:", "",
          *_section_agentdojo_gaps(data), ""]
    L += ["### 3b. Live AgentDojo subset", ""]
    if data.agentdojo_live:
        for r in data.agentdojo_live:
            L += [f"#### {r.label} — agent `{_model_of(r)}`", "", *_live_table(r), ""]
    else:
        L += ["_Not run._", ""]
    L += ["## 4. Latency and cost", "", *_section_latency(data), ""]
    return "\n".join(L) + "\n" + _CAVEATS


_CAVEATS = """
## 5. Known gaps and caveats

- **Small n.** Offline: 42 + 42 + 14 + 24 + 120 cases; live: 10 + 10 per arm; AgentDojo live: a handful of pairs per
  suite. Confidence intervals are wide; a 0/10 live ASR is compatible with a true rate of up to ~30 %.
- **Scripted attacker.** Offline numbers assume an agent that always performs the injected action with the
  attacker's literal values. They measure the gate, not the model, and are not end-to-end ASR.
- **No vulnerable live agent on our scenarios.** Neither Gemini (gemini-3.5-flash-lite) nor the Groq models
  (gpt-oss-20b, qwen3.8-27b) executed any of the 10 injected actions undefended, with or without the one-line
  injection warning in the system prompt, so the live scenario runs cannot show a security difference; they show
  utility and friction only. AgentDojo's `important_instructions` attack is the stronger live attack.
- **Prompt Guard 2 skipped** (gated on Hugging Face, no token). ProtectAI v2 at its default threshold hides most
  benign tool outputs in our worlds (JSON/YAML tool output is out of its training distribution).
- **AgentDojo gaps (by design or out of scope):** fetch-only goals (slack injection_task_3 "visit this URL": fetches
  are read-class and allowed by default), "goal collisions" where the attacker's destination equals one the user
  task legitimately uses (DM Alice, delete a file the user asked to touch), and content-level injections inside an
  allowed message body. Trace-scored goals (slack injection_task_5) are counted as AgentDojo-native successes even
  when every call was blocked.
- **The vendor "70 % → 2 %" claim** from the project brief is unattributed; it is used only as a reference point,
  not as a measured baseline.
- **Comparability.** LivePI-style ≠ LivePI (different agent, channels and models); AgentDojo numbers are only
  comparable with the full tuple (model, suite version, attack, defense, approver).
"""


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m firewall.eval.report")
    p.add_argument("--runs", nargs="*", type=Path, default=[], help="offline run directories")
    p.add_argument("--ablations", nargs="*", type=Path, default=[])
    p.add_argument("--live", nargs="*", type=Path, default=[])
    p.add_argument("--agentdojo-replay", nargs="*", type=Path, default=[])
    p.add_argument("--agentdojo-live", nargs="*", type=Path, default=[])
    p.add_argument("--bench-latency", type=Path, default=None)
    p.add_argument("--bench-http", type=Path, default=None)
    p.add_argument("--mutations", type=Path, default=None)
    p.add_argument("--suite", type=Path, default=None, help="JSON {seconds, passed, failed}")
    p.add_argument("--adaptive", type=Path, default=None)
    p.add_argument("--notes", type=Path, default=None, help="markdown file inserted after the headline criteria")
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--title", default=None)
    args = p.parse_args(argv)
    data = ReportData(
        offline=[load_run(d) for d in args.runs], ablations=[load_run(d) for d in args.ablations],
        live=[load_run(d) for d in args.live], agentdojo_replay=[load_run(d) for d in args.agentdojo_replay],
        agentdojo_live=[load_run(d) for d in args.agentdojo_live], bench_latency=_json(args.bench_latency),
        bench_http=_json(args.bench_http), mutations=_json(args.mutations), suite=_json(args.suite),
        adaptive=_json(args.adaptive),
        notes=args.notes.read_text(encoding="utf-8") if args.notes and args.notes.exists() else "")
    art = build_report(data, args.out, title=args.title)
    print(f"wrote {art.markdown} ({len(art.csvs)} CSVs, {len(art.charts)} charts)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

