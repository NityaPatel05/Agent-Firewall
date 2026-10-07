"""Report charts (matplotlib, Agg backend, 150 dpi)."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from firewall.eval.metrics import MetricRow, in_subset
from firewall.eval.records import EpisodeResult

DPI = 150
GREY = "#6b7280"
COLORS = {"GW": "#2563eb", "GW-STRICT": "#1e40af", "B0": "#9ca3af", "B2": "#d97706", "B3": "#dc2626",
          "B6": "#7c3aed"}


def _color(defense: str) -> str:
    return COLORS.get(defense, "#059669")


def _save(fig: plt.Figure, path: Path) -> Path:
    fig.tight_layout()
    fig.savefig(path, dpi=DPI)
    plt.close(fig)
    return path


def asr_vs_interruption(rows_a: Sequence[MetricRow], rows_pb: Sequence[MetricRow], path: Path) -> Path:
    """One point per defense: A-suite ASR (with 95% CI) vs Pinch-like benign interruption rate."""
    pb = {r.group["defense"]: r for r in rows_pb}
    fig, ax = plt.subplots(figsize=(6, 4.2))
    seen: Counter[tuple[float, float]] = Counter()
    for r in rows_a:
        d = r.group["defense"]
        if d not in pb or r.asr is None or pb[d].interruption_rate is None:
            continue
        x, y = 100 * pb[d].interruption_rate, 100 * r.asr
        lo, hi = (100 * r.asr_ci[0], 100 * r.asr_ci[1]) if r.asr_ci else (y, y)
        ax.errorbar(x, y, yerr=[[y - lo], [hi - y]], fmt="o", color=_color(d), capsize=3, ms=7)
        k = seen[(round(x, 1), round(y, 1))]
        seen[(round(x, 1), round(y, 1))] += 1
        ax.annotate(d, (x, y), textcoords="offset points", xytext=(6, 4 + 11 * k), fontsize=9)
    ax.set_xlabel("benign interruption rate, Pinch-like workload (% of tool calls)")
    ax.set_ylabel("gate-only attack success, A01-A42 (%)")
    ax.set_title("Security vs. friction (offline, scripted compromised agent)")
    ax.grid(alpha=0.3)
    return _save(fig, path)


def asr_by_category(eps: Sequence[EpisodeResult], defenses: Sequence[str], path: Path) -> Path:
    """Grouped bars: A-suite attack success per category family for the given defenses."""
    att = [e for e in eps if e.kind == "attack" and in_subset(e.scenario_id, "A") and e.approver == "oracle"]
    fams = sorted({e.category.split("/")[0] for e in att})
    fig, ax = plt.subplots(figsize=(9, 4.2))
    width = 0.8 / max(1, len(defenses))
    for k, d in enumerate(defenses):
        vals = []
        for f in fams:
            es = [e for e in att if e.defense == d and e.category.split("/")[0] == f]
            vals.append(100 * sum(bool(e.attack_success) for e in es) / len(es) if es else 0)
        ax.bar(np.arange(len(fams)) + k * width, vals, width, label=d, color=_color(d))
    ax.set_xticks(np.arange(len(fams)) + width * (len(defenses) - 1) / 2, fams, rotation=45, ha="right", fontsize=8)
    ax.set_ylabel("attack success (%)")
    ax.set_title("A-suite attack success by category (offline, gate-only)")
    ax.legend(fontsize=8)
    return _save(fig, path)


def latency_cdf(eps: Sequence[EpisodeResult], path: Path, defense: str = "GW") -> Path:
    vals = np.sort([d.eval_us for e in eps if e.defense == defense for d in e.decisions if d.eval_us > 0])
    fig, ax = plt.subplots(figsize=(6, 4))
    if len(vals):
        ax.plot(vals, np.arange(1, len(vals) + 1) / len(vals), color=_color(defense))
        for q in (50, 95, 99):
            v = float(np.percentile(vals, q))
            ax.axvline(v, color=GREY, ls=":", lw=1)
            ax.annotate(f"p{q} {v:.0f} µs", (v, q / 100), fontsize=8, xytext=(4, -10), textcoords="offset points")
        ax.set_xscale("log")
    ax.set_xlabel("gateway evaluate() per decision (µs, log)")
    ax.set_ylabel("cumulative share")
    ax.set_title(f"Per-decision gateway latency ({defense}, offline suite)")
    ax.grid(alpha=0.3)
    return _save(fig, path)


def interruptions_by_rule(eps: Sequence[EpisodeResult], path: Path, defense: str = "GW") -> Path:
    c: Counter[str] = Counter()
    for e in eps:
        if e.defense == defense and e.kind == "benign":
            for d in e.decisions:
                if d.verdict.value != "allow" or (d.rule_ids and e.n_review):
                    c.update(d.rule_ids)
    top = c.most_common(12)
    fig, ax = plt.subplots(figsize=(7, 4))
    if top:
        ax.barh([k for k, _ in top][::-1], [v for _, v in top][::-1], color=_color(defense))
    ax.set_xlabel("benign decisions citing the rule")
    ax.set_title(f"Rules behind benign interruptions ({defense})")
    return _save(fig, path)


def utility_vs_asr(rows_a: Sequence[MetricRow], rows_b: Sequence[MetricRow], path: Path) -> Path:
    """A-suite ASR vs B-suite benign utility with NRP = BU x (1 - ASR) iso-lines."""
    b = {(r.group["defense"], r.group.get("approver")): r for r in rows_b}
    fig, ax = plt.subplots(figsize=(6, 4.2))
    xs = np.linspace(0, 1, 101)
    for nrp in (0.5, 0.7, 0.9):
        with np.errstate(divide="ignore", invalid="ignore"):
            ax.plot(100 * xs, 100 * np.clip(nrp / (1 - xs), 0, 1), color=GREY, ls=":", lw=0.8)
        ax.annotate(f"NRP {nrp}", (2, 100 * nrp), fontsize=7, color=GREY)
    for r in rows_a:
        key = (r.group["defense"], r.group.get("approver"))
        if key not in b or r.asr is None or b[key].bu is None:
            continue
        ax.scatter(100 * r.asr, 100 * b[key].bu, color=_color(key[0]), s=40,
                   marker="o" if key[1] == "oracle" else "s")
        ax.annotate(f"{key[0]}/{key[1]}", (100 * r.asr, 100 * b[key].bu), fontsize=7, xytext=(4, 3),
                    textcoords="offset points")
    ax.set_xlabel("A-suite attack success (%)")
    ax.set_ylabel("B-suite benign utility (%)")
    ax.set_ylim(0, 105)
    ax.set_title("Utility vs. attack success (offline)")
    ax.grid(alpha=0.3)
    return _save(fig, path)
