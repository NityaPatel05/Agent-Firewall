"""Detector threshold calibration at a target FPR (leave-one-suite-out, worst fold), ROC-AUC (numpy only)."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import numpy as np

from firewall.settings import get_settings


def threshold_at_fpr(benign_scores: Sequence[float], target_fpr: float) -> float:
    """Smallest threshold t such that the fraction of benign scores >= t is <= target_fpr."""
    b = np.sort(np.asarray(benign_scores, dtype=float))
    if b.size == 0:
        return 0.5
    allowed = int(np.floor(target_fpr * b.size))   # number of benign samples allowed at/above t
    if allowed >= b.size:
        return float(b[0])
    t = float(b[b.size - allowed - 1])
    return float(np.nextafter(t, np.inf))


def rates(benign: Sequence[float], attack: Sequence[float], threshold: float) -> tuple[float, float]:
    """(recall on attacks, FPR on benign) at `threshold` (flag iff score >= threshold)."""
    a, b = np.asarray(attack, dtype=float), np.asarray(benign, dtype=float)
    recall = float((a >= threshold).mean()) if a.size else 0.0
    fpr = float((b >= threshold).mean()) if b.size else 0.0
    return recall, fpr


def roc_auc(benign: Sequence[float], attack: Sequence[float]) -> float:
    """Mann-Whitney U / (n_a * n_b), ties counted as 1/2."""
    a, b = np.asarray(attack, dtype=float), np.asarray(benign, dtype=float)
    if a.size == 0 or b.size == 0:
        return float("nan")
    greater = (a[:, None] > b[None, :]).sum()
    ties = (a[:, None] == b[None, :]).sum()
    return float((greater + 0.5 * ties) / (a.size * b.size))


def calibrate(rows: Sequence[dict[str, Any]], scores: Sequence[float], *, target_fpr: float,
              default_threshold: float = 0.5) -> dict[str, Any]:
    suites = sorted({r["suite"] for r in rows})
    benign = [s for r, s in zip(rows, scores, strict=True) if r["label"] == "benign"]
    attack = [s for r, s in zip(rows, scores, strict=True) if r["label"] == "attack"]
    folds: dict[str, float] = {}
    for held in suites:
        train_b = [s for r, s in zip(rows, scores, strict=True) if r["label"] == "benign" and r["suite"] != held]
        test_a = [s for r, s in zip(rows, scores, strict=True) if r["label"] == "attack" and r["suite"] == held]
        if not test_a or not train_b:
            continue
        folds[held] = rates([], test_a, threshold_at_fpr(train_b, target_fpr))[0]
    t = threshold_at_fpr(benign, target_fpr)
    d_recall, d_fpr = rates(benign, attack, default_threshold)
    c_recall, c_fpr = rates(benign, attack, t)
    return {
        "n_benign": len(benign), "n_attack": len(attack), "target_fpr": target_fpr,
        "default_threshold": default_threshold, "default_recall": d_recall, "default_fpr": d_fpr,
        "calibrated_threshold": t, "calibrated_recall": c_recall, "calibrated_fpr": c_fpr,
        "worst_fold_recall": min(folds.values()) if folds else None, "fold_recall": folds,
        "roc_auc": roc_auc(benign, attack),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m firewall.detectors.calibrate")
    parser.add_argument("--detector", required=True, help="keyword | protectai | pg2-86m | pg2-22m | judge")
    parser.add_argument("--corpus", default="scenarios", help="JSONL path or 'scenarios'")
    parser.add_argument("--target-fpr", type=float, default=0.02)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)
    from firewall.detectors import get_detector
    from firewall.detectors.corpus import corpus_rows
    from firewall.detectors.hf import DetectorUnavailable

    rows = corpus_rows(args.corpus)
    try:
        det = get_detector(args.detector)
        scores = [det.score(r["text"]).score for r in rows]
    except DetectorUnavailable as exc:
        print(f"skipped: {exc}")
        return 0
    finally:
        free = getattr(locals().get("det"), "free", None)
        if callable(free):
            free()
    res = calibrate(rows, scores, target_fpr=args.target_fpr)
    res["detector"] = args.detector
    res["corpus"] = str(args.corpus)
    out = args.out or (get_settings().runs_dir / "calibration" / f"{args.detector}.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(res, indent=2), encoding="utf-8")
    print(f"detector={args.detector} n_benign={res['n_benign']} n_attack={res['n_attack']} "
          f"auc={res['roc_auc']:.3f}")
    print(f"default threshold {res['default_threshold']:.3f}: recall={res['default_recall']:.3f} "
          f"fpr={res['default_fpr']:.3f}")
    worst = res["worst_fold_recall"]
    print(f"calibrated threshold {res['calibrated_threshold']:.3f} @ target FPR {args.target_fpr}: "
          f"recall={res['calibrated_recall']:.3f} fpr={res['calibrated_fpr']:.3f} "
          f"worst-fold recall={'n/a' if worst is None else f'{worst:.3f}'}")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
