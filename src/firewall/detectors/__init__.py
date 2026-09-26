"""Detectors (baselines / escalation signals only): keyword, ProtectAI, Prompt Guard 2, LLM judge."""

from __future__ import annotations

import json
from typing import Literal

from firewall.detectors.base import Detector, DetectorResult, DetectorRunner
from firewall.settings import get_settings

DetectorName = Literal["keyword", "protectai", "pg2-86m", "pg2-22m", "judge"]


def calibrated_threshold(name: str) -> float | None:
    path = get_settings().runs_dir / "calibration" / f"{name}.json"
    if not path.exists():
        return None
    return float(json.loads(path.read_text(encoding="utf-8"))["calibrated_threshold"])


def get_detector(name: str, *, threshold: float | Literal["calibrated"] | None = None) -> Detector:
    """Construct a detector; HF models load lazily on first `score()`."""
    t: float | None
    if threshold == "calibrated":
        t = calibrated_threshold(name)
        if t is None:
            raise FileNotFoundError(f"no calibration for {name}: run python -m firewall.detectors.calibrate")
    else:
        t = threshold
    if name == "keyword":
        from firewall.detectors.keyword import KeywordDetector

        return KeywordDetector(threshold=0.5 if t is None else t)
    if name in ("protectai", "pg2-86m", "pg2-22m"):
        from firewall.detectors import hf

        factory = {"protectai": hf.protectai_v2, "pg2-86m": hf.prompt_guard_86m, "pg2-22m": hf.prompt_guard_22m}
        return factory[name](0.5 if t is None else t)
    if name == "judge":
        from firewall.detectors.llm_judge import LLMJudgeDetector
        from firewall.llm.providers import make_chat_model

        return LLMJudgeDetector(make_chat_model("judge"), threshold=0.5 if t is None else t)
    raise KeyError(f"unknown detector {name!r}")


__all__ = ["Detector", "DetectorResult", "DetectorRunner", "calibrated_threshold", "get_detector"]
