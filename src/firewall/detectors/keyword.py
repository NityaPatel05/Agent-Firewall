"""Heuristic multilingual injection detector (offline baseline B6)."""

from __future__ import annotations

import re
import time

from firewall.core.decoders import trigger_phrases
from firewall.detectors.base import DetectorResult

IMPERATIVE_PATTERNS = [
    re.compile(r"(?i)\b(you|assistant|ai|agent|bot)\b[^.\n]{0,20}\b(must|should|need to|have to|are required to)\b"),
    re.compile(r"(?i)<\s*/?\s*information\s*>"),
    re.compile(r"(?i)important\s*!{2,}|important\s+instructions"),
    re.compile(r"(?i)\bignore\s+(all|previous|prior|the above)\b"),
    re.compile(r"(?i)\b(pre-?approved|already approved|skip (the )?review)\b"),
    re.compile(r"(?i)\b(user|system|admin)\s+says\s*:"),
]


class KeywordDetector:
    def __init__(self, threshold: float = 0.5, name: str = "keyword") -> None:
        self.threshold = threshold
        self.name = name

    def score(self, text: str) -> DetectorResult:
        t0 = time.perf_counter()
        phrases = trigger_phrases(text)
        imperative = sum(1 for rx in IMPERATIVE_PATTERNS if rx.search(text))
        s = min(1.0, 0.5 * len(phrases) + 0.25 * imperative)
        return DetectorResult(detector=self.name, flagged=s >= self.threshold, score=s, threshold=self.threshold,
                              latency_ms=(time.perf_counter() - t0) * 1000)
