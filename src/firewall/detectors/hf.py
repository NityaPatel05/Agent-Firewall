"""Hugging Face classifiers (ProtectAI DeBERTa v2, Prompt Guard 2). Lazy, CPU-only, freeable (low-RAM machine)."""

from __future__ import annotations

import gc
import logging
import time
from typing import Any

from firewall.detectors.base import DetectorResult
from firewall.detectors.windowing import windows

log = logging.getLogger(__name__)


class DetectorUnavailable(RuntimeError):
    """Model weights cannot be loaded (not downloaded, gated without HF auth, or no torch)."""


class HFClassifierDetector:
    """Max injection-probability over 510-token windows; the pipeline is loaded on first use and can be freed."""

    def __init__(self, model_id: str, *, injection_labels: set[str] | None = None, threshold: float = 0.5,
                 device: str = "cpu", max_windows: int = 16, name: str | None = None) -> None:
        self.model_id = model_id
        self.injection_labels = {label.upper() for label in (injection_labels or set())}
        self.threshold = threshold
        self.device = device
        self.max_windows = max_windows
        self.name = name or model_id.rsplit("/", 1)[-1]
        self._pipe: Any = None

    def load(self) -> None:
        if self._pipe is not None:
            return
        try:
            import torch
            from transformers import pipeline
        except ImportError as exc:  # pragma: no cover - depends on optional extra
            raise DetectorUnavailable(f"{self.name}: transformers/torch not installed") from exc
        from firewall.settings import get_settings

        torch.set_num_threads(max(1, min(4, torch.get_num_threads())))
        secret = get_settings().hf_token   # gated repos (Prompt Guard 2) need it; never logged
        try:
            self._pipe = pipeline("text-classification", model=self.model_id, device=-1, top_k=None,
                                  truncation=True, max_length=512,
                                  token=secret.get_secret_value() if secret is not None else None)
        except Exception as exc:  # gated repo, no network in offline tests, missing weights …
            raise DetectorUnavailable(f"{self.name}: cannot load {self.model_id}: {type(exc).__name__}") from exc
        if not self.injection_labels:
            id2label = getattr(self._pipe.model.config, "id2label", {})
            labels = [str(v).upper() for v in id2label.values()]
            malicious = [lab for lab in labels if lab in {"INJECTION", "MALICIOUS", "JAILBREAK", "LABEL_1", "UNSAFE"}]
            self.injection_labels = set(malicious or labels[1:])

    def free(self) -> None:
        """Release model memory (the machine has little RAM; load one model at a time)."""
        self._pipe = None
        gc.collect()

    def score(self, text: str) -> DetectorResult:
        self.load()
        t0 = time.perf_counter()
        wins = windows(text, self._pipe.tokenizer)[: self.max_windows]
        outputs = self._pipe(wins, batch_size=4)
        best = 0.0
        best_idx = 0
        for i, scores in enumerate(outputs):
            p = sum(s["score"] for s in scores if str(s["label"]).upper() in self.injection_labels)
            if p > best:
                best, best_idx = p, i
        return DetectorResult(detector=self.name, flagged=best >= self.threshold, score=float(best),
                              threshold=self.threshold, windows=len(wins), span=(best_idx, best_idx + 1),
                              latency_ms=(time.perf_counter() - t0) * 1000)


def protectai_v2(threshold: float = 0.5) -> HFClassifierDetector:
    return HFClassifierDetector("protectai/deberta-v3-base-prompt-injection-v2", injection_labels={"INJECTION"},
                                threshold=threshold, name="protectai")


def prompt_guard_86m(threshold: float = 0.5) -> HFClassifierDetector:
    return HFClassifierDetector("meta-llama/Llama-Prompt-Guard-2-86M", threshold=threshold, name="pg2-86m")


def prompt_guard_22m(threshold: float = 0.5) -> HFClassifierDetector:
    return HFClassifierDetector("meta-llama/Llama-Prompt-Guard-2-22M", threshold=threshold, name="pg2-22m")
