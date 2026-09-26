"""Detector protocol, results and an off-hot-path runner. Detectors are signals only (never load-bearing)."""

from __future__ import annotations

import threading
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Protocol

from pydantic import BaseModel, ConfigDict


class DetectorResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    detector: str
    flagged: bool
    score: float
    threshold: float
    windows: int = 1
    span: tuple[int, int] | None = None
    latency_ms: float = 0.0


class Detector(Protocol):
    name: str
    threshold: float

    def score(self, text: str) -> DetectorResult: ...


class DetectorRunner:
    """Scores texts in a small thread pool (or synchronously, e.g. in benchmarks)."""

    def __init__(self, detector: Detector, *, synchronous: bool = False, max_workers: int = 2) -> None:
        self.detector = detector
        self.synchronous = synchronous
        self._pool = None if synchronous else ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="det")
        self._futures: dict[str, Future[DetectorResult]] = {}
        self._results: dict[str, DetectorResult] = {}
        self._lock = threading.Lock()

    def submit(self, key: str, text: str) -> None:
        if self._pool is None:
            self._results[key] = self.detector.score(text)
            return
        with self._lock:
            self._futures[key] = self._pool.submit(self.detector.score, text)

    def result(self, key: str, timeout: float | None = None) -> DetectorResult | None:
        if key in self._results:
            return self._results[key]
        with self._lock:
            fut = self._futures.get(key)
        if fut is None:
            return None
        res = fut.result(timeout=timeout)
        self._results[key] = res
        return res

    def close(self) -> None:
        if self._pool is not None:
            self._pool.shutdown(wait=True)
