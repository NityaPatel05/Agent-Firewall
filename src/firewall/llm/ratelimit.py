"""Client-side rate limiter per model: RPM token bucket, 60 s TPM window, RPD persisted in SQLite."""

from __future__ import annotations

import sqlite3
import threading
import time
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from firewall.llm.config import ModelLimits, load_model_config
from firewall.settings import get_settings

WINDOW_S = 60.0


class QuotaExhausted(RuntimeError):
    """The daily request quota (RPD) for a model is used up; runs should stop cleanly."""


class RateLimiter:
    def __init__(self, model: str, limits: ModelLimits, *, db_path: Path,
                 clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep,
                 wall: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        self.model = model
        self.limits = limits
        self._clock, self._sleep, self._wall = clock, sleep, wall
        self._requests: deque[float] = deque()
        self._tokens: deque[list[float]] = deque()   # [time, tokens]
        self._lock = threading.Lock()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(db_path), check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("CREATE TABLE IF NOT EXISTS rpd (model TEXT, day TEXT, count INTEGER, PRIMARY KEY(model, day))")
        self._db.commit()

    def _day(self) -> str:
        return self._wall().astimezone(ZoneInfo(self.limits.rpd_reset_tz)).date().isoformat()

    def used_today(self) -> int:
        row = self._db.execute("SELECT count FROM rpd WHERE model=? AND day=?", (self.model, self._day())).fetchone()
        return int(row[0]) if row else 0

    def _prune(self, now: float) -> None:
        while self._requests and now - self._requests[0] >= WINDOW_S:
            self._requests.popleft()
        while self._tokens and now - self._tokens[0][0] >= WINDOW_S:
            self._tokens.popleft()

    def acquire(self, est_tokens: int) -> None:
        """Block until a request of `est_tokens` fits the RPM/TPM windows; raise QuotaExhausted on RPD."""
        with self._lock:
            if self.used_today() >= self.limits.rpd:
                raise QuotaExhausted(f"{self.model}: daily quota of {self.limits.rpd} requests exhausted")
            est = min(est_tokens, self.limits.tpm)
            while True:
                now = self._clock()
                self._prune(now)
                tok_used = sum(t[1] for t in self._tokens)
                if len(self._requests) < self.limits.rpm and tok_used + est <= self.limits.tpm:
                    break
                waits = []
                if len(self._requests) >= self.limits.rpm:
                    waits.append(self._requests[0] + WINDOW_S - now)
                if tok_used + est > self.limits.tpm and self._tokens:
                    waits.append(self._tokens[0][0] + WINDOW_S - now)
                self._sleep(max(0.01, min(waits) if waits else 0.01))
            self._requests.append(now)
            self._tokens.append([now, float(est)])
            day = self._day()
            self._db.execute("INSERT INTO rpd(model, day, count) VALUES (?, ?, 1) "
                             "ON CONFLICT(model, day) DO UPDATE SET count = count + 1", (self.model, day))
            self._db.commit()

    def record_usage(self, tokens_in: int, tokens_out: int) -> None:
        """Replace the estimate of the latest request with the actual token usage."""
        with self._lock:
            if self._tokens:
                self._tokens[-1][1] = float(tokens_in + tokens_out)

    def close(self) -> None:
        self._db.close()


_LIMITERS: dict[str, RateLimiter] = {}
_LIMITERS_LOCK = threading.Lock()


def get_limiter(model: str) -> RateLimiter:
    """Process-wide limiter per model (thread-safe)."""
    with _LIMITERS_LOCK:
        lim = _LIMITERS.get(model)
        if lim is None:
            lim = RateLimiter(model, load_model_config().limits_for(model), db_path=get_settings().limiter_path)
            _LIMITERS[model] = lim
        return lim
