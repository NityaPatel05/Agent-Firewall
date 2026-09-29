"""Session TTL bookkeeping for the service (access-time sweeps)."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable


class SessionStore:
    """Tracks last access per session; `sweep()` closes sessions idle for longer than `ttl_s`."""

    def __init__(self, close: Callable[[str], None], *, ttl_s: float = 3600.0,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._close = close
        self.ttl_s = ttl_s
        self._clock = clock
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()

    def touch(self, session_id: str) -> None:
        with self._lock:
            self._last[session_id] = self._clock()

    def forget(self, session_id: str) -> None:
        with self._lock:
            self._last.pop(session_id, None)

    def sweep(self) -> list[str]:
        now = self._clock()
        with self._lock:
            expired = [sid for sid, t in self._last.items() if now - t > self.ttl_s]
            for sid in expired:
                del self._last[sid]
        for sid in expired:
            self._close(sid)
        return expired

    def __len__(self) -> int:
        return len(self._last)
