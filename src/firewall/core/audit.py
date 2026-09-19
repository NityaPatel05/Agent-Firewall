"""Audit sinks: one structured record per decision / output / approval / final answer."""

from __future__ import annotations

import queue
import threading
from pathlib import Path
from typing import Protocol

from firewall.core.models import AuditRecord


class AuditSink(Protocol):
    def write(self, record: AuditRecord) -> None: ...
    def flush(self) -> None: ...
    def close(self) -> None: ...


class MemoryAuditSink:
    def __init__(self) -> None:
        self.records: list[AuditRecord] = []
        self._lock = threading.Lock()

    def write(self, record: AuditRecord) -> None:
        with self._lock:
            self.records.append(record)

    def flush(self) -> None:
        return None

    def close(self) -> None:
        return None


class JsonlAuditSink:
    """Appends JSON lines; with `background=True` a daemon thread drains a bounded queue."""

    def __init__(self, path: Path, *, background: bool = True, queue_size: int = 10000) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("a", encoding="utf-8")
        self._lock = threading.Lock()
        self._queue: queue.Queue[AuditRecord | None] | None = None
        self._thread: threading.Thread | None = None
        if background:
            self._queue = queue.Queue(maxsize=queue_size)
            self._thread = threading.Thread(target=self._drain, name="fw-audit", daemon=True)
            self._thread.start()

    def _write_now(self, record: AuditRecord) -> None:
        with self._lock:
            self._fh.write(record.model_dump_json() + "\n")

    def _drain(self) -> None:
        assert self._queue is not None
        while True:
            item = self._queue.get()
            try:
                if item is None:
                    return
                self._write_now(item)
            finally:
                self._queue.task_done()

    def write(self, record: AuditRecord) -> None:
        if self._queue is None:
            self._write_now(record)
        else:
            self._queue.put(record)

    def flush(self) -> None:
        if self._queue is not None:
            self._queue.join()
        with self._lock:
            self._fh.flush()

    def close(self) -> None:
        if self._queue is not None and self._thread is not None and self._thread.is_alive():
            self._queue.put(None)
            self._thread.join(timeout=5)
        with self._lock:
            if not self._fh.closed:
                self._fh.flush()
                self._fh.close()
