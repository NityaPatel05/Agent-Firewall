"""SQLite response cache, usage tracking, retries, and CachedChatModel (live / record / replay)."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
import warnings
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Literal

from langchain_core.callbacks import CallbackManagerForLLMRun
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.load import dumpd, loads
from langchain_core.messages import AIMessage, BaseMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.utils.function_calling import convert_to_openai_tool
from pydantic import ConfigDict, Field
from tenacity import RetryCallState, Retrying, retry_if_exception, stop_after_attempt, wait_exponential_jitter

from firewall.llm.ratelimit import RateLimiter


class CacheMiss(RuntimeError):
    """Replay mode found no cached response for a request."""


def _canonical_message(m: BaseMessage) -> dict[str, Any]:
    """Stable view of a message for keying (no random ids, no provider metadata)."""
    out: dict[str, Any] = {"type": m.type, "content": m.content}
    if isinstance(m, AIMessage) and m.tool_calls:
        out["tool_calls"] = [{"name": tc["name"], "args": tc["args"], "id": tc.get("id")} for tc in m.tool_calls]
    if isinstance(m, ToolMessage):
        out["tool_call_id"] = m.tool_call_id
        out["name"] = m.name
        out["status"] = m.status
    return out


class ResponseCache:
    """SQLite (WAL) table responses(key, model, created, payload); payload = langchain-serialized AIMessage."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("CREATE TABLE IF NOT EXISTS responses (key TEXT PRIMARY KEY, model TEXT, created REAL, "
                         "payload TEXT)")
        self._db.commit()

    @staticmethod
    def key(*, provider: str, model: str, messages: Sequence[BaseMessage], tools: Sequence[dict] | None,
            params: Mapping[str, Any]) -> str:
        body = {"provider": provider, "model": model, "messages": [_canonical_message(m) for m in messages],
                "tools": list(tools or []), "params": dict(params)}
        text = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def get(self, key: str) -> AIMessage | None:
        with self._lock:
            row = self._db.execute("SELECT payload FROM responses WHERE key=?", (key,)).fetchone()
        if row is None:
            return None
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            msg = loads(row[0], allowed_objects="messages")
        return msg if isinstance(msg, AIMessage) else None

    def put(self, key: str, msg: AIMessage, model: str) -> None:
        payload = json.dumps(dumpd(msg), sort_keys=True, ensure_ascii=False)
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO responses(key, model, created, payload) VALUES (?, ?, ?, ?)",
                             (key, model, time.time(), payload))
            self._db.commit()

    def __len__(self) -> int:
        with self._lock:
            return int(self._db.execute("SELECT COUNT(*) FROM responses").fetchone()[0])


class UsageTracker:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.calls = 0
        self.cache_hits = 0
        self.tokens_in = 0
        self.tokens_out = 0
        self.cost_usd = 0.0
        self.errors = 0

    def add(self, *, call: bool = False, hit: bool = False, tokens_in: int = 0, tokens_out: int = 0,
            cost: float = 0.0, error: bool = False) -> None:
        with self._lock:
            self.calls += int(call)
            self.cache_hits += int(hit)
            self.tokens_in += tokens_in
            self.tokens_out += tokens_out
            self.cost_usd += cost
            self.errors += int(error)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {"calls": self.calls, "cache_hits": self.cache_hits, "tokens_in": self.tokens_in,
                    "tokens_out": self.tokens_out, "cost_usd": round(self.cost_usd, 6), "errors": self.errors}


_RETRY_NAMES = ("RateLimit", "ServiceUnavailable", "ResourceExhausted", "Timeout", "APIConnection",
                "InternalServer", "ServerError", "ConnectError", "ReadError")


def _status_of(exc: BaseException) -> int | None:
    for attr in ("status_code", "code", "status"):
        v = getattr(exc, attr, None)
        if isinstance(v, int):
            return v
    resp = getattr(exc, "response", None)
    v = getattr(resp, "status_code", None)
    return v if isinstance(v, int) else None


def is_retryable(exc: BaseException) -> bool:
    status = _status_of(exc)
    if status in (429, 500, 502, 503, 504):
        return True
    name = type(exc).__name__
    if any(n in name for n in _RETRY_NAMES):
        return True
    text = str(exc)
    return any(s in text for s in ("429", "RESOURCE_EXHAUSTED", "UNAVAILABLE", "503 ", "overloaded"))


def _retry_after(exc: BaseException | None) -> float | None:
    resp = getattr(exc, "response", None)
    headers = getattr(resp, "headers", None)
    if headers is not None:
        v = headers.get("retry-after") or headers.get("Retry-After")
        try:
            return float(v) if v is not None else None
        except ValueError:
            return None
    return None


def estimate_tokens(messages: Sequence[BaseMessage], tools: Sequence[dict] | None) -> int:
    chars = sum(len(str(m.content)) for m in messages) + len(json.dumps(list(tools or []), default=str))
    return max(1, chars // 4)


class CachedChatModel(BaseChatModel):
    """Wraps a provider chat model with a response cache, a client-side rate limiter and retries."""

    model_config = ConfigDict(arbitrary_types_allowed=True)
    inner: Any
    provider: str
    model_id: str
    # Not `cache`: that name is BaseChatModel's own (global LangChain cache) field.
    response_cache: ResponseCache | None = None
    limiter: RateLimiter | None = None
    mode: Literal["live", "record", "replay"] = "live"
    usage: UsageTracker = Field(default_factory=UsageTracker)
    bound_tools: list[dict] | None = None
    params: dict[str, Any] = Field(default_factory=dict)
    price_in: float = 0.0
    price_out: float = 0.0
    max_attempts: int = 6
    wait_initial: float = 2.0
    wait_max: float = 60.0

    @property
    def _llm_type(self) -> str:
        return f"cached-{self.provider}"

    def bind_tools(self, tools: Sequence[Any], **kwargs: Any) -> CachedChatModel:  # type: ignore[override]
        schemas = [convert_to_openai_tool(t) for t in tools]
        bound = self.inner.bind_tools(tools, **kwargs)
        extra = {k: v for k, v in kwargs.items() if isinstance(v, (str, int, float, bool))}
        return self.model_copy(update={"inner": bound, "bound_tools": schemas, "params": {**self.params, **extra}})

    def _key(self, messages: Sequence[BaseMessage]) -> str:
        return ResponseCache.key(provider=self.provider, model=self.model_id, messages=messages,
                                 tools=self.bound_tools, params=self.params)

    def _wait(self, state: RetryCallState) -> float:
        exc = state.outcome.exception() if state.outcome is not None else None
        ra = _retry_after(exc)
        if ra is not None:
            return min(ra, self.wait_max)
        return wait_exponential_jitter(initial=self.wait_initial, max=self.wait_max)(state)

    def _call_inner(self, messages: list[BaseMessage], stop: list[str] | None) -> AIMessage:
        if self.limiter is not None:
            self.limiter.acquire(estimate_tokens(messages, self.bound_tools))
        retrying = Retrying(stop=stop_after_attempt(self.max_attempts), wait=self._wait,
                            retry=retry_if_exception(is_retryable), reraise=True)
        try:
            msg = retrying(self.inner.invoke, messages, stop=stop)
        except Exception:
            self.usage.add(error=True)
            raise
        if not isinstance(msg, AIMessage):
            msg = AIMessage(content=getattr(msg, "content", str(msg)))
        u = msg.usage_metadata or {}
        tin, tout = int(u.get("input_tokens", 0)), int(u.get("output_tokens", 0))
        if self.limiter is not None:
            self.limiter.record_usage(tin, tout)
        cost = (tin * self.price_in + tout * self.price_out) / 1_000_000
        self.usage.add(call=True, tokens_in=tin, tokens_out=tout, cost=cost)
        return msg

    def _generate(self, messages: list[BaseMessage], stop: list[str] | None = None,
                  run_manager: CallbackManagerForLLMRun | None = None, **kwargs: Any) -> ChatResult:
        key = self._key(messages)
        if self.response_cache is not None and self.mode in ("live", "replay"):
            hit = self.response_cache.get(key)
            if hit is not None:
                self.usage.add(hit=True)
                return ChatResult(generations=[ChatGeneration(message=hit)])
            if self.mode == "replay":
                raise CacheMiss(f"no cached response for {self.model_id} (key {key[:12]})")
        msg = self._call_inner(messages, stop)
        if self.response_cache is not None:
            self.response_cache.put(key, msg, self.model_id)
        return ChatResult(generations=[ChatGeneration(message=msg)])
