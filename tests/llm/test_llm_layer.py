"""M9: offline guard, response cache, rate limiter, CachedChatModel (all offline, fake clocks)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from firewall.llm.cache import (
    CachedChatModel,
    CacheMiss,
    ResponseCache,
    UsageTracker,
    _retry_after,
    is_retryable,
)
from firewall.llm.config import ModelLimits, load_model_config
from firewall.llm.offline_guard import OfflineModeError, assert_live_allowed
from firewall.llm.providers import make_chat_model
from firewall.llm.ratelimit import QuotaExhausted, RateLimiter
from firewall.settings import api_keys, clear_settings_cache

# ---------------------------------------------------------------- offline guard / config


def test_offline_mode_refuses_provider_clients() -> None:
    with pytest.raises(OfflineModeError):
        assert_live_allowed("google")
    with pytest.raises(OfflineModeError):
        make_chat_model("agent")


def test_live_mode_without_key_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FIREWALL_MODE", "live")
    clear_settings_cache()
    with pytest.raises(OfflineModeError, match="no API key"):
        assert_live_allowed("groq")


def test_replay_mode_needs_no_key_and_never_calls(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("FIREWALL_MODE", "replay")
    clear_settings_cache()
    m = make_chat_model("agent", cache=ResponseCache(tmp_path / "c.sqlite"))
    with pytest.raises(CacheMiss):
        m.invoke([HumanMessage("hi")])


def test_api_keys_split() -> None:
    from pydantic import SecretStr

    assert api_keys(SecretStr("a, b,,c")) == ["a", "b", "c"]
    assert api_keys(None) == []


def test_model_config_roles_and_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = load_model_config()
    assert cfg.role("agent").provider == "google"
    assert cfg.limits_for("unknown-model").rpm > 0
    monkeypatch.setenv("FIREWALL_MODEL_AGENT", "groq:openai/gpt-oss-20b")
    spec = load_model_config().role("agent")
    assert (spec.provider, spec.model) == ("groq", "openai/gpt-oss-20b")


# ---------------------------------------------------------------- cache


def test_cache_key_ignores_message_ids(tmp_path: Path) -> None:
    a = [HumanMessage("x", id="1"), AIMessage("", tool_calls=[{"name": "t", "args": {}, "id": "c1"}], id="r1"),
         ToolMessage("out", tool_call_id="c1", id="9")]
    b = [HumanMessage("x", id="2"), AIMessage("", tool_calls=[{"name": "t", "args": {}, "id": "c1"}], id="r2"),
         ToolMessage("out", tool_call_id="c1", id="8")]
    k = ResponseCache.key(provider="p", model="m", messages=a, tools=None, params={})
    assert k == ResponseCache.key(provider="p", model="m", messages=b, tools=None, params={})
    assert k != ResponseCache.key(provider="p", model="m2", messages=a, tools=None, params={})
    assert k != ResponseCache.key(provider="p", model="m", messages=a, tools=None, params={"temperature": 1})


def test_cache_roundtrip_persists(tmp_path: Path) -> None:
    path = tmp_path / "c.sqlite"
    c = ResponseCache(path)
    msg = AIMessage("", tool_calls=[{"name": "send_money", "args": {"amount": 5}, "id": "c1"}])
    c.put("k", msg, "m")
    again = ResponseCache(path).get("k")
    assert again is not None and again.tool_calls[0]["args"] == {"amount": 5}
    assert len(c) == 1 and c.get("missing") is None


# ---------------------------------------------------------------- rate limiter


class FakeTime:
    def __init__(self) -> None:
        self.t = 0.0
        self.slept: list[float] = []
        self.day = datetime(2026, 5, 1, 12, tzinfo=UTC)

    def clock(self) -> float:
        return self.t

    def sleep(self, s: float) -> None:
        self.slept.append(s)
        self.t += s

    def wall(self) -> datetime:
        return self.day


def _limiter(tmp_path: Path, ft: FakeTime, **kw: Any) -> RateLimiter:
    limits = ModelLimits(**{"rpm": 2, "tpm": 1000, "rpd": 5, **kw})
    return RateLimiter("m", limits, db_path=tmp_path / "rl.sqlite", clock=ft.clock, sleep=ft.sleep, wall=ft.wall)


def test_rpm_waits_for_window(tmp_path: Path) -> None:
    ft = FakeTime()
    lim = _limiter(tmp_path, ft)
    lim.acquire(10)
    lim.acquire(10)
    assert ft.slept == []
    lim.acquire(10)
    assert ft.t >= 60.0


def test_tpm_waits(tmp_path: Path) -> None:
    ft = FakeTime()
    lim = _limiter(tmp_path, ft, rpm=100)
    lim.acquire(900)
    lim.acquire(200)
    assert ft.t >= 60.0


def test_record_usage_replaces_estimate(tmp_path: Path) -> None:
    ft = FakeTime()
    lim = _limiter(tmp_path, ft, rpm=100)
    lim.acquire(900)
    lim.record_usage(50, 50)
    lim.acquire(800)
    assert ft.slept == []


def test_rpd_persisted_and_day_rollover(tmp_path: Path) -> None:
    ft = FakeTime()
    lim = _limiter(tmp_path, ft, rpm=100)
    for _ in range(5):
        lim.acquire(1)
    with pytest.raises(QuotaExhausted):
        lim.acquire(1)
    lim.close()
    lim2 = _limiter(tmp_path, ft, rpm=100)    # new process: same SQLite
    assert lim2.used_today() == 5
    with pytest.raises(QuotaExhausted):
        lim2.acquire(1)
    ft.day += timedelta(days=1)
    lim2.acquire(1)
    assert lim2.used_today() == 1
    lim2.close()


def test_rpd_reset_timezone(tmp_path: Path) -> None:
    ft = FakeTime()
    ft.day = datetime(2026, 5, 2, 3, tzinfo=UTC)   # still May 1 in Los Angeles
    lim = _limiter(tmp_path, ft, rpd_reset_tz="America/Los_Angeles")
    assert lim._day() == "2026-05-01"
    lim.close()


# ---------------------------------------------------------------- CachedChatModel


class Err429(Exception):
    status_code = 429


class FlakyModel:
    def __init__(self, fails: int) -> None:
        self.fails = fails
        self.calls = 0

    def bind_tools(self, tools: Any, **kw: Any) -> FlakyModel:
        return self

    def invoke(self, messages: Any, stop: Any = None) -> AIMessage:
        self.calls += 1
        if self.calls <= self.fails:
            raise Err429("429 RESOURCE_EXHAUSTED")
        return AIMessage("ok", usage_metadata={"input_tokens": 10, "output_tokens": 2, "total_tokens": 12})


def _cached(tmp_path: Path, inner: Any, mode: str = "live") -> CachedChatModel:
    return CachedChatModel(inner=inner, provider="scripted", model_id="m", response_cache=ResponseCache(tmp_path / "c.sqlite"),
                           mode=mode, usage=UsageTracker(), max_attempts=4, wait_initial=0.0, wait_max=0.0,
                           price_in=1.0, price_out=2.0)  # type: ignore[arg-type]


def test_retry_then_cache_hit(tmp_path: Path) -> None:
    inner = FlakyModel(fails=2)
    m = _cached(tmp_path, inner)
    assert m.invoke([HumanMessage("q")]).content == "ok"
    assert inner.calls == 3
    assert m.invoke([HumanMessage("q")]).content == "ok"
    assert inner.calls == 3
    snap = m.usage.snapshot()
    assert snap["calls"] == 1 and snap["cache_hits"] == 1 and snap["tokens_in"] == 10
    assert snap["cost_usd"] == pytest.approx((10 * 1.0 + 2 * 2.0) / 1e6)


def test_retries_exhausted_counts_error(tmp_path: Path) -> None:
    m = _cached(tmp_path, FlakyModel(fails=99))
    with pytest.raises(Err429):
        m.invoke([HumanMessage("q")])
    assert m.usage.snapshot()["errors"] == 1


def test_record_mode_overwrites(tmp_path: Path) -> None:
    inner = FlakyModel(fails=0)
    m = _cached(tmp_path, inner, mode="record")
    m.invoke([HumanMessage("q")])
    m.invoke([HumanMessage("q")])
    assert inner.calls == 2


def test_replay_mode_hit_and_miss(tmp_path: Path) -> None:
    live = _cached(tmp_path, FlakyModel(fails=0))
    live.invoke([HumanMessage("q")])
    replay = _cached(tmp_path, FlakyModel(fails=99), mode="replay")
    assert replay.invoke([HumanMessage("q")]).content == "ok"
    with pytest.raises(CacheMiss):
        replay.invoke([HumanMessage("other")])


def test_is_retryable_and_retry_after() -> None:
    assert is_retryable(Err429())
    assert not is_retryable(ValueError("bad request"))

    class E(Exception):
        response = SimpleNamespace(headers={"retry-after": "7"})

    assert _retry_after(E()) == 7.0
    assert _retry_after(ValueError()) is None


def test_bind_tools_changes_key(tmp_path: Path) -> None:
    from langchain_core.tools import tool

    @tool
    def get_balance() -> str:
        """Balance."""
        return "1"

    m = _cached(tmp_path, FlakyModel(fails=0))
    bound = m.bind_tools([get_balance])
    assert bound.bound_tools and bound._key([HumanMessage("q")]) != m._key([HumanMessage("q")])
