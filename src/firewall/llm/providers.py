"""Provider factory: Gemini (langchain-google-genai) and Groq (langchain-groq), always cached + rate-limited."""

from __future__ import annotations

import os
from typing import Any, Literal

from langchain_core.language_models.chat_models import BaseChatModel

from firewall.llm.cache import CachedChatModel, ResponseCache, UsageTracker
from firewall.llm.config import ModelSpec, load_model_config
from firewall.llm.offline_guard import OfflineModeError, assert_live_allowed
from firewall.llm.ratelimit import get_limiter
from firewall.settings import api_keys, get_settings

_CACHES: dict[str, ResponseCache] = {}


def default_cache() -> ResponseCache:
    path = get_settings().cache_path
    key = str(path)
    if key not in _CACHES:
        _CACHES[key] = ResponseCache(path)
    return _CACHES[key]


def _key(provider: str, index: int | None) -> str | None:
    """Pick one key from a (possibly comma-separated) key setting; index via FIREWALL_KEY_INDEX_<PROVIDER>."""
    s = get_settings()
    keys = api_keys(s.gemini_api_key if provider == "google" else s.groq_api_key)
    if not keys:
        return None
    if index is None:
        index = int(os.environ.get(f"FIREWALL_KEY_INDEX_{provider.upper()}", "0"))
    return keys[index % len(keys)]


def key_count(provider: str) -> int:
    s = get_settings()
    return len(api_keys(s.gemini_api_key if provider == "google" else s.groq_api_key))


def _build_inner(spec: ModelSpec, key_index: int | None = None) -> BaseChatModel:
    key = _key(spec.provider, key_index)
    if spec.provider == "google":
        from langchain_google_genai import ChatGoogleGenerativeAI

        kwargs: dict[str, Any] = {"model": spec.model, "temperature": spec.temperature, "max_retries": 0}
        if key is not None:
            kwargs["google_api_key"] = key
        if spec.thinking is not None:
            # langchain-google-genai 4.4.2 exposes `thinking_level` (Gemini 3.x) next to `thinking_budget`.
            kwargs["thinking_level"] = spec.thinking
        return ChatGoogleGenerativeAI(**kwargs)
    if spec.provider == "groq":
        from langchain_groq import ChatGroq

        gkw: dict[str, Any] = {"model": spec.model, "temperature": spec.temperature, "max_retries": 0}
        if key is not None:
            gkw["api_key"] = key
        return ChatGroq(**gkw)
    raise OfflineModeError("scripted models are constructed directly (ScriptedChatModel)")


def make_chat_model(role_or_spec: str | ModelSpec, *, mode: str | None = None,
                    cache: ResponseCache | None | Literal["default"] = "default",
                    usage: UsageTracker | None = None, key_index: int | None = None) -> CachedChatModel:
    """Build the provider model for a role (or explicit spec), wrapped in CachedChatModel."""
    cfg = load_model_config()
    spec = cfg.role(role_or_spec) if isinstance(role_or_spec, str) else role_or_spec
    if spec.provider == "scripted":
        raise OfflineModeError("scripted models are constructed directly (ScriptedChatModel)")
    assert_live_allowed(spec.provider)
    run_mode = mode or get_settings().mode
    if run_mode not in ("live", "record", "replay"):
        raise OfflineModeError(f"mode {run_mode!r} does not allow provider models")
    limits = cfg.limits_for(spec.model)
    inner: Any = _ReplayOnly() if run_mode == "replay" else _build_inner(spec, key_index)
    return CachedChatModel(
        inner=inner, provider=spec.provider, model_id=spec.model,
        response_cache=default_cache() if cache == "default" else cache,
        limiter=get_limiter(spec.model) if run_mode in ("live", "record") else None,
        mode=run_mode,  # type: ignore[arg-type]
        usage=usage or UsageTracker(),
        params={"temperature": spec.temperature, "thinking": spec.thinking},
        price_in=limits.price_in, price_out=limits.price_out,
    )


class _ReplayOnly:
    """Stand-in inner model for replay without keys: binding works, calling is an error."""

    def bind_tools(self, tools: Any, **kwargs: Any) -> _ReplayOnly:
        return self

    def invoke(self, *args: Any, **kwargs: Any) -> Any:
        raise OfflineModeError("replay mode: provider call attempted (cache miss)")
