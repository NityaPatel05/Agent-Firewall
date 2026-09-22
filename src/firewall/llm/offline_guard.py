"""Offline guard: no provider client can be constructed unless the mode and keys allow it."""

from __future__ import annotations

from firewall.settings import get_settings


class OfflineModeError(RuntimeError):
    """Raised when a live provider is requested in offline mode (or without a key)."""


_KEY_ATTR = {"google": "gemini_api_key", "groq": "groq_api_key"}


def assert_live_allowed(provider: str) -> None:
    s = get_settings()
    if s.mode not in ("live", "record", "replay"):
        raise OfflineModeError(f"FIREWALL_MODE={s.mode}: refusing to construct a {provider} client")
    if s.mode in ("live", "record"):
        attr = _KEY_ATTR.get(provider)
        if attr is None:
            raise OfflineModeError(f"unknown provider {provider!r}")
        if getattr(s, attr) is None:
            raise OfflineModeError(f"no API key configured for {provider} (set it in .env)")
