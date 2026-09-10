"""Runtime settings loaded from the environment and an optional `.env` file."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from dotenv import dotenv_values
from pydantic import BaseModel, SecretStr

Mode = Literal["offline", "replay", "live", "record"]

_ENV_MAP: dict[str, str] = {
    "FIREWALL_MODE": "mode",
    "GEMINI_API_KEY": "gemini_api_key",
    "GROQ_API_KEY": "groq_api_key",
    "HF_TOKEN": "hf_token",
    "FIREWALL_RUNS_DIR": "runs_dir",
    "FIREWALL_CONFIG_DIR": "config_dir",
    "FIREWALL_LOG_LEVEL": "log_level",
}


class Settings(BaseModel):
    """Process-wide configuration. Secrets are `SecretStr` and never printed."""

    mode: Mode = "offline"
    gemini_api_key: SecretStr | None = None
    groq_api_key: SecretStr | None = None
    hf_token: SecretStr | None = None
    runs_dir: Path = Path("runs")
    cache_path: Path = Path("runs/.llm_cache.sqlite")
    limiter_path: Path = Path("runs/.ratelimit.sqlite")
    config_dir: Path | None = None
    log_level: str = "INFO"


def _dotenv_file() -> Path | None:
    """Locate `.env` (FIREWALL_DOTENV overrides; FIREWALL_NO_DOTENV=1 disables)."""
    if os.environ.get("FIREWALL_NO_DOTENV") == "1":
        return None
    explicit = os.environ.get("FIREWALL_DOTENV")
    if explicit:
        return Path(explicit)
    return Path.cwd() / ".env"


def _collect_env() -> dict[str, str]:
    """Merge `.env` values with process env; the process env wins. Never mutates os.environ."""
    merged: dict[str, str] = {}
    path = _dotenv_file()
    if path is not None and path.is_file():
        for key, value in dotenv_values(path).items():
            if value is not None:
                merged[key] = value
    for key in _ENV_MAP:
        if key in os.environ:
            merged[key] = os.environ[key]
    return merged


@lru_cache(maxsize=1)
def _cached_settings() -> Settings:
    env = _collect_env()
    data: dict[str, object] = {}
    for env_name, field in _ENV_MAP.items():
        value = env.get(env_name)
        if value is not None and value != "":
            data[field] = value
    settings = Settings.model_validate(data)
    if "runs_dir" in data:
        settings = settings.model_copy(
            update={
                "cache_path": settings.runs_dir / ".llm_cache.sqlite",
                "limiter_path": settings.runs_dir / ".ratelimit.sqlite",
            }
        )
    return settings


def api_keys(secret: SecretStr | None) -> list[str]:
    """A key setting may hold several comma-separated keys (rotation); returns them in order."""
    if secret is None:
        return []
    return [k.strip() for k in secret.get_secret_value().split(",") if k.strip()]


def get_settings(*, reload: bool = False) -> Settings:
    """Return cached settings; `reload=True` re-reads the environment."""
    if reload:
        _cached_settings.cache_clear()
    return _cached_settings()


def clear_settings_cache() -> None:
    """Drop cached settings (used by tests)."""
    _cached_settings.cache_clear()
