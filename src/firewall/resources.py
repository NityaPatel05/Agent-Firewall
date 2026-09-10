"""Locate packaged data directories (policies, registry, data, scenarios)."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path
from typing import Literal

from firewall.settings import get_settings

Kind = Literal["policies", "registry", "data", "scenarios"]

_SUBDIR: dict[str, tuple[str, ...]] = {
    "policies": ("policies",),
    "registry": ("registry",),
    "data": ("data",),
    "scenarios": ("eval", "scenarios"),
}


def package_root() -> Path:
    """Filesystem path of the installed `firewall` package."""
    return Path(str(files("firewall")))


def data_path(kind: Kind, *parts: str) -> Path:
    """Path to a packaged data file/dir; `Settings.config_dir` overrides when the file exists there."""
    if kind not in _SUBDIR:
        raise ValueError(f"unknown data kind: {kind!r}")
    override = get_settings().config_dir
    if override is not None:
        candidate = Path(override) / kind / Path(*parts) if parts else Path(override) / kind
        if candidate.exists():
            return candidate
    return package_root().joinpath(*_SUBDIR[kind], *parts)
