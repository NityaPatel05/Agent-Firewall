"""Shared pytest configuration: opt-in markers, offline environment and network guard."""

from __future__ import annotations

import importlib.util
import socket
from collections.abc import Iterator
from typing import Any

import pytest

from firewall.settings import clear_settings_cache

_LOOPBACK = {"127.0.0.1", "::1", "localhost", "0:0:0:0:0:0:0:1"}


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption("--run-live", action="store_true", default=False, help="run tests marked live")
    parser.addoption("--run-models", action="store_true", default=False, help="run tests marked models")
    parser.addoption("--run-agentdojo", action="store_true", default=False,
                     help="run tests marked agentdojo (importing AgentDojo's pipeline package costs ~14 s)")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    skip_live = pytest.mark.skip(reason="needs --run-live")
    skip_models = pytest.mark.skip(reason="needs --run-models")
    has_agentdojo = importlib.util.find_spec("agentdojo") is not None
    skip_adojo = pytest.mark.skip(reason="needs --run-agentdojo" if has_agentdojo else "agentdojo not installed")
    has_agentdojo = has_agentdojo and bool(config.getoption("--run-agentdojo"))
    for item in items:
        if "live" in item.keywords and not config.getoption("--run-live"):
            item.add_marker(skip_live)
        if "models" in item.keywords and not config.getoption("--run-models"):
            item.add_marker(skip_models)
        if "agentdojo" in item.keywords and not has_agentdojo:
            item.add_marker(skip_adojo)


def _is_loopback(address: Any) -> bool:
    if isinstance(address, tuple) and address:
        host = str(address[0])
        return host in _LOOPBACK or host.startswith("127.")
    # AF_UNIX paths and other non-IP families are local by definition.
    return isinstance(address, (str, bytes))


@pytest.fixture(autouse=True)
def _offline_env(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> Iterator[None]:
    """Force offline mode, strip API keys, and isolate the runs dir for non-live tests."""
    if "live" in request.keywords:
        yield
        return
    monkeypatch.setenv("FIREWALL_MODE", "offline")
    monkeypatch.setenv("FIREWALL_NO_DOTENV", "1")
    for key in ("GEMINI_API_KEY", "GROQ_API_KEY", "HF_TOKEN"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("FIREWALL_RUNS_DIR", str(tmp_path))
    monkeypatch.setenv("HF_HUB_OFFLINE", "1")
    clear_settings_cache()
    yield
    clear_settings_cache()


@pytest.fixture(autouse=True)
def _network_guard(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Block non-loopback socket connections in offline tests."""
    if "live" in request.keywords:
        return
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex

    def guarded_connect(self: socket.socket, address: Any) -> Any:
        if not _is_loopback(address):
            raise RuntimeError("network disabled in offline tests")
        return real_connect(self, address)

    def guarded_connect_ex(self: socket.socket, address: Any) -> Any:
        if not _is_loopback(address):
            raise RuntimeError("network disabled in offline tests")
        return real_connect_ex(self, address)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
