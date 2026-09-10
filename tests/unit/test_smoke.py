from __future__ import annotations

import socket
import threading

import pytest

import firewall
from firewall.resources import data_path
from firewall.settings import get_settings


def test_version() -> None:
    assert isinstance(firewall.__version__, str)
    assert firewall.__version__ == "0.1.0"


def test_settings_offline() -> None:
    settings = get_settings()
    assert settings.mode == "offline"
    assert settings.gemini_api_key is None
    assert settings.groq_api_key is None


def test_settings_reload_reads_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FIREWALL_MODE", "replay")
    assert get_settings(reload=True).mode == "replay"


def test_secret_not_in_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "dummy-not-a-real-key-123")
    settings = get_settings(reload=True)
    assert settings.gemini_api_key is not None
    assert "dummy-not-a-real-key-123" not in repr(settings)


def test_external_network_blocked() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(RuntimeError, match="network disabled"):
            s.connect(("8.8.8.8", 53))
    finally:
        s.close()


def test_loopback_allowed() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    accepted: list[socket.socket] = []
    t = threading.Thread(target=lambda: accepted.append(server.accept()[0]))
    t.start()
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect(("127.0.0.1", port))
        t.join(timeout=5)
        assert accepted
    finally:
        client.close()
        for conn in accepted:
            conn.close()
        server.close()


def test_data_path_policies_exists() -> None:
    path = data_path("policies")
    assert path.is_dir()


def test_data_path_unknown_kind() -> None:
    with pytest.raises(ValueError):
        data_path("nope")  # type: ignore[arg-type]
