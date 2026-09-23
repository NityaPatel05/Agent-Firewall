"""Web tools. Every request is logged with the full URL in `world.http_log` (exfil oracles read it)."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit, urlunsplit

from firewall.agent.tools._base import ToolError, impl
from firewall.agent.world import HttpRequest, MockWorld


def _page_key(world: MockWorld, url: str) -> str | None:
    if url in world.web:
        return url
    sp = urlsplit(url)
    base = urlunsplit((sp.scheme, sp.netloc, sp.path, "", ""))
    return base if base in world.web else None


@impl("web")
def get_webpage(world: MockWorld, url: str) -> str:
    world.http_log.append(HttpRequest(method="GET", url=url))
    key = _page_key(world, url)
    if key is None:
        raise ToolError(f"404 Not Found: {url}")
    return world.web[key].text


@impl("web")
def web_search(world: MockWorld, query: str) -> list[dict]:
    words = [w for w in query.lower().split() if len(w) > 2]
    hits = [p for p in world.web.values() if any(w in p.text.lower() or w in p.url.lower() for w in words)]
    return [{"url": p.url, "snippet": p.text[:160]} for p in hits[:5]]


@impl("web")
def get_weather(world: MockWorld, url: str) -> dict[str, Any] | str:
    world.http_log.append(HttpRequest(method="GET", url=url))
    key = _page_key(world, url)
    return world.web[key].text if key else {"temp_c": 12, "conditions": "unknown"}


@impl("web")
def post_form(world: MockWorld, url: str, fields: dict[str, Any]) -> dict[str, Any]:
    world.http_log.append(HttpRequest(method="POST", url=url, body=dict(fields)))
    return {"status": "submitted", "url": url}


@impl("web")
def call_webhook(world: MockWorld, url: str, payload: str) -> dict[str, Any]:
    world.http_log.append(HttpRequest(method="POST", url=url, body={"payload": payload}))
    return {"status": 200}


@impl("web")
def login_portal(world: MockWorld, url: str, username: str | None = None) -> dict[str, Any]:
    world.http_log.append(HttpRequest(method="POST", url=url, body={"username": username or world.user_email,
                                                                    "password": "<saved credential>"}))
    return {"status": "logged in", "url": url}
