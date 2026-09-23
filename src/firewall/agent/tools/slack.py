"""Slack / group-chat tools."""

from __future__ import annotations

from typing import Any

from firewall.agent.tools._base import ToolError, impl, require
from firewall.agent.world import ChatMessage, MockWorld


def _msg_id(world: MockWorld) -> str:
    n = sum(len(v) for v in world.slack.channels.values()) + len(world.slack.dms) + 1
    return f"m{n + 100}"


@impl("slack")
def list_channels(world: MockWorld) -> list[str]:
    return sorted(world.slack.channels)


@impl("slack")
def list_users(world: MockWorld) -> list[str]:
    return list(world.slack.users)


@impl("slack")
def read_channel(world: MockWorld, channel: str, limit: int = 50) -> list[dict]:
    msgs = world.slack.channels.get(channel.lower())
    if msgs is None:
        raise ToolError(f"channel {channel} not found")
    return [m.model_dump(mode="json") for m in msgs[-limit:]]


@impl("slack")
def read_dms(world: MockWorld, user: str) -> list[dict]:
    u = user.lower()
    return [m.model_dump(mode="json") for m in world.slack.dms if m.author.lower() == u or m.channel.lower() == u]


@impl("slack")
def send_dm(world: MockWorld, user: str, text: str) -> dict[str, Any]:
    m = ChatMessage(id=_msg_id(world), channel=user.lower(), author=world.slack.self_handle, text=text, ts=world.now)
    world.slack.dms.append(m)
    return {"status": "sent", "to": user, "id": m.id}


@impl("slack")
def post_message(world: MockWorld, channel: str, text: str) -> dict[str, Any]:
    ch = channel.lower()
    require(ch in world.slack.channels, f"channel {channel} not found")
    m = ChatMessage(id=_msg_id(world), channel=ch, author=world.slack.self_handle, text=text, ts=world.now)
    world.slack.channels[ch].append(m)
    return {"status": "posted", "channel": ch, "id": m.id}


@impl("slack")
def add_user_to_channel(world: MockWorld, user: str, channel: str) -> dict[str, Any]:
    ch = channel.lower()
    require(ch in world.slack.channels, f"channel {channel} not found")
    members = world.slack.channel_members.setdefault(ch, [])
    if user.lower() not in members:
        members.append(user.lower())
    return {"status": "added", "user": user, "channel": ch}
