"""Calendar tools."""

from __future__ import annotations

from typing import Any

from firewall.agent.tools._base import ToolError, impl, next_id
from firewall.agent.world import Event, MockWorld, Reminder


def _view(e: Event) -> dict[str, Any]:
    return e.model_dump(mode="json")


def _find(world: MockWorld, event_id: str) -> Event:
    for e in world.calendar:
        if e.id == event_id:
            return e
    raise ToolError(f"event {event_id} not found")


@impl("calendar")
def list_events(world: MockWorld, day: str) -> list[dict]:
    d = str(day)[:10]
    return [_view(e) for e in world.calendar if e.start[:10] == d and e.status != "cancelled"]


@impl("calendar")
def get_event(world: MockWorld, event_id: str) -> dict[str, Any]:
    return _view(_find(world, event_id))


@impl("calendar")
def list_pending_invites(world: MockWorld) -> list[dict]:
    return [_view(e) for e in world.calendar if e.status == "pending"]


@impl("calendar")
def create_event(world: MockWorld, title: str, start: str, end: str, participants: list[str] | None = None,
                 location: str = "", description: str = "") -> dict[str, Any]:
    e = Event(id=next_id("ev", [x.id for x in world.calendar]), title=title, start=start, end=end,
              participants=list(participants or []), organizer=world.user_email, location=location,
              description=description)
    world.calendar.append(e)
    return {"status": "created", "id": e.id, "invited": e.participants}


@impl("calendar")
def accept_invite(world: MockWorld, event_id: str) -> dict[str, Any]:
    e = _find(world, event_id)
    e.status = "accepted"
    return {"status": "accepted", "id": e.id}


@impl("calendar")
def cancel_event(world: MockWorld, event_id: str, notify: bool = False) -> dict[str, Any]:
    e = _find(world, event_id)
    e.status = "cancelled"
    return {"status": "cancelled", "id": e.id, "notified": e.participants if notify else []}


@impl("calendar")
def set_reminder(world: MockWorld, title: str, at: str) -> dict[str, Any]:
    r = Reminder(id=next_id("r", [x.id for x in world.reminders]), title=title, at=at)
    world.reminders.append(r)
    return {"status": "set", "id": r.id}
