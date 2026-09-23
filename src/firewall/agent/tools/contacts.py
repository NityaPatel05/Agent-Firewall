"""Contacts tools."""

from __future__ import annotations

from typing import Any

from firewall.agent.tools._base import impl
from firewall.agent.world import Contact, MockWorld


@impl("contacts")
def list_contacts(world: MockWorld) -> list[dict]:
    return [c.model_dump(mode="json") for c in world.contacts]


@impl("contacts")
def search_contacts(world: MockWorld, query: str) -> list[dict]:
    q = query.lower()
    return [c.model_dump(mode="json") for c in world.contacts
            if q in c.name.lower() or q in c.email.lower() or (c.handle and q in c.handle.lower())]


@impl("contacts")
def add_contact(world: MockWorld, name: str, email: str | None = None, iban: str | None = None,
                handle: str | None = None) -> dict[str, Any]:
    world.contacts.append(Contact(name=name, email=email or "", iban=iban, handle=handle))
    return {"status": "added", "name": name}
