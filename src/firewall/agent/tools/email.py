"""Email tools."""

from __future__ import annotations

from typing import Any

from firewall.agent.tools._base import ToolError, impl, next_id, require
from firewall.agent.world import Email, MockWorld


def _view(e: Email) -> dict[str, Any]:
    return {"id": e.id, "sender": e.sender, "sender_name": e.sender_name, "to": e.to, "cc": e.cc,
            "subject": e.subject, "body": e.body, "attachments": e.attachments, "timestamp": e.timestamp,
            "read": e.read, "folder": e.folder}


def _find(world: MockWorld, email_id: str) -> Email:
    for e in world.inbox:
        if e.id == email_id:
            return e
    raise ToolError(f"email {email_id} not found")


def _send(world: MockWorld, to: list[str], subject: str, body: str, *, cc: list[str] | None = None,
          bcc: list[str] | None = None, attachments: list[str] | None = None) -> dict[str, Any]:
    for p in attachments or []:
        require(p in world.files, f"attachment {p} not found")
    e = Email(id=next_id("s", [x.id for x in world.inbox]), sender=world.user_email, sender_name=world.user_name,
              to=list(to), cc=list(cc or []), bcc=list(bcc or []), subject=subject, body=body,
              attachments=list(attachments or []), read=True, folder="sent", timestamp=world.now)
    world.inbox.append(e)
    return {"status": "sent", "id": e.id, "to": e.to, "cc": e.cc, "bcc": e.bcc}


@impl("email")
def list_emails(world: MockWorld, folder: str = "inbox", unread_only: bool = False, limit: int = 20) -> list[dict]:
    items = [e for e in world.inbox if e.folder == folder and (not unread_only or not e.read)]
    items.sort(key=lambda e: e.timestamp, reverse=True)
    return [_view(e) for e in items[:limit]]


@impl("email")
def search_emails(world: MockWorld, query: str, limit: int = 20) -> list[dict]:
    q = query.lower()
    hits = [e for e in world.inbox if q in f"{e.subject} {e.body} {e.sender} {e.sender_name}".lower()]
    return [_view(e) for e in hits[:limit]]


@impl("email")
def read_email(world: MockWorld, email_id: str) -> dict[str, Any]:
    e = _find(world, email_id)
    e.read = True
    return _view(e)


@impl("email")
def send_email(world: MockWorld, to: list[str], subject: str, body: str, cc: list[str] | None = None,
               bcc: list[str] | None = None, attachments: list[str] | None = None) -> dict[str, Any]:
    return _send(world, to, subject, body, cc=cc, bcc=bcc, attachments=attachments)


@impl("email")
def reply_email(world: MockWorld, email_id: str, body: str, cc: list[str] | None = None,
                bcc: list[str] | None = None, attachments: list[str] | None = None) -> dict[str, Any]:
    orig = _find(world, email_id)
    return _send(world, [orig.sender], f"Re: {orig.subject}", body, cc=cc, bcc=bcc, attachments=attachments)


@impl("email")
def forward_email(world: MockWorld, email_id: str, to: list[str], note: str = "") -> dict[str, Any]:
    orig = _find(world, email_id)
    body = f"{note}\n\n---------- Forwarded message ----------\nFrom: {orig.sender}\n{orig.body}".strip()
    return _send(world, to, f"Fwd: {orig.subject}", body, attachments=orig.attachments)


@impl("email")
def draft_email(world: MockWorld, subject: str, body: str, to: list[str] | None = None) -> dict[str, Any]:
    e = Email(id=next_id("d", [x.id for x in world.inbox]), sender=world.user_email, to=list(to or []),
              subject=subject, body=body, folder="drafts", read=True, timestamp=world.now)
    world.inbox.append(e)
    return {"status": "drafted", "id": e.id}


@impl("email")
def delete_email(world: MockWorld, email_id: str) -> dict[str, Any]:
    _find(world, email_id).folder = "trash"
    return {"status": "deleted", "id": email_id}
