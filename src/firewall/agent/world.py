"""MockWorld: deterministic, in-memory state behind the mock tools (offline, no I/O besides loading YAML)."""

from __future__ import annotations

import copy
import re
from collections.abc import Sequence
from decimal import Decimal
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

from firewall.resources import data_path

NOW = "2026-11-01T09:00:00"


class Email(BaseModel):
    id: str
    sender: str
    sender_name: str = ""
    to: list[str]
    cc: list[str] = Field(default_factory=list)
    bcc: list[str] = Field(default_factory=list)
    subject: str
    body: str
    attachments: list[str] = Field(default_factory=list)
    read: bool = False
    folder: Literal["inbox", "sent", "drafts", "trash"] = "inbox"
    timestamp: str = NOW


class Event(BaseModel):
    id: str
    title: str
    start: str
    end: str
    participants: list[str] = Field(default_factory=list)
    organizer: str
    location: str = ""
    description: str = ""
    status: Literal["pending", "accepted", "cancelled"] = "accepted"


class Reminder(BaseModel):
    id: str
    title: str
    at: str


class Transaction(BaseModel):
    id: str
    sender: str
    recipient: str
    amount: Decimal
    subject: str
    date: str
    recurring: bool = False


class BankState(BaseModel):
    own_iban: str
    balance: Decimal
    transactions: list[Transaction]
    scheduled: list[Transaction]
    password: str
    user_info: dict[str, str]


class FileEntry(BaseModel):
    path: str
    content: str
    owner: str = "emma"
    shared_with: dict[str, str] = Field(default_factory=dict)


class WebPage(BaseModel):
    url: str
    text: str
    status: int = 200


class HttpRequest(BaseModel):
    method: Literal["GET", "POST", "PUT"]
    url: str
    body: dict[str, Any] | None = None


class ChatMessage(BaseModel):
    id: str
    channel: str
    author: str
    text: str
    ts: str = NOW


class SlackState(BaseModel):
    channels: dict[str, list[ChatMessage]]
    users: list[str]
    dms: list[ChatMessage] = Field(default_factory=list)
    self_handle: str = "@emma"
    channel_members: dict[str, list[str]] = Field(default_factory=dict)


class Hotel(BaseModel):
    id: str
    name: str
    city: str
    price: Decimal
    description: str
    reviews: list[str] = Field(default_factory=list)


class Flight(BaseModel):
    id: str
    origin: str
    dest: str
    date: str
    price: Decimal
    airline: str


class TravelState(BaseModel):
    hotels: list[Hotel]
    flights: list[Flight]
    bookings: list[dict[str, Any]] = Field(default_factory=list)


class MCPToolDef(BaseModel):
    name: str
    description: str
    input_schema: dict[str, Any] = Field(default_factory=dict)
    behavior: str


class MCPServer(BaseModel):
    name: str
    source: str
    tools: list[MCPToolDef]
    version: int = 1
    rug_pull_after_calls: int | None = None
    rug_pull_patch: dict[str, str] | None = None
    calls: int = 0


class ShellState(BaseModel):
    executed: list[list[str]] = Field(default_factory=list)
    firewall_enabled: bool = True
    files_written: list[str] = Field(default_factory=list)


class WalletState(BaseModel):
    own_address: str
    balance_sol: Decimal
    keyfile_path: str
    transfers: list[dict[str, Any]] = Field(default_factory=list)


class Contact(BaseModel):
    name: str
    email: str
    iban: str | None = None
    handle: str | None = None


class ActionRecord(BaseModel):
    seq: int
    tool: str
    args: dict[str, Any]
    ok: bool
    note: str = ""


class WorldOverride(BaseModel):
    """Set or append a value at a world path (see `apply_path`)."""

    path: str
    value: Any
    mode: Literal["set", "append"] = "set"


class InjectionSpec(BaseModel):
    """Attacker-controlled text placed at a world path."""

    path: str
    text: str
    mode: Literal["append", "replace", "insert_marker"] = "append"


class MockWorld(BaseModel):
    now: str = NOW
    user_name: str
    user_email: str
    user_handle: str
    inbox: list[Email]
    calendar: list[Event]
    reminders: list[Reminder] = Field(default_factory=list)
    bank: BankState
    files: dict[str, FileEntry]
    web: dict[str, WebPage]
    http_log: list[HttpRequest] = Field(default_factory=list)
    slack: SlackState
    travel: TravelState
    mcp: dict[str, MCPServer]
    installed_mcp: list[str] = Field(default_factory=list)
    shell: ShellState = Field(default_factory=ShellState)
    memory: dict[str, str] = Field(default_factory=dict)
    wallet: WalletState
    contacts: list[Contact]
    agent_config: dict[str, str] = Field(default_factory=dict)
    log: list[ActionRecord] = Field(default_factory=list)

    @classmethod
    def load(cls, name_or_path: str = "base") -> MockWorld:
        """Load `eval/scenarios/worlds/<name>.yaml` (or a path)."""
        p = Path(name_or_path)
        path = p if p.suffix in (".yaml", ".yml") and p.exists() else data_path("scenarios", "worlds",
                                                                                f"{name_or_path}.yaml")
        return cls.model_validate(copy.deepcopy(_parse_yaml(str(path), path.stat().st_mtime_ns)))

    def copy_deep(self) -> MockWorld:
        return self.model_copy(deep=True)

    def apply_overrides(self, overrides: Sequence[WorldOverride]) -> MockWorld:
        data = self.model_dump(mode="python")
        for o in overrides:
            apply_path(data, o.path, o.value, mode=o.mode)
        return MockWorld.model_validate(data)

    def render_injections(self, injections: Sequence[InjectionSpec]) -> MockWorld:
        data = self.model_dump(mode="python")
        for inj in injections:
            if inj.path.endswith("[+]"):
                apply_path(data, inj.path, inj.text, mode="append")
                continue
            current = get_path(data, inj.path)
            if inj.mode == "replace" or current is None:
                new: Any = inj.text
            elif inj.mode == "insert_marker":
                new = str(current).replace("{INJECTION}", inj.text)
            else:
                new = f"{current}\n\n{inj.text}"
            apply_path(data, inj.path, new, mode="set")
        return MockWorld.model_validate(data)

    def record(self, tool: str, args: dict[str, Any], ok: bool = True, note: str = "") -> None:
        self.log.append(ActionRecord(seq=len(self.log) + 1, tool=tool, args=dict(args), ok=ok, note=note))


@lru_cache(maxsize=32)
def _parse_yaml(path: str, mtime_ns: int) -> Any:
    """Parsed world YAML, cached per (path, mtime); callers deep-copy before use."""
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


# ------------------------------------------------------------------ path syntax
# name | .name | [key=value] (select list item) | ["key"] (dict key) | [+] (append) | [3] (index)
_TOKEN_RE = re.compile(r"""\.?([A-Za-z_][\w-]*)|\[\+\]|\[(\d+)\]|\[(\w+)=([^\]]+)\]|\[["']([^"']*)["']\]""")


class PathError(KeyError):
    pass


def _tokens(path: str) -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    pos = 0
    while pos < len(path):
        m = _TOKEN_RE.match(path, pos)
        if m is None or m.end() == pos:
            raise PathError(f"bad path syntax at {path[pos:]!r} in {path!r}")
        name, index, sel_key, sel_val, key = m.groups()
        if name is not None:
            out.append(("key", name))
        elif m.group(0) == "[+]":
            out.append(("append", None))
        elif index is not None:
            out.append(("index", int(index)))
        elif sel_key is not None:
            out.append(("select", (sel_key, sel_val)))
        else:
            out.append(("key", key))
        pos = m.end()
    return out


def _step(container: Any, tok: tuple[str, Any], path: str) -> Any:
    kind, arg = tok
    if kind == "key":
        if not isinstance(container, dict) or arg not in container:
            raise PathError(f"{arg!r} not found in {path!r}")
        return container[arg]
    if kind == "index":
        return container[arg]
    if kind == "select":
        k, v = arg
        for item in container:
            if isinstance(item, dict) and str(item.get(k)) == v:
                return item
        raise PathError(f"no item with {k}={v} in {path!r}")
    raise PathError(f"[+] only allowed at the end of {path!r}")


def get_path(data: dict[str, Any], path: str) -> Any:
    cur: Any = data
    for tok in _tokens(path):
        cur = _step(cur, tok, path)
    return cur


def apply_path(data: dict[str, Any], path: str, value: Any, *, mode: Literal["set", "append"] = "set") -> None:
    toks = _tokens(path)
    parent: Any = data
    for tok in toks[:-1]:
        parent = _step(parent, tok, path)
    kind, arg = toks[-1]
    if kind == "append" or mode == "append":
        target = parent if kind == "append" else _step(parent, toks[-1], path)
        if not isinstance(target, list):
            raise PathError(f"cannot append to non-list at {path!r}")
        target.append(value)
    elif kind == "key" or kind == "index":
        parent[arg] = value
    elif kind == "select":
        k, v = arg
        for i, item in enumerate(parent):
            if isinstance(item, dict) and str(item.get(k)) == v:
                parent[i] = value
                return
        raise PathError(f"no item with {k}={v} in {path!r}")
