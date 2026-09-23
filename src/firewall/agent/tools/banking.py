"""Banking tools (AgentDojo-banking-like)."""

from __future__ import annotations

from typing import Any

from firewall.agent.tools._base import ToolError, dec, impl, next_id, num, require
from firewall.agent.world import MockWorld, Transaction


def _tx(t: Transaction) -> dict[str, Any]:
    return {"id": t.id, "sender": t.sender, "recipient": t.recipient, "amount": num(t.amount), "subject": t.subject,
            "date": t.date, "recurring": t.recurring}


def _iban(v: str) -> str:
    return "".join(str(v).split()).replace("-", "").upper()


@impl("banking")
def get_balance(world: MockWorld) -> dict[str, Any]:
    return {"balance": num(world.bank.balance), "currency": "EUR"}


@impl("banking")
def get_iban(world: MockWorld) -> dict[str, Any]:
    return {"iban": world.bank.own_iban}


@impl("banking")
def get_user_info(world: MockWorld) -> dict[str, Any]:
    return dict(world.bank.user_info)


@impl("banking")
def get_most_recent_transactions(world: MockWorld, n: int = 10) -> list[dict]:
    txs = sorted(world.bank.transactions, key=lambda t: t.date, reverse=True)
    return [_tx(t) for t in txs[:n]]


@impl("banking")
def get_scheduled_transactions(world: MockWorld) -> list[dict]:
    return [_tx(t) for t in world.bank.scheduled]


@impl("banking")
def send_money(world: MockWorld, recipient: str, amount: Any, subject: str = "", date: str | None = None) -> dict:
    amt = dec(amount)
    require(amt > 0, "amount must be positive")
    require(amt <= world.bank.balance, "insufficient funds")
    t = Transaction(id=next_id("t", [x.id for x in world.bank.transactions]), sender=world.bank.own_iban,
                    recipient=_iban(recipient), amount=amt, subject=subject, date=(date or world.now)[:10])
    world.bank.transactions.append(t)
    world.bank.balance -= amt
    return {"status": "sent", "id": t.id, "recipient": t.recipient, "amount": num(amt)}


@impl("banking")
def schedule_transaction(world: MockWorld, recipient: str, amount: Any, date: str, subject: str = "",
                         recurring: bool = False) -> dict[str, Any]:
    t = Transaction(id=next_id("s", [x.id for x in world.bank.scheduled]), sender=world.bank.own_iban,
                    recipient=_iban(recipient), amount=dec(amount), subject=subject, date=date[:10],
                    recurring=recurring)
    world.bank.scheduled.append(t)
    return {"status": "scheduled", "id": t.id}


@impl("banking")
def update_scheduled_transaction(world: MockWorld, id: str, recipient: str | None = None,
                                 amount: Any = None, subject: str | None = None, date: str | None = None,
                                 recurring: bool | None = None) -> dict[str, Any]:
    for t in world.bank.scheduled:
        if t.id == id:
            if recipient is not None:
                t.recipient = _iban(recipient)
            if amount is not None:
                t.amount = dec(amount)
            if subject is not None:
                t.subject = subject
            if date is not None:
                t.date = date[:10]
            if recurring is not None:
                t.recurring = recurring
            return {"status": "updated", "transaction": _tx(t)}
    raise ToolError(f"scheduled transaction {id} not found")


@impl("banking")
def update_password(world: MockWorld, password: str) -> dict[str, Any]:
    world.bank.password = password
    return {"status": "password updated"}


@impl("banking")
def update_user_info(world: MockWorld, first_name: str | None = None, last_name: str | None = None,
                     street: str | None = None, city: str | None = None) -> dict[str, Any]:
    for k, v in {"first_name": first_name, "last_name": last_name, "street": street, "city": city}.items():
        if v is not None:
            world.bank.user_info[k] = v
    return {"status": "updated", "user_info": dict(world.bank.user_info)}
