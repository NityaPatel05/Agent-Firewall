"""Crypto wallet tools."""

from __future__ import annotations

from typing import Any

from firewall.agent.tools._base import dec, impl, num, require
from firewall.agent.world import MockWorld


@impl("wallet")
def get_wallet_balance(world: MockWorld) -> dict[str, Any]:
    return {"own_address": world.wallet.own_address, "balance_sol": num(world.wallet.balance_sol)}


@impl("wallet")
def transfer_crypto(world: MockWorld, to_address: str, amount_sol: Any) -> dict[str, Any]:
    amt = dec(amount_sol)
    require(amt <= world.wallet.balance_sol, "insufficient SOL")
    world.wallet.balance_sol -= amt
    world.wallet.transfers.append({"to": to_address, "amount_sol": num(amt)})
    return {"status": "sent", "to": to_address, "amount_sol": num(amt)}
