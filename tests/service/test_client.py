from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from firewall.agent.demos import DEMOS
from firewall.agent.run import EpisodeConfig, run_episode
from firewall.core.approvals import OracleApprover
from firewall.core.gateway import Gateway
from firewall.core.models import ApprovalResult, ToolCall, Verdict
from firewall.core.registry import ToolRegistry
from firewall.core.task_spec import TaskSpec
from firewall.llm.scripted import ScriptedChatModel
from firewall.service.app import create_app
from firewall.service.client import (
    GatewayHTTPError,
    RemoteConflictError,
    RemoteGateway,
    RemoteUnknownSessionError,
)
from firewall.service.store import SessionStore


@pytest.fixture
def remote(tmp_path: Path) -> Iterator[RemoteGateway]:
    with TestClient(create_app(audit_path=tmp_path / "audit.jsonl")) as tc:
        yield RemoteGateway(client=tc)


def _call(tool: str, cid: str = "c1", **args: Any) -> ToolCall:
    return ToolCall(call_id=cid, tool=tool, args=args)


def test_every_method_round_trips(remote: RemoteGateway) -> None:
    sid = remote.new_session("r1", own_emails=["emma.j.personal@gmail.com"])
    assert remote.last_session is not None and remote.last_session.policy_id == "all"
    with pytest.raises(RemoteConflictError):
        remote.new_session("r1")
    assert remote.record_system_message(sid, "system prompt").kind.value == "system"
    assert remote.record_user_message(sid, "Pay the invoice attached (invoice_0425.pdf)").entry_id == "e2"
    out = remote.label_output(sid, _call("read_file", "r", path="/finance/invoice_0425.pdf"),
                              "INVOICE 0425. Amount due 1,250.00 EUR. IBAN GB33 BUKB 2020 1555 5555 55")
    assert out.label.integrity == 0 and out.entry_ids
    call = _call("send_money", "c2", recipient="GB33BUKB20201555555555", amount=1250)
    d = remote.evaluate(sid, call)
    assert d.verdict == Verdict.REVIEW and d.review is not None and d.review.items[0].arg == "recipient"
    d2 = remote.record_approval(sid, d, ApprovalResult(approved=True, approver="human"))
    assert d2.verdict == Verdict.ALLOW
    remote.commit(sid, call, d2, executed=True)
    assert remote.provenance(sid)["counters"]["calls_by_tool"] == {"send_money": 1}
    summary = remote.record_summary(sid, "paid the invoice", ["e3"])
    assert summary.kind.value == "summary"
    spec = ToolRegistry.from_yaml().get("weather__get_forecast")
    assert spec is not None and remote.observe_tool_definitions(sid, [spec]) == []
    assert remote.sanitize_final_answer(sid, "plain text").changed is False
    remote.set_task_spec(sid, TaskSpec(source="fixture", read_only=True))
    assert remote.provenance(sid)["task_spec"]["source"] == "fixture"
    assert remote.healthz()["status"] == "ok"
    assert any(r["event"] == "decision" for r in remote.audit(sid))
    remote.close_session(sid)
    with pytest.raises(RemoteUnknownSessionError):
        remote.evaluate(sid, call)
    with pytest.raises(KeyError):  # mirrors the in-process exception type
        remote.provenance(sid)
    assert issubclass(RemoteUnknownSessionError, GatewayHTTPError)


def _strip(decisions: list[Any]) -> list[dict[str, Any]]:
    return [d.model_dump(mode="json", exclude={"eval_us"}) for d in decisions]


def test_parity_pay_invoice_benign_remote_vs_in_process(remote: RemoteGateway) -> None:
    demo = DEMOS["pay-invoice-benign"]
    traces = []
    for gw in (Gateway.from_config(), remote):
        cfg = EpisodeConfig(episode_id=demo.name, user_prompt=demo.prompt, world=demo.world(),
                            model=ScriptedChatModel(steps=list(demo.script)), gateway=gw,
                            approver=OracleApprover(demo.legit))
        traces.append(run_episode(cfg))
    local, http = traces
    assert [d.verdict for d in local.decisions] == [Verdict.ALLOW, Verdict.REVIEW, Verdict.ALLOW]
    assert _strip(local.decisions) == _strip(http.decisions)
    assert local.final_answer == http.final_answer
    assert local.world_after.bank.transactions[-1].recipient == http.world_after.bank.transactions[-1].recipient


def test_parity_attack_demo(remote: RemoteGateway) -> None:
    demo = DEMOS["pay-bill-attack"]
    traces = []
    for gw in (Gateway.from_config(), remote):
        cfg = EpisodeConfig(episode_id=demo.name, user_prompt=demo.prompt, world=demo.world(),
                            model=ScriptedChatModel(steps=list(demo.script)), gateway=gw)
        traces.append(run_episode(cfg))
    assert _strip(traces[0].decisions) == _strip(traces[1].decisions)
    assert traces[1].decisions[-1].verdict == Verdict.BLOCK


def test_session_store_ttl_eviction() -> None:
    closed: list[str] = []
    now = [0.0]
    store = SessionStore(closed.append, ttl_s=10, clock=lambda: now[0])
    store.touch("a")
    now[0] = 5
    store.touch("b")
    now[0] = 12
    assert store.sweep() == ["a"] and closed == ["a"] and len(store) == 1
    store.forget("b")
    assert len(store) == 0
