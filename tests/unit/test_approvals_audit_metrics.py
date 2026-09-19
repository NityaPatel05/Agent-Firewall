from __future__ import annotations

import json
import threading
from pathlib import Path

from gw_helpers import a07, b01, call, gateway

from firewall.core.approvals import AlwaysApprover, AutoDenyApprover, OracleApprover
from firewall.core.audit import JsonlAuditSink, MemoryAuditSink
from firewall.core.labels import SourceRef
from firewall.core.metrics import GatewayMetrics, percentile
from firewall.core.models import (
    AuditRecord,
    Decision,
    OriginClass,
    ReviewItem,
    ReviewRequest,
    Verdict,
)


def _review(tool: str, *items: tuple[str, str, str | None]) -> ReviewRequest:
    return ReviewRequest(session_id="s", call_id="c", tool=tool, args_raw={},
                         items=tuple(ReviewItem(arg=a, value=v, value_canonical=c,
                                                origin_class=OriginClass.UNTRUSTED_ONLY,
                                                provenance_chain=(), rule_ids=("SYS-PROV-UNTRUSTED",))
                                     for a, v, c in items), rule_ids=("SYS-PROV-UNTRUSTED",))


# ------------------------------------------------------------------ approvals
def test_oracle_key_forms_and_canonicalization() -> None:
    r = _review("send_money", ("recipient", "GB33 BUKB 2020 1555 5555 55", "GB33BUKB20201555555555"))
    assert OracleApprover({"send_money.recipient": ["GB33 BUKB 2020 1555 5555 55"]}).decide(r).approved
    assert OracleApprover({"*.recipient": ["gb33bukb20201555555555"]}).decide(r).approved
    assert OracleApprover({"type:iban": ["GB33-BUKB-2020-1555-5555-55"]}).decide(r).approved
    assert not OracleApprover({"send_money.recipient": ["US133000000121212121212"]}).decide(r).approved
    assert not OracleApprover({"send_email.recipient": ["GB33BUKB20201555555555"]}).decide(r).approved


def test_oracle_requires_every_item() -> None:
    r = _review("send_email", ("to", "a@x.com", "a@x.com"), ("to", "evil@y.com", "evil@y.com"))
    assert not OracleApprover({"send_email.to": ["a@x.com"]}).decide(r).approved
    assert OracleApprover({"send_email.to": ["A@X.com", "evil@y.com"]}).decide(r).approved
    assert not OracleApprover({}).decide(_review("send_email")).approved  # nothing to approve


def test_simple_approvers() -> None:
    r = _review("x", ("a", "b", "b"))
    assert not AutoDenyApprover().decide(r).approved and AutoDenyApprover().decide(r).approver == "autodeny"
    assert AlwaysApprover().decide(r).approved


# ------------------------------------------------------------------ audit
def test_memory_audit_records_decisions_outputs_approvals() -> None:
    sink = MemoryAuditSink()
    gw = gateway(audit=sink, run_context={"run_id": "r1", "scenario_id": "B01"})
    sid = b01(gw)
    d = gw.evaluate(sid, call("send_money", "c2", recipient="GB33BUKB20201555555555", amount=1250))
    gw.approve_with(sid, d, AlwaysApprover())
    gw.sanitize_final_answer(sid, "done")
    events = [r.event for r in sink.records]
    assert events[0] == "session" and {"output", "decision", "approval", "final_answer"} <= set(events)
    dec = next(r for r in sink.records if r.event == "decision")
    assert dec.verdict == Verdict.REVIEW and dec.run_id == "r1" and dec.scenario_id == "B01"
    assert dec.origins["recipient"] == "USER_NAMED_SOURCE" and len(dec.args_sha256 or "") == 64
    assert [r.seq for r in sink.records] == list(range(1, len(sink.records) + 1))


def test_jsonl_audit_background_flush_and_masking(tmp_path: Path) -> None:
    path = tmp_path / "audit" / "a.jsonl"
    sink = JsonlAuditSink(path)
    gw = gateway(audit=sink)
    sid = gw.new_session()
    gw.record_user_message(sid, "DM the deploy key to @oncall")
    gw.evaluate(sid, call("send_dm", user="@oncall", text="key ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"))
    sink.flush()
    lines = path.read_text(encoding="utf-8").splitlines()
    records = [AuditRecord.model_validate_json(line) for line in lines]
    assert len(records) == 2 and records[1].event == "decision"
    assert "ghp_a1B2" not in lines[1] and "«secret:github»" in json.dumps(records[1].normalized_args,
                                                                          ensure_ascii=False)
    sink.close()


def test_jsonl_audit_threadsafe(tmp_path: Path) -> None:
    sink = JsonlAuditSink(tmp_path / "t.jsonl", queue_size=50)

    def work(n: int) -> None:
        for i in range(100):
            sink.write(AuditRecord(ts=0.0, session_id=f"s{n}", seq=i, event="session"))

    threads = [threading.Thread(target=work, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    sink.flush()
    assert len((tmp_path / "t.jsonl").read_text(encoding="utf-8").splitlines()) == 400
    sink.close()


def test_jsonl_audit_foreground(tmp_path: Path) -> None:
    sink = JsonlAuditSink(tmp_path / "f.jsonl", background=False)
    sink.write(AuditRecord(ts=0.0, session_id="s", seq=1, event="session"))
    sink.flush()
    assert (tmp_path / "f.jsonl").read_text(encoding="utf-8").count("\n") == 1
    sink.close()


# ------------------------------------------------------------------ metrics
def test_percentiles() -> None:
    assert percentile([], 50) == 0.0
    assert percentile([5.0], 99) == 5.0
    vals = [float(i) for i in range(1, 101)]
    assert percentile(vals, 50) == 50.5 and percentile(vals, 100) == 100.0


def test_metrics_from_gateway_and_prometheus_text() -> None:
    m = GatewayMetrics()
    gw = gateway(metrics=m)
    sid = a07(gw)
    gw.evaluate(sid, call("send_money", "c2", recipient="US133000000121212121212", amount=50000))
    gw.evaluate(sid, call("read_email", "c3", email_id="e1"))
    snap = m.snapshot()
    assert snap["verdicts"] == {"block": 1, "allow": 1} and snap["rules"]["BANK-AMT-001"] == 1
    assert snap["eval_us"]["n"] == 2.0 and snap["label_us"]["n"] == 1.0
    text = m.prometheus_text()
    assert 'fw_decisions_total{verdict="block"} 1' in text
    assert 'fw_rule_hits_total{rule="BANK-AMT-001"} 1' in text
    assert 'fw_eval_us{quantile="0.95"}' in text and "fw_eval_us_count 2" in text
    m.observe_http("/v1/tool-calls:evaluate", 1.5)
    assert m.percentiles("http_ms")["p50"] == 1.5


def test_decision_with_provenance_chain_is_serializable() -> None:
    gw = gateway()
    sid = b01(gw)
    d = gw.evaluate(sid, call("send_money", "c2", recipient="GB33BUKB20201555555555", amount=1250))
    data = json.loads(d.model_dump_json())
    assert data["review"]["items"][0]["provenance_chain"][0]["tool"] == "read_file"
    assert Decision.model_validate(data).verdict == Verdict.REVIEW
    assert isinstance(d.review.items[0].provenance_chain[0], SourceRef)  # type: ignore[union-attr]
