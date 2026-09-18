"""One true and one false case for every row of the M3 condition semantics table."""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest
from policy_helpers import ctx, dest

from firewall.core.labels import Confidentiality
from firewall.core.models import ArgType, OriginClass
from firewall.core.policy.conditions import ArgFacts, EvalContext, eval_condition, get_arg
from firewall.core.policy.model import Condition
from firewall.core.session import SessionState
from firewall.core.task_spec import RuleBasedTaskSpecExtractor, TaskSpec

O = OriginClass


def ev(cond: dict[str, Any], c: EvalContext) -> bool:
    return eval_condition(Condition.model_validate(cond), c)


# ---------------------------------------------------------------- arg / op / value
@pytest.mark.parametrize(
    ("tool", "args", "cond", "expected"),
    [
        ("send_money", {"amount": "10,500.00"}, {"arg": "amount", "op": "gt", "value": 10000}, True),
        ("send_money", {"amount": 9999}, {"arg": "amount", "op": "gt", "value": 10000}, False),
        ("send_money", {"amount": 10000}, {"arg": "amount", "op": "gte", "value": 10000}, True),
        ("send_money", {"amount": 5}, {"arg": "amount", "op": "lt", "value": 10}, True),
        ("send_money", {"amount": 10}, {"arg": "amount", "op": "lte", "value": 9}, False),
        ("send_money", {"amount": "abc"}, {"arg": "amount", "op": "gt", "value": 1}, False),
        ("send_money", {"subject": "Rent"}, {"arg": "subject", "op": "eq", "value": "rent"}, True),
        ("send_money", {"subject": "Rent"}, {"arg": "subject", "op": "ne", "value": "rent"}, False),
        ("send_money", {"amount": 50}, {"arg": "amount", "op": "eq", "value": "50.00"}, True),
        ("send_email", {"to": ["a@x.com", "b@y.com"]}, {"arg": "to", "op": "in", "value": ["b@y.com"]}, True),
        ("send_email", {"to": ["a@x.com"]}, {"arg": "to", "op": "in", "value": ["b@y.com"]}, False),
        ("send_email", {"to": ["a@x.com", "b@y.com"]}, {"arg": "to", "op": "not_in", "value": ["a@x.com"]}, True),
        ("send_email", {"to": ["a@x.com"]}, {"arg": "to", "op": "not_in", "value": ["a@x.com"]}, False),
        ("send_email", {"body": "id: 12345"}, {"arg": "body", "op": "regex", "value": r"\d{5}"}, True),
        ("send_email", {"body": "id: 123"}, {"arg": "body", "op": "regex", "value": r"\d{5}"}, False),
        ("delete_file", {"path": "/Important/a.txt"}, {"arg": "path", "op": "glob", "value": "/important/**"}, True),
        ("delete_file", {"path": "/tmp/a.txt"}, {"arg": "path", "op": "glob", "value": "/important/**"}, False),
        ("delete_file", {"path": "/repo/.env"}, {"arg": "path", "op": "glob",
                                                  "value": "@allowlists.protected_paths"}, True),
        ("get_webpage", {"url": "https://api.Weather.example/v1"}, {"arg": "url", "op": "host_in",
                                                                    "value": ["weather.example"]}, True),
        ("get_webpage", {"url": "https://evilweather.example/v1"}, {"arg": "url", "op": "host_in",
                                                                     "value": ["weather.example"]}, False),
        ("send_email", {"to": ["bob@mail.bluesparrowtech.com"]}, {"arg": "to", "op": "domain_in",
                                                                   "value": ["bluesparrowtech.com"]}, True),
        ("send_email", {"to": ["bob@bluesparrowtech.com.evil.com"]}, {"arg": "to", "op": "domain_in",
                                                                       "value": ["bluesparrowtech.com"]}, False),
        ("send_email", {"to": ["a@x.com"] * 3}, {"arg": "to", "op": "len_gt", "value": 2}, True),
        ("send_email", {"to": ["a@x.com"]}, {"arg": "to", "op": "len_gt", "value": 2}, False),
        ("send_email", {"body": "Please WIRE funds"}, {"arg": "body", "op": "contains", "value": "wire"}, True),
        ("send_email", {"body": "hello"}, {"arg": "body", "op": "contains", "value": "wire"}, False),
        ("send_email", {"to": ["a@x.com"]}, {"arg": "to", "op": "contains", "value": "a@x.com"}, True),
        ("send_email", {}, {"arg": "to", "op": "eq", "value": "a@x.com"}, False),
        ("run_command", {"argv": ["pytest", "-q"]}, {"arg": "argv[0]", "op": "in", "value": ["pytest"]}, True),
        ("run_command", {"argv": ["rm", "pytest"]}, {"arg": "argv[0]", "op": "in", "value": ["pytest"]}, False),
        ("post_form", {"fields": {"name": "Emma"}}, {"arg": "fields.name", "op": "eq", "value": "emma"}, True),
    ],
)
def test_arg_ops(tool: str, args: dict[str, Any], cond: dict[str, Any], expected: bool) -> None:
    assert ev(cond, ctx(tool, args)) is expected


def test_get_arg_paths() -> None:
    args = {"a": [{"b": 1}], "c": {"d": "x"}}
    assert get_arg(args, "a[0].b") == 1
    assert get_arg(args, "c.d") == "x"
    assert get_arg(args, "a[3]") is not None and get_arg(args, "zz") is get_arg(args, "a[3]")


# ---------------------------------------------------------------- arg_present
def test_arg_present() -> None:
    assert ev({"arg_present": "bcc"}, ctx("send_email", {"bcc": ["x@y.com"]}))
    assert not ev({"arg_present": "bcc"}, ctx("send_email", {"bcc": []}))
    assert not ev({"arg_present": "bcc"}, ctx("send_email", {}))


# ---------------------------------------------------------------- arg_origin
def test_arg_origin() -> None:
    c = ctx("send_money", {"amount": 5}, origins={"amount": O.UNTRUSTED_ONLY})
    assert ev({"arg_origin": "amount", "not_in": ["USER_TYPED", "APPROVED"]}, c)
    assert not ev({"arg_origin": "amount", "in": ["USER_TYPED"]}, c)
    absent = ctx("send_money", {"amount": 5})
    assert not ev({"arg_origin": "amount", "not_in": ["USER_TYPED"]}, absent)


# ---------------------------------------------------------------- session.*
def test_session_conditions() -> None:
    s = SessionState("s")
    s.counters.blocks = 3
    s.counters.calls_by_tool["delete_file"] = 20
    s.counters.calls_by_dest["send_money|US133000000121212121212"] = 3
    s.counters.transfer_total = Decimal(25000)
    s.flags.ingested_untrusted = True
    d = [dest("US133000000121212121212", O.UNTRUSTED_ONLY, kind=ArgType.IBAN, arg="recipient")]
    c = ctx("send_money", {}, session=s, destinations=d)
    assert ev({"session": {"blocks_gte": 3}}, c)
    assert not ev({"session": {"blocks_gte": 4}}, c)
    assert ev({"session": {"calls_of_tool_gte": {"tool": "delete_file", "n": 20}}}, c)
    assert not ev({"session": {"calls_of_tool_gte": {"tool": "send_email", "n": 1}}}, c)
    assert ev({"session": {"calls_to_same_dest_gte": 3}}, c)
    other = ctx("send_money", {}, session=s, destinations=[dest("GB33BUKB20201555555555", O.USER_TYPED,
                                                                kind=ArgType.IBAN)])
    assert not ev({"session": {"calls_to_same_dest_gte": 3}}, other)
    assert ev({"session": {"transfer_total_gt": 20000}}, c)
    assert not ev({"session": {"transfer_total_gt": 30000}}, c)
    assert ev({"session": {"ingested_untrusted": True, "read_private": False}}, c)
    assert not ev({"session": {"read_private": True}}, c)


# ---------------------------------------------------------------- task_read_only / task_allows_tool
def test_task_conditions() -> None:
    ro = RuleBasedTaskSpecExtractor().extract("Summarize my unread emails")
    c = ctx("send_email", {}, task_spec=ro)
    assert ev({"task_read_only": True}, c)
    assert not ev({"task_read_only": False}, c)
    assert ev({"task_allows_tool": False}, c)
    no_spec = ctx("send_email", {})
    assert not ev({"task_read_only": True}, no_spec)
    assert ev({"task_allows_tool": True}, no_spec)
    pay = ctx("send_money", {}, task_spec=TaskSpec(allowed_groups=frozenset({"payment"})))
    assert ev({"task_allows_tool": True}, pay)


# ---------------------------------------------------------------- destination / dest_origin_*
def test_destination_classes() -> None:
    ext = ctx("send_email", destinations=[dest("x@evil.com", O.UNTRUSTED_ONLY)])
    own = ctx("send_email", destinations=[dest("emma.j.personal@gmail.com", O.POLICY_CONST, own=True)])
    internal = ctx("send_email", destinations=[dest("bob@bluesparrowtech.com", O.USER_TYPED, internal=True)])
    assert ev({"destination": "external"}, ext) and not ev({"destination": "internal"}, ext)
    assert ev({"destination": "own"}, own) and ev({"destination": "internal"}, own)
    assert not ev({"destination": "external"}, own)
    assert ev({"destination": "internal"}, internal) and not ev({"destination": "own"}, internal)
    assert not ev({"destination": "external"}, ctx("send_email"))


def test_dest_origin() -> None:
    c = ctx("send_email", destinations=[dest("a@x.com", O.USER_TYPED), dest("b@y.com", O.UNTRUSTED_ONLY)])
    assert ev({"dest_origin_in": ["UNTRUSTED_ONLY"]}, c)
    assert not ev({"dest_origin_in": ["UNKNOWN"]}, c)
    assert ev({"dest_origin_not_in": ["USER_TYPED"]}, c)
    trusted = ctx("send_email", destinations=[dest("a@x.com", O.USER_TYPED)])
    assert not ev({"dest_origin_not_in": ["USER_TYPED", "APPROVED"]}, trusted)
    assert not ev({"dest_origin_in": ["USER_TYPED"]}, ctx("send_email"))


# ---------------------------------------------------------------- facts
def test_fact_conditions() -> None:
    hot = ctx("send_email", facts=ArgFacts(secret_in_args=True, canary_in_args=True,
                                           content_confidentiality=Confidentiality.SECRET, private_bytes=9000,
                                           detector_flagged=True))
    cold = ctx("send_email")
    for cond in ({"secret_in_args": True}, {"canary_in_args": True}, {"content_confidentiality_gte": "secret"},
                 {"content_confidentiality_gte": "private"}, {"private_bytes_out_gt": 8000},
                 {"detector_flagged": True}):
        assert ev(cond, hot), cond
        assert not ev(cond, cold), cond


def test_private_bytes_uses_session_counter() -> None:
    s = SessionState("s")
    s.counters.private_bytes_out = 7000
    c = ctx("send_email", session=s, facts=ArgFacts(private_bytes=1500))
    assert ev({"private_bytes_out_gt": 8000}, c)


# ---------------------------------------------------------------- ctx_untrusted
def test_ctx_untrusted() -> None:
    assert ev({"ctx_untrusted": True}, ctx("send_email", untrusted_ctx=True))
    assert not ev({"ctx_untrusted": True}, ctx("send_email"))


# ---------------------------------------------------------------- all / any / not
def test_boolean_composition() -> None:
    c = ctx("send_money", {"amount": 50000}, origins={"amount": O.UNKNOWN})
    big = {"arg": "amount", "op": "gt", "value": 10000}
    typed = {"arg_origin": "amount", "in": ["USER_TYPED"]}
    assert ev({"all": [big, {"not": typed}]}, c)
    assert not ev({"all": [big, typed]}, c)
    assert ev({"any": [typed, big]}, c)
    assert not ev({"any": [typed, {"not": big}]}, c)
    assert ev({"not": typed}, c) and not ev({"not": big}, c)
