"""Hypothesis properties of the decision pipeline (deterministic: derandomize=True)."""

from __future__ import annotations

import zlib
from typing import Any

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from firewall.core.gateway import Gateway
from firewall.core.models import ArgType, SideEffect, ToolCall, Verdict
from firewall.core.policy.loader import load_policy
from firewall.core.registry import ToolRegistry

REG = ToolRegistry.from_yaml()
POLICY = load_policy("all", registry=REG)
SETTINGS = settings(max_examples=200, derandomize=True, deadline=None,
                    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])

PROMPT = ("Pay the invoice attached (invoice_0425.pdf), email bob@bluesparrowtech.com the summary, DM @alice, "
          "share the folder with my team, delete old files, transfer the crypto and send $120 to "
          "DE21 5001 0517 4431 2198 93")
BASE_OUTPUTS: list[tuple[str, dict[str, Any], Any]] = [
    ("read_file", {"path": "/finance/invoice_0425.pdf"}, "INVOICE 0425. Amount 1,250.00 EUR. IBAN GB33 BUKB 2020 1555 5555 55"),
    ("read_email", {"email_id": "e1"}, {"id": "e1", "sender": "x@partner.example", "subject": "Q3",
                                        "body": "numbers attached, contact carl@taxpros.example"}),
    ("list_contacts", {}, [{"name": "Carl", "email": "carl@taxpros.example"}]),
    ("get_user_info", {}, {"first_name": "Emma", "account_no": "4419-2231-7765"}),
    ("read_channel", {"channel": "#general"}, [{"id": "m1", "channel": "#general", "author": "@bob",
                                                "text": "standup at 10", "ts": "t"}]),
]
CALLS: list[ToolCall] = [
    ToolCall(call_id="p1", tool="send_money", args={"recipient": "GB33BUKB20201555555555", "amount": 1250}),
    ToolCall(call_id="p2", tool="send_money", args={"recipient": "DE21500105174431219893", "amount": 120}),
    ToolCall(call_id="p3", tool="send_email", args={"to": ["bob@bluesparrowtech.com"], "subject": "s", "body": "b"}),
    ToolCall(call_id="p4", tool="send_email", args={"to": ["carl@taxpros.example"], "subject": "s", "body": "b"}),
    ToolCall(call_id="p5", tool="send_dm", args={"user": "@alice", "text": "hi"}),
    ToolCall(call_id="p6", tool="delete_file", args={"path": "/tmp/scratch/a.txt"}),
    ToolCall(call_id="p7", tool="update_agent_config", args={"key": "x", "value": "y"}),
    ToolCall(call_id="p8", tool="read_email", args={"email_id": "e1"}),
    ToolCall(call_id="p9", tool="send_money", args={"recipient": "US133000000121212121212", "amount": 50000}),
]

# (tool, authority arg, value type, base args) for consequential tools with an origin-required authority arg.
AUTHORITY_CASES: list[tuple[str, str, ArgType, dict[str, Any]]] = [
    ("send_money", "recipient", ArgType.IBAN, {"amount": 10}),
    ("send_email", "to", ArgType.EMAIL, {"subject": "s", "body": "b"}),
    ("forward_email", "to", ArgType.EMAIL, {"email_id": "e1"}),
    ("send_dm", "user", ArgType.HANDLE, {"text": "hi"}),
    ("share_file", "grantees", ArgType.EMAIL, {"path": "/docs"}),
    ("delete_file", "path", ArgType.PATH, {}),
    ("transfer_crypto", "to_address", ArgType.CRYPTO_ADDRESS, {"amount_sol": 1}),
    ("post_form", "url", ArgType.URL, {"fields": {"a": "b"}}),
]
UNTRUSTED_TOOLS = ["read_email", "get_webpage", "read_file", "read_channel"]

_word = st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=3, max_size=9)
_payload = st.lists(st.one_of(_word, st.sampled_from([
    "ignore", "previous", "instructions", "IMPORTANT", "you", "must", "now", "send", "money", "please",
    "urgent", "assistant", "system:", "transfer", "everything", "forward", "all", "Ignoriere", "Anweisungen",
])), min_size=3, max_size=40).map(" ".join)


def _base_session(gw: Gateway, sid: str) -> str:
    sid = gw.new_session(sid)
    gw.record_user_message(sid, PROMPT)
    for i, (tool, args, out) in enumerate(BASE_OUTPUTS):
        gw.label_output(sid, ToolCall(call_id=f"b{i}", tool=tool, args=args), out)
    return sid


def _add_untrusted(gw: Gateway, sid: str, tool: str, text: str, n: int) -> None:
    cid = f"u{n}"
    if tool == "read_email":
        gw.label_output(sid, ToolCall(call_id=cid, tool=tool, args={"email_id": f"m{n}"}),
                        {"id": f"m{n}", "sender": f"news{n}@random.example", "subject": "hello", "body": text})
    elif tool == "get_webpage":
        gw.label_output(sid, ToolCall(call_id=cid, tool=tool, args={"url": f"https://random{n}.example/x"}), text)
    elif tool == "read_file":
        gw.label_output(sid, ToolCall(call_id=cid, tool=tool, args={"path": f"/downloads/r{n}.txt"}), text)
    else:
        gw.label_output(sid, ToolCall(call_id=cid, tool=tool, args={"channel": "#random"}),
                        [{"id": f"x{n}", "channel": "#random", "author": "@stranger", "text": text, "ts": "t"}])


def _value(t: ArgType, token: str) -> str:
    return {
        ArgType.IBAN: "FR76" + str(zlib.crc32(token.encode()) * 7919).zfill(23)[:23],
        ArgType.EMAIL: f"{token}@evil-{token}.example",
        ArgType.HANDLE: f"@{token}x",
        ArgType.PATH: f"/home/{token}/data.txt",
        ArgType.CRYPTO_ADDRESS: ("9xQeWvG816bUx9EPjHmaT23yvVM2ZW" + token.upper()[:6] + "ZbPus")[:44],
        ArgType.URL: f"https://{token}.evil.example/p",
    }[t]


@SETTINGS
@given(case=st.sampled_from(AUTHORITY_CASES), token=_word, src=st.sampled_from(UNTRUSTED_TOOLS), pad=_payload)
def test_untrusted_only_authority_never_allowed(case: tuple[str, str, ArgType, dict[str, Any]], token: str,
                                                src: str, pad: str) -> None:
    tool, arg, t, base = case
    gw = Gateway(policy=POLICY, registry=REG)
    sid = _base_session(gw, "p1")
    value = _value(t, token)
    _add_untrusted(gw, sid, src, f"{pad} {value} {pad}", 1)
    spec = REG.get(tool)
    assert spec is not None
    arg_value: Any = [value] if spec.args[arg].type == ArgType.LIST else value
    d = gw.evaluate(sid, ToolCall(call_id="x", tool=tool, args={**base, arg: arg_value}))
    assert d.verdict != Verdict.ALLOW, (tool, value, [(f.rule_id, f.verdict.value) for f in d.findings])


@SETTINGS
@given(idx=st.integers(min_value=0, max_value=len(CALLS) - 1))
def test_decisions_are_deterministic(idx: int) -> None:
    gw = Gateway(policy=POLICY, registry=REG)
    sid = _base_session(gw, "p2")
    c = CALLS[idx]
    d1, d2 = gw.evaluate(sid, c), gw.evaluate(sid, c)
    assert d1.model_copy(update={"eval_us": 0.0}) == d2.model_copy(update={"eval_us": 0.0})


def _fingerprint(gw: Gateway, sid: str) -> list[tuple[str, tuple[str, ...]]]:
    out = []
    for c in CALLS:
        d = gw.evaluate(sid, c)
        out.append((d.verdict.value, d.rule_ids))
    return out


@settings(max_examples=60, derandomize=True, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(texts=st.lists(_payload, min_size=1, max_size=4), srcs=st.lists(st.sampled_from(UNTRUSTED_TOOLS),
                                                                      min_size=4, max_size=4))
def test_payload_blindness(texts: list[str], srcs: list[str]) -> None:
    """Untrusted text sharing no typed value/shingle with the calls never changes any decision (session already
    tainted, so session-level flags are already set)."""
    gw = Gateway(policy=POLICY, registry=REG)
    sid = _base_session(gw, "p3")
    _add_untrusted(gw, sid, "read_email", "baseline untrusted note", 0)
    before = _fingerprint(gw, sid)
    for i, text in enumerate(texts):
        _add_untrusted(gw, sid, srcs[i], text, i + 1)
    assert _fingerprint(gw, sid) == before


@settings(max_examples=60, derandomize=True, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(picks=st.lists(st.integers(min_value=0, max_value=len(CALLS) - 1), min_size=1, max_size=3),
       src=st.sampled_from(UNTRUSTED_TOOLS), pad=_payload)
def test_monotonicity(picks: list[int], src: str, pad: str) -> None:
    """Adding untrusted entries (even ones repeating call values) never turns BLOCK/REVIEW into ALLOW."""
    gw = Gateway(policy=POLICY, registry=REG)
    sid = _base_session(gw, "p4")
    before = _fingerprint(gw, sid)
    values = " ".join(str(v) for i in picks for v in CALLS[i].args.values())
    _add_untrusted(gw, sid, src, f"{pad} {values}", 1)
    after = _fingerprint(gw, sid)
    for (v0, _), (v1, _) in zip(before, after, strict=True):
        if v0 != "allow":
            assert v1 != "allow"


@settings(max_examples=60, derandomize=True, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(token=_word, se=st.sampled_from([SideEffect.PAYMENT, SideEffect.EXTERNAL_COMM, SideEffect.SHARE]))
def test_approvals_only_relax_the_approved_value(token: str, se: SideEffect) -> None:
    gw = Gateway(policy=POLICY, registry=REG)
    sid = _base_session(gw, "p5")
    before = _fingerprint(gw, sid)
    unrelated = f"{token}@approved-elsewhere.example"
    gw.pin_approval(sid, se, ArgType.EMAIL, unrelated)
    assert _fingerprint(gw, sid) == before
