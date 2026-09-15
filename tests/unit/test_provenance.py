from __future__ import annotations

from typing import Any

import pytest

from firewall.core.labels import Confidentiality, Integrity, Label, SourceKind
from firewall.core.models import ArgRole, ArgType, OriginClass, SideEffect, ToolCall
from firewall.core.provenance import (
    Ledger,
    ShingleIndex,
    Signal,
    ValueIndex,
    compute_output_labels,
    resolve_origin,
)
from firewall.core.registry import ArgSpec, ToolRegistry, ToolSpec
from firewall.core.session import ApprovalStore
from firewall.core.task_spec import NamedSource, TaskSpec

REG = ToolRegistry.from_yaml()


def _spec(name: str) -> ToolSpec:
    spec = REG.get(name)
    assert spec is not None
    return spec


def _untrusted(tool: str = "read_email", ref: str | None = None, conf: Confidentiality = Confidentiality.PRIVATE) -> Label:
    return Label.tool(trusted=False, conf=conf, tool=tool, call_id="c1", ref=ref)


IBAN = ArgSpec(type=ArgType.IBAN, role=ArgRole.AUTHORITY)
EMAILS = ArgSpec(type=ArgType.LIST, items=ArgType.EMAIL, role=ArgRole.AUTHORITY)
TEXT = ArgSpec(type=ArgType.TEXT, role=ArgRole.AUTHORITY)


def _resolve(ledger: Ledger, spec: ArgSpec, value: Any, *, task_spec: TaskSpec | None = None,
             approvals: ApprovalStore | None = None, side_effect: SideEffect = SideEffect.PAYMENT,
             constants: dict[ArgType, frozenset[str]] | None = None) -> OriginClass:
    return resolve_origin(ledger, arg="a", spec=spec, value=value, task_spec=task_spec, approvals=approvals,
                          side_effect=side_effect, constants=constants).origin_class


# ------------------------------------------------------------------ ledger basics

def test_ledger_append_normalizes_and_sequences() -> None:
    led = Ledger()
    e1 = led.append(kind=SourceKind.USER, text="  Hello\u200b  World ", label=Label.user())
    e2 = led.append(kind=SourceKind.SYSTEM, text="sys", label=Label.system())
    assert (e1.entry_id, e1.seq, e1.text) == ("e1", 1, "Hello World")
    assert (e2.entry_id, e2.seq) == ("e2", 2)
    assert len(led) == 2 and led.get("e2") is e2
    assert [e.entry_id for e in led.entries()] == ["e1", "e2"]


def test_ledger_ctx_label_join() -> None:
    led = Ledger()
    assert led.ctx_label().trusted
    led.append(kind=SourceKind.USER, text="hi", label=Label.user())
    assert led.ctx_label().trusted and led.ctx_label().confidentiality == Confidentiality.PRIVATE
    led.append(kind=SourceKind.TOOL_OUTPUT, text="x", label=_untrusted(conf=Confidentiality.SECRET))
    ctx = led.ctx_label()
    assert ctx.integrity == Integrity.UNTRUSTED and ctx.confidentiality == Confidentiality.SECRET


def test_ledger_snapshot_hides_later_appends() -> None:
    led = Ledger()
    led.append(kind=SourceKind.USER, text="pay a@b.com", label=Label.user())
    snap = led.snapshot()
    led.append(kind=SourceKind.TOOL_OUTPUT, text="c@d.com", label=_untrusted())
    assert len(snap) == 1 and len(led) == 2
    assert snap.find_typed(ArgType.EMAIL, "c@d.com") == []
    assert snap.ctx_label().trusted
    with pytest.raises(KeyError):
        snap.get("e2")


def test_add_signal_replaces_entry() -> None:
    led = Ledger()
    led.append(kind=SourceKind.TOOL_OUTPUT, text="x", label=_untrusted())
    led.add_signal("e1", Signal(source="decoder", kind="trigger:en"))
    assert led.get("e1").signals[0].kind == "trigger:en"


def test_value_index_typed_and_exact() -> None:
    idx = ValueIndex()
    led = Ledger()
    e = led.append(kind=SourceKind.TOOL_OUTPUT, text="pay GB33 BUKB 2020 1555 5555 55 now", label=_untrusted())
    idx.add(e)
    assert idx.lookup(ArgType.IBAN, "GB33BUKB20201555555555") == ["e1"]
    short = led.append(kind=SourceKind.TOOL_OUTPUT, text="E7", label=_untrusted())
    idx.add(short)
    assert idx.lookup_exact("e7") == ["e2"]
    amount = led.append(kind=SourceKind.TOOL_OUTPUT, text="50", label=_untrusted())
    idx.add(amount)
    assert idx.lookup(ArgType.AMOUNT, "50.00") == ["e3"]


def test_find_text_min_len() -> None:
    led = Ledger()
    led.append(kind=SourceKind.TOOL_OUTPUT, text="set firewall.allow_all to true", label=_untrusted())
    assert [e.entry_id for e in led.find_text("firewall.allow_all")] == ["e1"]
    assert led.find_text("allow") == []


def test_shingle_index_private_only() -> None:
    s = ShingleIndex()
    led = Ledger()
    secret_text = "The quarterly revenue forecast is 4.2 million with a margin of 18 percent overall."
    e1 = led.append(kind=SourceKind.TOOL_OUTPUT, text=secret_text, label=_untrusted())
    e2 = led.append(kind=SourceKind.TOOL_OUTPUT, text=secret_text + " public",
                    label=_untrusted(conf=Confidentiality.PUBLIC))
    s.add(e1)
    s.add(e2)
    assert s.lookup_text("fyi: " + secret_text[10:60] + " ...") == {"e1"}
    assert s.lookup_text("short") == set()
    assert {e.entry_id for e in led.find_shingles(secret_text[5:70])} == {"e1"}


# ------------------------------------------------------------------ output labeling

def test_labels_read_email_fields() -> None:
    spec = _spec("read_email")
    call = ToolCall(call_id="c1", tool="read_email", args={"email_id": "e3"})
    frags = compute_output_labels(spec, call, {"id": "e3", "sender": "x@evil.example", "subject": "Hi",
                                               "body": "text"}, user_handle="@emma")
    by_field = {f.field: f for f in frags}
    assert by_field["id"].label.trusted
    assert not by_field["sender"].label.trusted and not by_field["body"].label.trusted
    assert by_field["body"].ref == "e3" and "x@evil.example" in by_field["body"].ref_aliases
    assert all(f.label.confidentiality == Confidentiality.PRIVATE for f in frags)
    (src,) = by_field["id"].label.sources
    assert src.kind == SourceKind.OWN_RECORD


def test_labels_read_channel_per_author() -> None:
    spec = _spec("read_channel")
    call = ToolCall(call_id="c1", tool="read_channel", args={"channel": "#general"})
    out = [
        {"id": "m1", "channel": "#general", "author": "@Emma", "text": "mine", "ts": "t"},
        {"id": "m2", "channel": "#general", "author": "@mallory", "text": "theirs", "ts": "t"},
    ]
    frags = compute_output_labels(spec, call, out, user_handle="@emma")
    by_field = {f.field: f for f in frags}
    assert by_field["[0].text"].label.trusted and by_field["[0].text"].author == "@Emma"
    assert not by_field["[1].text"].label.trusted and by_field["[1].text"].author == "@mallory"
    assert by_field["[1].id"].label.trusted  # field override beats the author rule
    assert by_field["[1].text"].ref == "m2" and "#general" in by_field["[1].text"].ref_aliases


def test_labels_get_user_info_own_record() -> None:
    spec = _spec("get_user_info")
    call = ToolCall(call_id="c1", tool="get_user_info", args={})
    frags = compute_output_labels(spec, call, {"iban": "DE89370400440532013000", "street": "Main"},
                                  user_handle="@emma")
    assert frags and all(f.label.trusted for f in frags)


def test_labels_string_output_and_skips() -> None:
    spec = _spec("read_file")
    call = ToolCall(call_id="c1", tool="read_file", args={"path": "/docs/a.txt"})
    (frag,) = compute_output_labels(spec, call, "hello", user_handle="@emma")
    assert frag.ref == "/docs/a.txt" and frag.field is None and not frag.label.trusted
    spec2 = _spec("list_emails")
    frags = compute_output_labels(spec2, ToolCall(call_id="c2", tool="list_emails", args={}),
                                  [{"id": "e1", "read": True, "body": None, "subject": ""}], user_handle="@emma")
    assert [f.field for f in frags] == ["[0].id"]


def test_labels_mcp_server_recorded() -> None:
    spec = _spec("status__check_status")
    frags = compute_output_labels(spec, ToolCall(call_id="c1", tool=spec.qualified_name, args={}), "ok",
                                  user_handle="@emma")
    (src,) = frags[0].label.sources
    assert src.server == "status" and src.tool == "status__check_status"


# ------------------------------------------------------------------ resolve_origin table

def _ledger_with(*entries: tuple[SourceKind, str, Label, dict[str, Any]]) -> Ledger:
    led = Ledger()
    for kind, text, label, extra in entries:
        led.append(kind=kind, text=text, label=label, **extra)
    return led


def test_origin_user_typed() -> None:
    led = _ledger_with((SourceKind.USER, "pay GB33BUKB20201555555555", Label.user(), {}))
    assert _resolve(led, IBAN, "GB33 BUKB 2020 1555 5555 55") == OriginClass.USER_TYPED


def test_origin_policy_const_from_system_and_constants() -> None:
    led = _ledger_with((SourceKind.SYSTEM, "IBAN GB33BUKB20201555555555", Label.system(), {}))
    assert _resolve(led, IBAN, "GB33BUKB20201555555555") == OriginClass.POLICY_CONST
    empty = Ledger()
    consts = {ArgType.IBAN: frozenset({"DE89370400440532013000"})}
    assert _resolve(empty, IBAN, "DE89 3704 0044 0532 0130 00", constants=consts) == OriginClass.POLICY_CONST


def test_origin_own_record() -> None:
    lab = Label.tool(trusted=True, conf=Confidentiality.PRIVATE, tool="get_user_info", call_id="c1",
                     kind=SourceKind.OWN_RECORD)
    led = _ledger_with((SourceKind.TOOL_OUTPUT, "DE89370400440532013000", lab, {}))
    assert _resolve(led, IBAN, "DE89370400440532013000") == OriginClass.OWN_RECORD


def test_origin_approved_and_scope() -> None:
    led = Ledger()
    approvals = ApprovalStore()
    approvals.add(SideEffect.PAYMENT, ArgType.IBAN, "GB33BUKB20201555555555")
    assert _resolve(led, IBAN, "GB33BUKB20201555555555", approvals=approvals) == OriginClass.APPROVED
    assert _resolve(led, IBAN, "GB33BUKB20201555555555", approvals=approvals,
                    side_effect=SideEffect.WRITE) == OriginClass.UNKNOWN


def test_origin_named_source_vs_untrusted() -> None:
    led = _ledger_with(
        (SourceKind.TOOL_OUTPUT, "IBAN GB33BUKB20201555555555", _untrusted("read_file", ref="/finance/invoice_0425.pdf"),
         {"ref": "/finance/invoice_0425.pdf"}),
        (SourceKind.TOOL_OUTPUT, "IBAN US133000000121212121212", _untrusted("read_file", ref="/docs/x.txt"),
         {"ref": "/docs/x.txt"}),
    )
    ts = TaskSpec(named_sources=(NamedSource(ref_kind="file", pattern="*invoice_0425.pdf*",
                                             authorizes=frozenset({ArgType.IBAN})),))
    assert _resolve(led, IBAN, "GB33BUKB20201555555555", task_spec=ts) == OriginClass.USER_NAMED_SOURCE
    assert _resolve(led, IBAN, "US133000000121212121212", task_spec=ts) == OriginClass.UNTRUSTED_ONLY
    ts_url_only = TaskSpec(named_sources=(NamedSource(ref_kind="file", pattern="*invoice*",
                                                      authorizes=frozenset({ArgType.URL})),))
    assert _resolve(led, IBAN, "GB33BUKB20201555555555", task_spec=ts_url_only) == OriginClass.UNTRUSTED_ONLY


def test_origin_unknown_and_label() -> None:
    led = Ledger()
    origin = resolve_origin(led, arg="a", spec=IBAN, value="FR7630006000011234567890189", task_spec=None,
                            approvals=None, side_effect=SideEffect.PAYMENT)
    assert origin.origin_class == OriginClass.UNKNOWN and not origin.label.trusted
    bad = resolve_origin(led, arg="a", spec=IBAN, value="not-an-iban", task_spec=None, approvals=None,
                         side_effect=SideEffect.PAYMENT)
    assert bad.origin_class == OriginClass.UNKNOWN and bad.value_canonical is None
    text = resolve_origin(led, arg="a", spec=ArgSpec(type=ArgType.TEXT, role=ArgRole.CONTENT), value="hello there",
                          task_spec=None, approvals=None, side_effect=SideEffect.WRITE)
    assert text.origin_class == OriginClass.UNKNOWN and text.label.trusted


def test_origin_ranking_user_beats_untrusted_regardless_of_order() -> None:
    led = _ledger_with(
        (SourceKind.TOOL_OUTPUT, "a@b.com", _untrusted(), {}),
        (SourceKind.USER, "email a@b.com", Label.user(), {}),
    )
    origin = resolve_origin(led, arg="to", spec=EMAILS, value=["a@b.com"], task_spec=None, approvals=None,
                            side_effect=SideEffect.EXTERNAL_COMM)
    assert origin.origin_class == OriginClass.USER_TYPED
    assert origin.matches[0].origin_class == OriginClass.USER_TYPED
    assert not origin.label.trusted  # label is the join of all matches (conservative for sinks)


def test_origin_list_least_trusted() -> None:
    led = _ledger_with(
        (SourceKind.USER, "email a@b.com", Label.user(), {}),
        (SourceKind.TOOL_OUTPUT, "cc c@evil.com", _untrusted(), {}),
    )
    o = resolve_origin(led, arg="to", spec=EMAILS, value=["a@b.com", "c@evil.com"], task_spec=None, approvals=None,
                       side_effect=SideEffect.EXTERNAL_COMM)
    assert o.origin_class == OriginClass.UNTRUSTED_ONLY and o.value_canonical == ["a@b.com", "c@evil.com"]
    o2 = resolve_origin(led, arg="to", spec=EMAILS, value=["a@b.com", "new@x.com"], task_spec=None, approvals=None,
                        side_effect=SideEffect.EXTERNAL_COMM)
    assert o2.origin_class == OriginClass.UNKNOWN


def test_origin_text_substring() -> None:
    led = _ledger_with((SourceKind.USER, "set key notifications.digest please", Label.user(), {}))
    assert _resolve(led, TEXT, "Notifications.Digest") == OriginClass.USER_TYPED
    assert _resolve(led, TEXT, "set") == OriginClass.UNKNOWN


def test_origin_summary_trusted_ignored_untrusted_counts() -> None:
    led = _ledger_with(
        (SourceKind.SUMMARY, "contact x@y.com", Label.user(), {}),
        (SourceKind.SUMMARY, "contact z@y.com", _untrusted(), {}),
    )
    assert _resolve(led, EMAILS, ["x@y.com"], side_effect=SideEffect.EXTERNAL_COMM) == OriginClass.UNKNOWN
    assert _resolve(led, EMAILS, ["z@y.com"], side_effect=SideEffect.EXTERNAL_COMM) == OriginClass.UNTRUSTED_ONLY


def test_origin_homoglyph_never_inherits_trust() -> None:
    lab = Label.tool(trusted=True, conf=Confidentiality.PRIVATE, tool="list_contacts", call_id="c1",
                     kind=SourceKind.OWN_RECORD)
    led = _ledger_with((SourceKind.TOOL_OUTPUT, "bob@bluesparrowtech.com", lab, {}))
    assert _resolve(led, EMAILS, ["bоb@bluesparrowtech.com"], side_effect=SideEffect.EXTERNAL_COMM) == (
        OriginClass.UNKNOWN
    )
    assert _resolve(led, EMAILS, ["BOB@bluesparrowtech.com"], side_effect=SideEffect.EXTERNAL_COMM) == (
        OriginClass.OWN_RECORD
    )
