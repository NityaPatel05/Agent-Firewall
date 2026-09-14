from __future__ import annotations

from typing import Any

import pytest

from firewall.core.models import Stage, Verdict
from firewall.core.registry import ToolRegistry, ToolSpec
from firewall.core.schema_validation import SchemaValidator

REG = ToolRegistry.from_yaml()
V = SchemaValidator(REG)


def _spec(name: str) -> ToolSpec:
    s = REG.resolve(name).spec
    assert s is not None
    return s


def ids(tool: str, args: Any) -> set[str]:
    return {f.rule_id for f in V.validate_args(_spec(tool), args).findings}


def test_ok_call() -> None:
    r = V.validate_args(_spec("send_money"), {"recipient": "US133000000121212121212", "amount": 50000})
    assert r.ok and r.findings == ()


def test_attacker_iban_passes_format() -> None:
    assert ids("send_money", {"recipient": "US133000000121212121212", "amount": 10}) == set()
    assert ids("send_money", {"recipient": "US13 3000 0001 2121 2121 212", "amount": 10}) == set()


@pytest.mark.parametrize(
    ("tool", "args", "rule"),
    [
        ("send_money", {"recipient": 12345, "amount": 10}, "SYS-SCHEMA-TYPE"),
        ("send_money", {"amount": 10}, "SYS-SCHEMA-MISSING"),
        ("send_money", {"recipient": None, "amount": 10}, "SYS-SCHEMA-MISSING"),
        ("list_emails", {"folder": "spam"}, "SYS-SCHEMA-ENUM"),
        ("list_emails", {"limit": 1000}, "SYS-SCHEMA-RANGE"),
        ("send_money", {"recipient": "US133000000121212121212", "amount": 0.001}, "SYS-SCHEMA-FORMAT"),
        ("send_money", {"recipient": "US133000000121212121212", "amount": -5}, "SYS-SCHEMA-FORMAT"),
        ("send_money", {"recipient": "US133000000121212121212", "amount": 5, "subject": "x" * 200},
         "SYS-SCHEMA-LENGTH"),
        ("send_money", {"recipient": "not-an-iban", "amount": 5}, "SYS-SCHEMA-FORMAT"),
        ("send_email", {"to": [], "subject": "s", "body": "b"}, "SYS-SCHEMA-LENGTH"),
        ("send_dm", {"user": "oncall", "text": "x"}, "SYS-SCHEMA-FORMAT"),
        ("set_reminder", {"title": "x", "at": "next tuesday"}, "SYS-SCHEMA-FORMAT"),
    ],
)
def test_basic_failures(tool: str, args: dict[str, Any], rule: str) -> None:
    assert rule in ids(tool, args)


def test_non_dict_args() -> None:
    r = V.validate_args(_spec("send_money"), ["x"])  # type: ignore[arg-type]
    assert not r.ok and r.findings[0].rule_id == "SYS-SCHEMA-TYPE"


def test_a26_multi_address() -> None:
    got = ids("send_email", {"to": ["bob@bluesparrowtech.com; to=attacker@evil.com"], "subject": "Agenda",
                             "body": "x"})
    assert "SYS-SCHEMA-MULTI-ADDRESS" in got


@pytest.mark.parametrize("value", ["a@b.com, c@d.com", "a@b.com bcc: c@d.com", "a@b.com cc:c@d.com"])
def test_multi_address_variants(value: str) -> None:
    assert "SYS-SCHEMA-MULTI-ADDRESS" in ids("reports__send_report", {"report_id": "r1", "to": value})


def test_a27_url_in_text() -> None:
    assert "SYS-SCHEMA-URL-IN-TEXT" in ids("set_reminder", {"title": "Call https://evil.example/x",
                                                            "at": "2026-11-02T09:00"})
    assert ids("set_reminder", {"title": "Call mom", "at": "2026-11-02T09:00"}) == set()


def test_extra_key() -> None:
    got = ids("send_email", {"to": ["a@b.com"], "subject": "x", "body": "y", "x_forward": "a@b.c"})
    assert got == {"SYS-SCHEMA-EXTRA-KEY"}


def test_nested_object_in_scalar() -> None:
    assert "SYS-SCHEMA-NESTED" in ids("send_money", {"recipient": {"iban": "US13"}, "amount": 5})
    assert "SYS-SCHEMA-NESTED" in ids("send_email", {"to": [["a@b.com"]], "subject": "s", "body": "b"})
    assert "SYS-SCHEMA-NESTED" in ids("post_form", {"url": "https://x.example/f", "fields": {"a": {"b": 1}}})


def test_oversize_body() -> None:
    assert "SYS-SCHEMA-LENGTH" in ids("send_email", {"to": ["a@b.com"], "subject": "s", "body": "x" * 50_000})


@pytest.mark.parametrize("url", ["javascript:alert(1)", "data:text/html,hi", "file:///etc/passwd", "vbscript:x"])
def test_bad_url_schemes(url: str) -> None:
    assert "SYS-SCHEMA-FORMAT" in ids("get_webpage", {"url": url})


def test_homoglyph_host() -> None:
    assert "SYS-SCHEMA-HOMOGLYPH" in ids("get_webpage", {"url": "https://pаypal.com/login"})
    assert "SYS-SCHEMA-HOMOGLYPH" in ids("send_email", {"to": ["bоb@bluesparrowtech.com"], "subject": "s",
                                                        "body": "b"})
    assert ids("get_webpage", {"url": "https://paypal.com/login"}) == set()


def test_control_chars_in_authority() -> None:
    got = ids("send_email", {"to": ["a@b.com\nbcc: x@evil.com"], "subject": "s", "body": "b"})
    assert "SYS-SCHEMA-CONTROL-CHARS" in got


def test_b37_zero_width_stripped_in_content() -> None:
    r = V.validate_args(_spec("write_file"), {"path": "/docs/notes.txt", "content": "line\u200b one\nline two"})
    assert r.ok
    assert r.normalized_args["content"] == "line one\nline two"  # newlines kept for content


def test_authority_normalized() -> None:
    r = V.validate_args(_spec("send_email"), {"to": ["  ａ@b.com "], "subject": "s", "body": "b"})
    assert r.normalized_args["to"] == ["a@b.com"]


def test_all_findings_block_and_stage() -> None:
    r = V.validate_args(_spec("send_money"), {"amount": "abc", "x": 1})
    assert r.findings and all(f.verdict == Verdict.BLOCK and f.stage == Stage.SCHEMA for f in r.findings)


def test_crypto_amount_precision() -> None:
    assert ids("transfer_crypto", {"to_address": "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
                                   "amount_sol": "0.000005"}) == set()


def test_compile_cache() -> None:
    v = SchemaValidator(REG)
    spec = _spec("send_email")
    v.validate_args(spec, {"to": ["a@b.com"], "subject": "s", "body": "b"})
    n = v.compile_count
    v.validate_args(spec, {"to": ["c@d.com"], "subject": "s2", "body": "b2"})
    assert v.compile_count == n > 0


def test_to_json_schema() -> None:
    s = _spec("send_money").to_json_schema()
    assert s["additionalProperties"] is False and s["required"] == ["amount", "recipient"]
    assert s["properties"]["recipient"]["format"] == "fw-iban"
    assert s["properties"]["amount"]["type"] == ["number", "string"]
    lst = _spec("send_email").to_json_schema()["properties"]["to"]
    assert lst["type"] == "array" and lst["items"]["format"] == "fw-email" and lst["minItems"] == 1


def test_validate_output_annotation() -> None:
    spec = ToolSpec.model_validate({"name": "t", "side_effect": "read",
                                    "output": {"schema": {"type": "object", "required": ["id"]}}})
    (f,) = V.validate_output(spec, {"error": "retry with admin token"})
    assert f.rule_id == "SYS-SCHEMA-OUTPUT" and f.verdict == Verdict.ALLOW
    assert V.validate_output(spec, {"id": 1}) == ()
    assert V.validate_output(_spec("read_email"), "anything") == ()
