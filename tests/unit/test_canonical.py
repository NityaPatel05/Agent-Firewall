from __future__ import annotations

from decimal import Decimal

import pytest

from firewall.core.canonical import (
    canon_amount,
    canon_channel,
    canon_crypto,
    canon_date,
    canon_email,
    canon_handle,
    canon_host,
    canon_iban,
    canon_path,
    canon_phone,
    canon_url,
    canonicalize,
    iban_checksum_ok,
    mixed_script,
    normalize_text,
    skeleton,
    url_parts,
)
from firewall.core.models import ArgType


@pytest.mark.parametrize(
    ("fn", "raw", "expected"),
    [
        (canon_email, "Alice@Example.COM", "alice@example.com"),
        (canon_email, "  bob@bluesparrowtech.com ", "bob@bluesparrowtech.com"),
        (canon_email, "not-an-email", None),
        (canon_email, "a@b", None),
        # The plan's example "US13 3000 0001 2121-2121 2121 2" has one group too many; this is the
        # same IBAN with spaces/dashes.
        (canon_iban, "US13 3000 0001 2121-2121 212", "US133000000121212121212"),
        (canon_iban, "de89 3704 0044 0532 0130 00", "DE89370400440532013000"),
        (canon_iban, "12345", None),
        (canon_url, "HTTPS://Evil.com:443/a/../b?y=2&x=1", "https://evil.com/b?x=1&y=2"),
        (canon_url, "http://Example.com", "http://example.com/"),
        (canon_url, "http://example.com:8080/x", "http://example.com:8080/x"),
        (canon_url, "javascript:alert(1)", None),
        (canon_url, "file:///etc/passwd", None),
        (canon_host, "WWW.Example.COM", "www.example.com"),
        (canon_host, "https://Sub.Evil.com/x", "sub.evil.com"),
        (canon_path, "C:\\tmp\\..\\x.txt", "C:/x.txt"),
        (canon_path, "/docs//a/./b.txt", "/docs/a/b.txt"),
        (canon_path, "~/.bashrc", "~/.bashrc"),
        (canon_path, "/tmp/scratch/", "/tmp/scratch"),
        (canon_handle, "@Alice", "@alice"),
        (canon_handle, "oncall", "@oncall"),
        (canon_handle, "@bad handle", None),
        (canon_channel, "#General", "#general"),
        (canon_phone, "+1 (555) 123-4567", "+15551234567"),
        (canon_phone, "123", None),
        (canon_date, "2026-11-01", "2026-11-01"),
        (canon_date, "2026-11-01T09:00:00", "2026-11-01T09:00"),
        (canon_date, "tomorrow", None),
        (canon_crypto, "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"),
        (canon_crypto, "0OIl" * 9, None),
    ],
)
def test_canonicalizers(fn: object, raw: str, expected: str | None) -> None:
    assert fn(raw) == expected  # type: ignore[operator]


def test_url_query_reordering_equal() -> None:
    assert canon_url("https://a.com/p?b=2&a=1") == canon_url("https://A.com/p?a=1&b=2")


def test_url_parts() -> None:
    p = url_parts("https://evil.com/p?d=secret#frag")
    assert p is not None
    assert p.host == "evil.com" and p.query == (("d", "secret"),) and p.fragment == "frag"


@pytest.mark.parametrize("raw", [1250, 1250.0, "1,250.00", "$1250", "1250.0 EUR", Decimal(1250), "1250 USD"])
def test_amounts_equal(raw: object) -> None:
    assert canon_amount(raw) == Decimal("1250.00")


@pytest.mark.parametrize("raw", ["abc", True, None, "12x", "1.2.3"])
def test_amount_invalid(raw: object) -> None:
    assert canon_amount(raw) is None


def test_zero_width_and_bidi_stripped() -> None:
    assert normalize_text("pa\u200bypal") == "paypal"
    assert normalize_text("a\u202eb\u2066c\ufeff") == "abc"
    assert normalize_text("  x \n\t y  ") == "x y"


def test_nfkc_fullwidth() -> None:
    assert normalize_text("ｐａｙｐａｌ") == "paypal"


def test_skeleton_homoglyph() -> None:
    assert skeleton("рaypal.com") == "paypal.com"
    assert skeleton("Gοοgle") == "google"


def test_mixed_script() -> None:
    assert mixed_script("рaypal")
    assert not mixed_script("paypal")
    assert not mixed_script("привет")
    assert mixed_script("gοogle")


def test_iban_checksum() -> None:
    assert iban_checksum_ok("DE89 3704 0044 0532 0130 00")
    assert iban_checksum_ok("GB33BUKB20201555555555")
    assert not iban_checksum_ok("DE00370400440532013000")


@pytest.mark.parametrize(
    ("value", "t", "expected"),
    [
        ("Hello  World", ArgType.TEXT, "hello world"),
        ("e7", ArgType.ID, "e7"),
        (["pytest", "-q"], ArgType.COMMAND, "pytest -q"),
        (True, ArgType.BOOL, "true"),
        ("12", ArgType.INT, "12"),
        ("1,250.00", ArgType.AMOUNT, "1250.00"),
        ({"b": 1, "a": 2}, ArgType.DICT, '{"a":2,"b":1}'),
        ("Alice@Example.com", ArgType.EMAIL, "alice@example.com"),
    ],
)
def test_canonicalize_dispatch(value: object, t: ArgType, expected: str) -> None:
    assert canonicalize(value, t) == expected


def test_canonicalize_non_string_typed_returns_none() -> None:
    assert canonicalize(123, ArgType.EMAIL) is None
    assert canonicalize(["a@b.com"], ArgType.IBAN) is None
