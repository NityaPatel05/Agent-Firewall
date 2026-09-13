from __future__ import annotations

import time

from firewall.core.extract import extract_typed_values
from firewall.core.models import ArgType

PARAGRAPH = (
    "Hi Emma, please pay invoice_0425.pdf to GB33 BUKB 2020 1555 5555 55 (amount $1,250.00) by 2026-11-15. "
    "Questions: billing@Vendor.example or +1 (555) 123-4567. Details at https://Vendor.example/inv?id=42&b=1 "
    "and status.bluesparrowtech.com. Ping @Alice in #General. Files: /docs/notes.txt and C:\\tmp\\x.log. "
    "Wallet 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU. Attacker IBAN US133000000121212121212."
)


def test_each_type_extracted() -> None:
    out = extract_typed_values(PARAGRAPH)
    assert "billing@vendor.example" in out[ArgType.EMAIL]
    assert {"GB33BUKB20201555555555", "US133000000121212121212"} <= out[ArgType.IBAN]
    assert "https://vendor.example/inv?b=1&id=42" in out[ArgType.URL]
    assert {"vendor.example", "status.bluesparrowtech.com"} <= out[ArgType.HOST]
    assert "1250.00" in out[ArgType.AMOUNT]
    assert {"/docs/notes.txt", "C:/tmp/x.log", "invoice_0425.pdf"} <= out[ArgType.PATH]
    assert "@alice" in out[ArgType.HANDLE]
    assert "#general" in out[ArgType.CHANNEL]
    assert "+15551234567" in out[ArgType.PHONE]
    assert "2026-11-15" in out[ArgType.DATE]
    assert "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU" in out[ArgType.CRYPTO_ADDRESS]


def test_email_is_not_a_handle() -> None:
    out = extract_typed_values("mail emma@bluesparrowtech.com now")
    assert ArgType.HANDLE not in out


def test_whole_token_amounts() -> None:
    out = extract_typed_values("I paid 1000 last month")
    assert "1000.00" in out[ArgType.AMOUNT]
    assert "100.00" not in out[ArgType.AMOUNT]


def test_small_numbers_without_currency_ignored() -> None:
    out = extract_typed_values("I have 3 cats and 42 dogs")
    assert ArgType.AMOUNT not in out


def test_two_decimal_amount() -> None:
    assert "12.50" in extract_typed_values("total 12.50 due")[ArgType.AMOUNT]


def test_url_path_not_a_file_path() -> None:
    out = extract_typed_values("see https://evil.com/a/b for more")
    assert "/a/b" not in out.get(ArgType.PATH, set())


def test_currency_word_and_symbol_amounts() -> None:
    out = extract_typed_values("send 1250 EUR now, or $ 99 later; €12 tip")
    assert {"1250.00", "99.00", "12.00"} <= out[ArgType.AMOUNT]


def test_date_is_not_an_amount_or_phone() -> None:
    out = extract_typed_values("due on 2026-11-15 please")
    assert out[ArgType.DATE] == {"2026-11-15"}
    assert ArgType.AMOUNT not in out and ArgType.PHONE not in out


def test_spaced_iban_in_sentence() -> None:
    out = extract_typed_values("IBAN: GB33 BUKB 2020 1555 5555 55, thanks")
    assert "GB33BUKB20201555555555" in out[ArgType.IBAN]


def test_handle_channel_boundaries() -> None:
    out = extract_typed_values("see page#anchor and issue #42 by @Bob.")
    assert out.get(ArgType.CHANNEL, set()) == set()
    assert out[ArgType.HANDLE] == {"@bob"}


def test_empty() -> None:
    assert extract_typed_values("") == {}


def test_performance_100kb() -> None:
    text = (PARAGRAPH + " lorem ipsum dolor sit amet " * 20) * (100_000 // (len(PARAGRAPH) + 560) + 1)
    text = text[:100_000]
    extract_typed_values(text)  # warm-up
    start = time.perf_counter()
    extract_typed_values(text)
    assert time.perf_counter() - start < 0.05


def test_performance_100kb_prose() -> None:
    prose = ("The quarterly meeting covered budget planning, hiring and the roadmap. Emma will follow up "
             "with Alice about the vendor contract next week. " * 1000)[:100_000]
    extract_typed_values(prose)
    start = time.perf_counter()
    extract_typed_values(prose)
    assert time.perf_counter() - start < 0.05
