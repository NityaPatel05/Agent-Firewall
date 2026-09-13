"""Typed-value extraction from free text; returns canonical values per ArgType.

Performance: one character-class pass finds "numeric runs" (dates, amounts, phones, IBAN tails); every
other pass is anchored on a literal (`://`, `@`, `#`, `/`, `.ext`, `.tld`) so the regex engine can skip
quickly. Boundary checks run in Python on the few candidates; canonicalization is memoized.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from functools import lru_cache

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
    url_parts,
)
from firewall.core.models import ArgType

_TLDS = (
    "com|org|net|io|dev|app|ai|co|uk|de|fr|es|it|nl|ch|at|eu|us|ca|au|in|jp|cn|ru|info|biz|me|tv|xyz|"
    "example|test|local|internal|gov|edu|site|online|cloud|tech|shop"
)
_FILE_EXTS = (
    "pdf|txt|md|csv|xlsx|xls|docx|doc|pptx|ppt|json|yaml|yml|py|js|ts|sh|zip|tar|gz|tgz|png|jpg|jpeg|"
    "gif|svg|log|env|ini|cfg|conf|toml|html|htm|xml|sql|key|pem|rs|go|java|c|cpp|h|rb|php|bat|ps1|exe|"
    "ipynb|eml|ics|bak|db|sqlite"
)

URL_BODY_RE = re.compile(r"[A-Za-z]{4,5}://[^\s<>\"'`\]\[)(]+")
AT_RE = re.compile(r"@[A-Za-z0-9_][A-Za-z0-9._-]{0,253}")
EMAIL_DOMAIN_RE = re.compile(r"@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
CHANNEL_RE = re.compile(r"#[A-Za-z0-9_][A-Za-z0-9._-]{0,79}")
NUMRUN_RE = re.compile(r"[\d$€£¥+(][\d.,:()+\- $€£¥T]*")
IBAN_RE = re.compile(r"[A-Z]{2}\d{2}(?:[A-Z0-9]{10,30}|(?:[ -][A-Z0-9]{4}){2,7}(?:[ -][A-Z0-9]{1,3})?)(?![A-Za-z0-9])")
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?)?(?!\d)")
AMOUNT_RE = re.compile(
    r"(?P<cur1>[$€£¥]\s?)?(?P<num>\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+(?:\.\d+)?)"
    r"(?![\w$€£¥]|[.,]\d)(?P<cur2>\s?(?:USD|EUR|GBP|CHF|SOL|dollars?|euros?)\b)?",
    re.IGNORECASE,
)
PHONE_RE = re.compile(r"[+(\d][\d()]{0,5}(?:[ .-]\(?\d{2,4}\)?){2,5}(?![\w])")
SLASH_PATH_RE = re.compile(r"/[\w.\-~]+(?:[/\\][\w.\-~]+)*/?")
BSLASH_PATH_RE = re.compile(r"\\[\w.\-~]+(?:[/\\][\w.\-~]+)*\\?")
FILE_EXT_RE = re.compile(rf"\.(?:{_FILE_EXTS})(?![\w@/-])", re.IGNORECASE)
HOST_TLD_RE = re.compile(rf"\.(?:{_TLDS})(?![\w@-])", re.IGNORECASE)
NUM_COMBO_RE = re.compile(
    rf"(?P<date>{DATE_RE.pattern})|(?P<phone>{PHONE_RE.pattern})|{AMOUNT_RE.pattern}", re.IGNORECASE
)
BASE58_RUN_RE = re.compile(r"[1-9A-HJ-NP-Za-km-z]+")
_DIGIT_RE = re.compile(r"\d")
_BASE58 = frozenset("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
_TRAILING = ".,;:!?'\""
_TOKEN_STRIP = ".,;:!?()[]{}<>\"'`"
_EMAIL_LOCAL = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._%+-")
_HOST_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.")
_FILE_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.")
_UPPER = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

_c_url = lru_cache(maxsize=4096)(canon_url)
_c_email = lru_cache(maxsize=4096)(canon_email)
_c_iban = lru_cache(maxsize=4096)(canon_iban)
_c_date = lru_cache(maxsize=4096)(canon_date)
_c_phone = lru_cache(maxsize=4096)(canon_phone)
_c_path = lru_cache(maxsize=4096)(canon_path)
_c_host = lru_cache(maxsize=4096)(canon_host)
_c_handle = lru_cache(maxsize=4096)(canon_handle)
_c_channel = lru_cache(maxsize=4096)(canon_channel)


@lru_cache(maxsize=4096)
def _c_amount(raw: str) -> str | None:
    d = canon_amount(raw)
    return None if d is None else str(d)


@lru_cache(maxsize=4096)
def _c_url_host(raw: str) -> str | None:
    p = url_parts(raw)
    return None if p is None else p.host


def _is_word(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def _prev(text: str, i: int) -> str:
    return text[i - 1] if i > 0 else ""


class _Spans:
    """Sorted, non-overlapping spans with O(log n) containment checks."""

    def __init__(self) -> None:
        self.starts: list[int] = []
        self.ends: list[int] = []

    def add(self, a: int, b: int) -> None:
        self.starts.append(a)
        self.ends.append(b)

    def contains(self, pos: int) -> bool:
        i = bisect_right(self.starts, pos) - 1
        return i >= 0 and pos < self.ends[i]


Out = dict[ArgType, set[str]]


def _add(out: Out, t: ArgType, v: str | None) -> None:
    if v:
        out.setdefault(t, set()).add(v)


def _expand_left(text: str, end: int, allowed: frozenset[str]) -> int:
    i = end
    while i > 0 and text[i - 1] in allowed:
        i -= 1
    return i


def _urls(text: str, out: Out) -> _Spans:
    spans = _Spans()
    idx = text.find("://")
    while idx != -1:
        for scheme_len in (5, 4):
            start = idx - scheme_len
            if start >= 0 and text[start:idx].lower() in ("https", "http") and not _is_word(_prev(text, start)):
                m = URL_BODY_RE.match(text, start)
                if m:
                    raw = m.group(0).rstrip(_TRAILING)
                    spans.add(start, start + len(raw))
                    _add(out, ArgType.URL, _c_url(raw))
                    _add(out, ArgType.HOST, _c_url_host(raw))
                break
        idx = text.find("://", idx + 3)
    return spans


def _at_signs(text: str, out: Out) -> None:
    for m in AT_RE.finditer(text):
        start = m.start()
        prev = _prev(text, start)
        if prev and prev in _EMAIL_LOCAL:
            dm = EMAIL_DOMAIN_RE.match(text, start)
            if dm is not None:
                left = _expand_left(text, start, _EMAIL_LOCAL)
                _add(out, ArgType.EMAIL, _c_email(text[left:dm.end()].rstrip(_TRAILING)))
        elif prev != "@":
            _add(out, ArgType.HANDLE, _c_handle(m.group(0).rstrip(_TRAILING)))


def _channels(text: str, out: Out) -> None:
    for m in CHANNEL_RE.finditer(text):
        prev = _prev(text, m.start())
        if prev and (_is_word(prev) or prev in "&#/"):
            continue
        raw = m.group(0).rstrip(_TRAILING)
        if any(ch.isalpha() for ch in raw):
            _add(out, ArgType.CHANNEL, _c_channel(raw))


def _crypto_at(text: str, pos: int, out: Out) -> int:
    """Check the base58 token around `pos` (a digit inside a word); return the token end."""
    left = _expand_left(text, pos, _BASE58)
    m = BASE58_RUN_RE.match(text, pos)
    right = m.end() if m else pos
    if 32 <= right - left <= 44 and not _is_word(_prev(text, left)) and not (
        right < len(text) and _is_word(text[right])
    ):
        tok = text[left:right]
        if any(c.isalpha() for c in tok):
            _add(out, ArgType.CRYPTO_ADDRESS, canon_crypto(tok))
    return right


def _numeric(text: str, out: Out, urls: _Spans) -> None:
    """Dates, phones, amounts, IBANs and crypto addresses, anchored on runs of digits/currency symbols."""
    n = len(text)
    crypto_end = -1
    for run in NUMRUN_RE.finditer(text):
        rs, re_ = run.span()
        if urls.contains(rs):
            continue
        prev = _prev(text, rs)
        # IBAN: two upper-case letters directly before a digit run.
        if rs >= 2 and prev in _UPPER and text[rs - 2] in _UPPER and not _is_word(_prev(text, rs - 2)):
            m = IBAN_RE.match(text, rs - 2)
            if m:
                _add(out, ArgType.IBAN, _c_iban(m.group(0)))
                continue
        if prev and _is_word(prev):
            if rs > crypto_end and text[rs].isdigit():
                crypto_end = _crypto_at(text, rs, out)
            continue
        if not (text[rs].isdigit() or _DIGIT_RE.search(text, rs, re_)):
            continue
        for m in NUM_COMBO_RE.finditer(text, rs, min(n, re_ + 10)):
            start = m.start()
            if start >= re_:
                break
            p = _prev(text, start)
            if p and (_is_word(p) or p in ".,-:+"):
                continue
            if m.group("date"):
                _add(out, ArgType.DATE, _c_date(m.group("date")))
            elif m.group("phone"):
                _add(out, ArgType.PHONE, _c_phone(m.group("phone")))
            else:
                num = m.group("num")
                whole, _, decimals = num.partition(".")
                if m.group("cur1") or m.group("cur2") or len(decimals) == 2 or len(whole.replace(",", "")) >= 3:
                    _add(out, ArgType.AMOUNT, _c_amount(num))


def _paths(text: str, out: Out, urls: _Spans) -> None:
    passes = [SLASH_PATH_RE] + ([BSLASH_PATH_RE] if "\\" in text else [])
    for rx in passes:
        for m in rx.finditer(text):
            start = m.start()
            if urls.contains(start):
                continue
            prev = _prev(text, start)
            prefix_start = start
            if prev == "~":
                prefix_start = start - 1
            elif prev == ":" and start >= 2 and text[start - 2].isalpha() and not _is_word(_prev(text, start - 2)):
                prefix_start = start - 2
            elif prev and (_is_word(prev) or prev in ":/.\\-"):
                continue
            raw = text[prefix_start:m.end()].rstrip(_TRAILING)
            if len(raw) > 2:
                _add(out, ArgType.PATH, _c_path(raw))
    for m in FILE_EXT_RE.finditer(text):
        left = _expand_left(text, m.start(), _FILE_CHARS)
        if left == m.start() or urls.contains(left):
            continue
        prev = _prev(text, left)
        if prev and (prev in "/\\@~" or _is_word(prev)):
            continue
        _add(out, ArgType.PATH, _c_path(text[left:m.end()]))


def _hosts(text: str, out: Out, urls: _Spans) -> None:
    for m in HOST_TLD_RE.finditer(text):
        left = _expand_left(text, m.start(), _HOST_CHARS)
        if left == m.start() or urls.contains(left):
            continue
        prev = _prev(text, left)
        if prev and (prev in "@/" or _is_word(prev)):
            continue
        raw = text[left:m.end()].strip(".-")
        if "." in raw:
            _add(out, ArgType.HOST, _c_host(raw))


def extract_typed_values(text: str) -> dict[ArgType, set[str]]:
    """Extract canonical typed values (whole tokens only) from `text`."""
    out: Out = {}
    if not text:
        return out
    urls = _urls(text, out) if "://" in text else _Spans()
    if "@" in text:
        _at_signs(text, out)
    if "#" in text:
        _channels(text, out)
    _numeric(text, out, urls)
    if "/" in text or "\\" in text or "." in text:
        _paths(text, out, urls)
    if "." in text:
        _hosts(text, out, urls)
    return out
