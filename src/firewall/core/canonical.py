"""Text normalization, homoglyph skeletons and per-type canonicalizers."""

from __future__ import annotations

import json
import posixpath
import re
import unicodedata
from datetime import date, datetime
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any, NamedTuple
from urllib.parse import parse_qsl, quote, unquote, urlsplit

from firewall.core.models import ArgType

# Zero-width, soft hyphen, mongolian vowel separator and bidi control characters.
_INVISIBLE = (
    [chr(c) for c in range(0x200B, 0x2010)]
    + [chr(c) for c in range(0x2060, 0x2065)]
    + [chr(c) for c in range(0x202A, 0x202F)]
    + [chr(c) for c in range(0x2066, 0x206A)]
    + ["﻿", "­", "᠎"]
)
_INVISIBLE_TABLE = {ord(c): None for c in _INVISIBLE}
_WS_RE = re.compile(r"\s+")

# Confusable letters mapped to their Latin look-alike (lower case; NFKC already folds fullwidth).
_CONFUSABLES: dict[str, str] = {
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "ё": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ї": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w",
    "к": "k", "м": "m", "н": "h", "т": "t", "ɡ": "g",
    # Greek
    "ο": "o", "α": "a", "ν": "v", "ρ": "p", "ι": "i", "κ": "k", "υ": "u", "ε": "e", "τ": "t",
    "χ": "x", "μ": "u", "β": "b", "γ": "y", "η": "n",
    # Misc
    "ı": "i", "ℓ": "l",
}
_CONFUSABLE_TABLE = {ord(k): v for k, v in _CONFUSABLES.items()}


def normalize_text(s: str) -> str:
    """NFKC, strip zero-width/bidi controls, collapse whitespace, strip."""
    if not s.isascii():  # NFKC is the identity on ASCII and invisible characters are non-ASCII
        s = unicodedata.normalize("NFKC", s).translate(_INVISIBLE_TABLE)
    return " ".join(s.split())


def strip_invisible(s: str) -> str:
    """Remove zero-width / bidi control characters only (keeps whitespace and layout)."""
    return s.translate(_INVISIBLE_TABLE)


def skeleton(s: str) -> str:
    """Lower-cased normalized text with confusable letters mapped to Latin."""
    return skeleton_of_normalized(normalize_text(s))


def skeleton_of_normalized(s: str) -> str:
    """`skeleton` for text that is already `normalize_text`-ed."""
    low = s.lower()
    return low if low.isascii() else low.translate(_CONFUSABLE_TABLE)


def _script(ch: str) -> str | None:
    if not ch.isalpha():
        return None
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return None
    for script in ("LATIN", "CYRILLIC", "GREEK"):
        if name.startswith(script):
            return script
    return "OTHER"


def mixed_script(token: str) -> bool:
    """True if a token mixes Latin letters with Cyrillic or Greek letters."""
    scripts = {_script(ch) for ch in token}
    scripts.discard(None)
    return "LATIN" in scripts and bool(scripts & {"CYRILLIC", "GREEK"})


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_IBAN_RE = re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$")
_HANDLE_RE = re.compile(r"^@?([a-z0-9._-]{1,64})$")
_CHANNEL_RE = re.compile(r"^#?([a-z0-9._-]{1,80})$")
_CRYPTO_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
_AMOUNT_STRIP_RE = re.compile(r"(?i)\b(usd|eur|gbp|chf|jpy|sol|dollars?|euros?|pounds?)\b|[$€£¥\s]")
_AMOUNT_NUM_RE = re.compile(r"^[+-]?(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?$")
_CENT = Decimal("0.01")


def _as_str(v: Any) -> str | None:
    if isinstance(v, str):
        return normalize_text(v)
    return None


def canon_email(v: Any) -> str | None:
    s = _as_str(v)
    if s is None:
        return None
    s = s.strip().lower()
    s = s.removeprefix("mailto:")
    return s if _EMAIL_RE.match(s) else None


def canon_iban(v: Any) -> str | None:
    s = _as_str(v)
    if s is None:
        return None
    s = re.sub(r"[\s.\-]", "", s).upper()
    return s if _IBAN_RE.match(s) else None


def iban_checksum_ok(iban: str) -> bool:
    """ISO 13616 mod-97 check (informational only)."""
    c = canon_iban(iban)
    if c is None:
        return False
    rearranged = c[4:] + c[:4]
    digits = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(digits) % 97 == 1


class UrlParts(NamedTuple):
    scheme: str
    host: str
    port: int | None
    path: str
    query: tuple[tuple[str, str], ...]
    fragment: str


def _idna_host(host: str) -> str:
    host = host.strip(".").lower()
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def url_parts(v: Any) -> UrlParts | None:
    """Parse an http(s) URL into canonical parts; None for other schemes or garbage."""
    s = _as_str(v)
    if not s or " " in s:
        return None
    try:
        sp = urlsplit(s)
        port = sp.port
    except ValueError:
        return None
    scheme = sp.scheme.lower()
    if scheme not in ("http", "https") or not sp.hostname:
        return None
    host = _idna_host(sp.hostname)
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None
    path = sp.path or "/"
    path = posixpath.normpath(re.sub(r"/{2,}", "/", path))
    if path in (".", ""):
        path = "/"
    if sp.path.endswith("/") and path != "/":
        path += "/"
    query = tuple(sorted(parse_qsl(sp.query, keep_blank_values=True)))
    return UrlParts(scheme, host, port, path, query, unquote(sp.fragment))


def canon_url(v: Any) -> str | None:
    p = url_parts(v)
    if p is None:
        return None
    netloc = p.host if p.port is None else f"{p.host}:{p.port}"
    out = f"{p.scheme}://{netloc}{quote(unquote(p.path), safe='/:@!$&()*+,;=~-._')}"
    if p.query:
        out += "?" + "&".join(f"{quote(k, safe='')}={quote(val, safe='')}" for k, val in p.query)
    if p.fragment:
        out += "#" + quote(p.fragment, safe="")
    return out


def canon_host(v: Any) -> str | None:
    s = _as_str(v)
    if not s:
        return None
    if "://" in s:
        p = url_parts(s)
        return p.host if p else None
    s = s.split("/")[0].split(":")[0]
    host = _idna_host(s)
    return host if re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", host) else None


def canon_amount_decimal(v: Any) -> Decimal | None:
    """Parse 1250, '1,250.00', '$1250', '1250.0 EUR' -> Decimal('1250.00')."""
    d = parse_amount(v)
    return None if d is None else d.quantize(_CENT, rounding=ROUND_HALF_UP)


def parse_amount(v: Any) -> Decimal | None:
    """Parse an amount without rounding (keeps crypto precision)."""
    if isinstance(v, bool):
        return None
    if isinstance(v, Decimal):
        d = v
    elif isinstance(v, int):
        d = Decimal(v)
    elif isinstance(v, float):
        d = Decimal(repr(v))
    elif isinstance(v, str):
        s = _AMOUNT_STRIP_RE.sub("", normalize_text(v))
        if not _AMOUNT_NUM_RE.match(s):
            return None
        try:
            d = Decimal(s.replace(",", ""))
        except InvalidOperation:
            return None
    else:
        return None
    if not d.is_finite():
        return None
    return d


def canon_amount(v: Any) -> Decimal | None:
    return canon_amount_decimal(v)


def canon_path(v: Any) -> str | None:
    s = _as_str(v)
    if not s or "\x00" in s:
        return None
    s = s.replace("\\", "/")
    s = re.sub(r"/{2,}", "/", s)
    norm = posixpath.normpath(s)
    if norm == ".":
        return None
    return norm


def canon_handle(v: Any) -> str | None:
    s = _as_str(v)
    if not s:
        return None
    m = _HANDLE_RE.match(s.lower())
    return f"@{m.group(1)}" if m else None


def canon_channel(v: Any) -> str | None:
    s = _as_str(v)
    if not s:
        return None
    m = _CHANNEL_RE.match(s.lower())
    return f"#{m.group(1)}" if m else None


def canon_phone(v: Any) -> str | None:
    s = _as_str(v) if isinstance(v, str) else (str(v) if isinstance(v, int) and not isinstance(v, bool) else None)
    if not s:
        return None
    if re.search(r"[A-Za-z]", s):
        return None
    digits = re.sub(r"\D", "", s)
    if len(digits) < 7:
        return None
    return ("+" if s.lstrip().startswith("+") else "") + digits


def canon_date(v: Any) -> str | None:
    if isinstance(v, datetime):
        dt: datetime | date = v
    elif isinstance(v, date):
        dt = v
    else:
        s = _as_str(v)
        if not s:
            return None
        s = s.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            try:
                dt = date.fromisoformat(s)
            except ValueError:
                return None
        if isinstance(dt, datetime) and len(s) == 10:
            dt = dt.date()
    if isinstance(dt, datetime):
        return dt.strftime("%Y-%m-%dT%H:%M")
    return dt.isoformat()


def canon_crypto(v: Any) -> str | None:
    s = _as_str(v)
    if not s:
        return None
    return s if _CRYPTO_RE.match(s) else None


def canon_text(v: Any) -> str | None:
    if v is None:
        return None
    return skeleton(v if isinstance(v, str) else str(v))


def canon_command(v: Any) -> str | None:
    if isinstance(v, (list, tuple)):
        return normalize_text(" ".join(str(x) for x in v))
    if isinstance(v, str):
        return normalize_text(v)
    return None


def _canon_json(v: Any) -> str | None:
    try:
        return json.dumps(v, sort_keys=True, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        return None


def canonicalize(value: Any, arg_type: ArgType) -> str | None:
    """Dispatch to the canonicalizer for `arg_type`; None when the value does not parse."""
    match arg_type:
        case ArgType.EMAIL:
            return canon_email(value)
        case ArgType.IBAN:
            return canon_iban(value)
        case ArgType.URL:
            return canon_url(value)
        case ArgType.HOST:
            return canon_host(value)
        case ArgType.AMOUNT:
            d = canon_amount(value)
            return None if d is None else str(d)
        case ArgType.PATH:
            return canon_path(value)
        case ArgType.HANDLE:
            return canon_handle(value)
        case ArgType.CHANNEL:
            return canon_channel(value)
        case ArgType.PHONE:
            return canon_phone(value)
        case ArgType.DATE:
            return canon_date(value)
        case ArgType.CRYPTO_ADDRESS:
            return canon_crypto(value)
        case ArgType.COMMAND:
            return canon_command(value)
        case ArgType.TEXT | ArgType.SECRET_TEXT:
            return canon_text(value)
        case ArgType.ID | ArgType.ENUM:
            return None if value is None else normalize_text(str(value))
        case ArgType.BOOL:
            return None if not isinstance(value, bool) else ("true" if value else "false")
        case ArgType.INT:
            if isinstance(value, bool):
                return None
            try:
                return str(int(value))
            except (TypeError, ValueError):
                return None
        case ArgType.LIST | ArgType.DICT:
            return _canon_json(value)
    return None
