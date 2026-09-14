"""Deterministic decoders (base64 / hex / ROT13 / URL-encoding), trigger phrases, split-payload join.

Everything here produces *signals* and derived ledger text only; nothing here can allow or block a call.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
from typing import TYPE_CHECKING, Literal
from urllib.parse import unquote

from pydantic import BaseModel, ConfigDict

if TYPE_CHECKING:
    from firewall.core.provenance import LedgerEntry, Signal

B64_RE = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
URLENC_RE = re.compile(r"(?:[^\s%]*%[0-9A-Fa-f]{2}){3,}[^\s%]*")
SPLIT_WINDOW = 200

TRIGGER_PHRASES: dict[str, tuple[str, ...]] = {
    "en": ("ignore previous instructions", "ignore all previous", "ignore the above", "important instructions",
           "you must now", "new instructions", "forward all", "send money", "transfer", "system:",
           "disregard", "exfiltrate", "do not tell the user", "before you answer", "as the assistant you must"),
    "de": ("ignoriere", "vorherigen anweisungen", "neue anweisung", "überweise", "leite alle", "sende alle"),
    "es": ("ignora las instrucciones", "instrucciones anteriores", "nuevas instrucciones", "transfiere",
           "reenvía todos", "envía todos"),
    "fr": ("ignore les instructions", "nouvelle instruction", "instructions précédentes", "transfère",
           "envoie tous"),
    "zh": ("忽略之前", "忽略以上", "新的指令", "转账", "发送所有", "转发所有"),
    "hi": ("पिछले निर्देश", "निर्देशों को अनदेखा", "नए निर्देश", "पैसे भेजो", "सभी ईमेल"),
    "ru": ("игнорируй", "предыдущие инструкции", "новые инструкции", "переведи деньги", "перешли все"),
}
_EN_WORDS = ("ignore", "instructions", "forward", "send", "transfer", "password", "money", "email", "secret",
             "previous", "assistant", "system", "exfiltrate", "delete")


_ROT_WORDS = tuple(codecs.encode(w, "rot13") for w in _EN_WORDS)


class Decoded(BaseModel):
    model_config = ConfigDict(frozen=True)
    scheme: Literal["base64", "hex", "rot13", "url"]
    text: str
    span: tuple[int, int]


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for ch in s if ch.isprintable() or ch in "\n\r\t")
    return ok / len(s)


def _try_b64(token: str) -> str | None:
    if token.lower() == token or token.upper() == token:  # base64 of text mixes cases
        return None
    raw = token.rstrip("=")
    padded = raw + "=" * (-len(raw) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            data = decoder(padded)
        except (binascii.Error, ValueError):
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if len(text) >= 8 and _printable_ratio(text) >= 0.85 and any(c.isspace() for c in text):
            return text
    return None


def _count_en_words(text: str) -> int:
    lower = text.lower()
    return sum(1 for w in _EN_WORDS if w in lower)


def decode_candidates(text: str) -> list[Decoded]:
    """Decode embedded payloads; ROT13 only if the decoded text contains >= 2 trigger words."""
    out: list[Decoded] = []
    # Payload tokens are >= 16 chars without whitespace: pre-filter with C-speed split, then regex the few left.
    tokens = text.split() if len(text) >= 16 else []
    long_tokens = {t for t in tokens if len(t) >= 16} if tokens and max(map(len, tokens)) >= 16 else set()
    for tok in sorted(long_tokens):
        start = text.find(tok)
        for m in B64_RE.finditer(tok):
            dec = _try_b64(m.group(0))
            if dec is not None:
                out.append(Decoded(scheme="base64", text=dec, span=(start + m.start(), start + m.end())))
        for m in HEX_RE.finditer(tok):
            try:
                dec = bytes.fromhex(m.group(0)).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                continue
            if _printable_ratio(dec) >= 0.85:
                out.append(Decoded(scheme="hex", text=dec, span=(start + m.start(), start + m.end())))
    if "%" in text:
        for m in URLENC_RE.finditer(text):
            dec = unquote(m.group(0))
            if dec != m.group(0):
                out.append(Decoded(scheme="url", text=dec, span=m.span()))
    if text:
        lower = text.lower()
        if sum(1 for w in _ROT_WORDS if w in lower) >= 2:  # cheap gate before encoding the whole text
            rot = codecs.encode(text, "rot13")
            if _count_en_words(rot) >= 2 and _count_en_words(rot) > _count_en_words(text):
                out.append(Decoded(scheme="rot13", text=rot, span=(0, len(text))))
    return out


_PUNCT_TABLE = str.maketrans({c: " " for c in "\"'`.,;:!?()[]{}<>«»“”‘’-/\\|*_#@"})
_ASCII_PHRASES: tuple[tuple[str, str, str], ...] = tuple(
    (lang, p, p.translate(_PUNCT_TABLE).split()[0])
    for lang, phrases in TRIGGER_PHRASES.items() for p in phrases if p.isascii() and p.translate(_PUNCT_TABLE).split()
)
_OTHER_PHRASES: tuple[tuple[str, str], ...] = tuple(
    (lang, p) for lang, phrases in TRIGGER_PHRASES.items() for p in phrases if not p.isascii()
)


def trigger_phrases(text: str) -> list[tuple[str, str]]:
    """(lang, phrase) pairs found in `text` (case-insensitive).

    ASCII phrases are gated on their first word being present (one C-speed split) before the substring check.
    """
    lower = text.lower()
    words = set(lower.translate(_PUNCT_TABLE).split())
    found = [(lang, p) for lang, p, first in _ASCII_PHRASES if first in words and p in lower]
    if not lower.isascii():
        found += [(lang, p) for lang, p in _OTHER_PHRASES if p in lower]
    return found


def trigger_signals(text: str) -> list[Signal]:
    """One signal per language with at least one trigger phrase. Signals only — never a verdict."""
    from firewall.core.provenance import Signal

    by_lang: dict[str, list[str]] = {}
    for lang, phrase in trigger_phrases(text):
        by_lang.setdefault(lang, []).append(phrase)
    return [Signal(source="decoders", kind=f"trigger:{lang}", detail="; ".join(ps)) for lang, ps in by_lang.items()]


def split_payload_join(prev: LedgerEntry, nxt: LedgerEntry) -> str | None:
    """Tail of `prev` + head of `nxt` when both are untrusted and come from different calls."""
    if prev.label.trusted or nxt.label.trusted:
        return None
    if prev.call_id is not None and prev.call_id == nxt.call_id:
        return None
    return prev.text[-SPLIT_WINDOW:] + " " + nxt.text[:SPLIT_WINDOW]
