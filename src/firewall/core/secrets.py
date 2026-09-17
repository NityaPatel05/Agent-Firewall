"""Secret detection/masking (LivePI regex set) and canary detection.

Each pattern has lower-case prefilter keywords; the regex only runs if a keyword occurs in the text, which keeps
scanning of large tool outputs cheap.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from functools import lru_cache

from pydantic import BaseModel, ConfigDict

SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "bearer": re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{20,}=*"),
    "openai": re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}"),
    "github": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"),
    "aws": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "slack": re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    "password_assign": re.compile(r"(?i)\bpass(?:word|wd|phrase)?\s*[:=]\s*[\"']?[^\s\"',;]{6,}"),
    "api_key_assign": re.compile(
        r"(?i)\b(?:api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token)\s*[:=]\s*"
        r"[\"']?[A-Za-z0-9_\-./+]{12,}"
    ),
    "otp": re.compile(r"(?i)(?:2fa|otp|one[- ]time|verification|security|login)\s*(?:code|pin)?[^\d\n]{0,20}?(?<!\d)(\d{6})(?!\d)"),
    "solana_keyfile": re.compile(r"\[\s*(?:\d{1,3}\s*,\s*){63}\d{1,3}\s*\]"),
}

_PREFILTER: dict[str, tuple[str, ...]] = {
    "private_key": ("private key-----",),
    "bearer": ("bearer",),
    "openai": ("sk-",),
    "github": ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"),
    "aws": ("akia",),
    "slack": ("xox",),
    "jwt": ("eyj",),
    "password_assign": ("pass",),
    "api_key_assign": ("key", "secret", "token"),
    "otp": ("2fa", "otp", "one-time", "one time", "verification", "security", "login"),
    "solana_keyfile": ("[",),
}


class SecretHit(BaseModel):
    model_config = ConfigDict(frozen=True)
    kind: str
    span: tuple[int, int]


def find_secrets(text: str) -> list[SecretHit]:
    """All secret-looking spans (sorted by start)."""
    if not text:
        return []
    return list(_find_secrets_cached(text))


@lru_cache(maxsize=512)
def _find_secrets_cached(text: str) -> tuple[SecretHit, ...]:
    return tuple(_find_secrets(text))


def _find_secrets(text: str) -> list[SecretHit]:
    lower = text.lower()
    hits: list[SecretHit] = []
    for kind, rx in SECRET_PATTERNS.items():
        if not any(k in lower for k in _PREFILTER[kind]):
            continue
        if kind == "solana_keyfile" and text.count(",") < 63:
            continue
        for m in rx.finditer(text):
            span = m.span(1) if kind == "otp" else m.span()
            hits.append(SecretHit(kind=kind, span=span))
    hits.sort(key=lambda h: h.span)
    return hits


def has_secret(text: str) -> bool:
    return bool(find_secrets(text))


def mask_secrets(text: str) -> tuple[str, list[SecretHit]]:
    """Replace secret spans with «secret:<kind>» (overlapping spans merged)."""
    hits = find_secrets(text)
    if not hits:
        return text, []
    out: list[str] = []
    pos = 0
    for h in hits:
        start, end = h.span
        if start < pos:
            continue
        out.append(text[pos:start])
        out.append(f"«secret:{h.kind}»")
        pos = end
    out.append(text[pos:])
    return "".join(out), hits


def find_canaries(text: str, canaries: Iterable[str]) -> list[str]:
    lower = text.lower()
    return [c for c in canaries if c and c.lower() in lower]
