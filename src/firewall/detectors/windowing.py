"""Split long texts into overlapping windows (tokens if a tokenizer is given, characters otherwise)."""

from __future__ import annotations

from typing import Any, Protocol


class Tokenizer(Protocol):
    def encode(self, text: str, **kwargs: Any) -> list[int]: ...
    def decode(self, ids: list[int], **kwargs: Any) -> str: ...


CHAR_SIZE = 2000
CHAR_STRIDE = 1500


def windows(text: str, tokenizer: Tokenizer | None = None, size: int = 510, stride: int = 384) -> list[str]:
    """Overlapping windows of `size` tokens advancing by `stride` (character fallback: 2000 / 1500)."""
    if not text:
        return [""]
    if tokenizer is None:
        if len(text) <= CHAR_SIZE:
            return [text]
        out = [text[i:i + CHAR_SIZE] for i in range(0, len(text) - CHAR_SIZE + CHAR_STRIDE, CHAR_STRIDE)]
        return [w for w in out if w]
    ids = tokenizer.encode(text, add_special_tokens=False)
    if len(ids) <= size:
        return [text]
    chunks = []
    for start in range(0, len(ids), stride):
        chunk = ids[start:start + size]
        chunks.append(tokenizer.decode(chunk, skip_special_tokens=True))
        if start + size >= len(ids):
            break
    return chunks
