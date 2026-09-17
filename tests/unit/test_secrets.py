from __future__ import annotations

import pytest

from firewall.core.secrets import find_canaries, find_secrets, has_secret, mask_secrets

POSITIVE = {
    "bearer": "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345",
    "openai": "key sk-proj-AbCdEfGhIjKlMnOpQrStUvWx",
    "github": "deploy ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
    "aws": "AKIAIOSFODNN7EXAMPLE",
    "slack": "xoxb-1234567890-abcdefghij",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIE...",
    "password_assign": "db password=Hunter2!x",
    "api_key_assign": "API_KEY: 9f8e7d6c5b4a39281706",
    "otp": "Your 2FA code is 492817.",
    "solana_keyfile": "[" + ",".join(str(i % 256) for i in range(64)) + "]",
}
NEGATIVE = {
    "bearer": "the bearer of bad news",
    "openai": "ask-me-anything",
    "github": "ghp_short",
    "aws": "AKIA123",
    "slack": "xox",
    "jwt": "eyJ only",
    "private_key": "-----BEGIN PUBLIC KEY-----",
    "password_assign": "password: abc",
    "api_key_assign": "api key rotation is monthly",
    "otp": "order 492817 shipped",
    "solana_keyfile": "[1, 2, 3]",
}


@pytest.mark.parametrize("kind", sorted(POSITIVE))
def test_positive(kind: str) -> None:
    assert kind in {h.kind for h in find_secrets(POSITIVE[kind])}


@pytest.mark.parametrize("kind", sorted(NEGATIVE))
def test_negative(kind: str) -> None:
    assert kind not in {h.kind for h in find_secrets(NEGATIVE[kind])}


def test_mask_preserves_surroundings() -> None:
    text = "before AKIAIOSFODNN7EXAMPLE after"
    masked, hits = mask_secrets(text)
    assert masked == "before «secret:aws» after" and len(hits) == 1
    assert mask_secrets("nothing here") == ("nothing here", [])


def test_otp_masks_only_digits() -> None:
    masked, _ = mask_secrets("Your 2FA code is 492817.")
    assert masked == "Your 2FA code is «secret:otp»."


def test_canaries() -> None:
    assert find_canaries("x canary-7f3a9c y", ["CANARY-7f3a9c", "CANARY-b41e02"]) == ["CANARY-7f3a9c"]
    assert find_canaries("clean", ["CANARY-7f3a9c"]) == []
    assert has_secret(POSITIVE["aws"]) and not has_secret("hello")
