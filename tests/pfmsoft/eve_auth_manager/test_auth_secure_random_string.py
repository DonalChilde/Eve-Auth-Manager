"""Tests for secure random string helpers."""

import string

import pytest

import pfmsoft.eve_auth_manager.auth.secure_random_string as secure_random_string_module
from pfmsoft.eve_auth_manager.auth.secure_random_string import (
    generate_secure_random_string,
)


def test_generate_secure_random_string_returns_requested_length(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Secure random string generation should use only alphanumeric characters."""
    sequence = iter("AbC123")

    def fake_choice(characters: str) -> str:
        assert characters == string.ascii_letters + string.digits
        return next(sequence)

    monkeypatch.setattr(secure_random_string_module.secrets, "choice", fake_choice)

    assert generate_secure_random_string(6) == "AbC123"


@pytest.mark.parametrize("length", [0, -1])
def test_generate_secure_random_string_rejects_non_positive_length(length: int) -> None:
    """Secure random string generation should reject invalid lengths."""
    with pytest.raises(ValueError, match="length must be greater than 0"):
        generate_secure_random_string(length)
