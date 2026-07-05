"""Tests for PKCE code challenge generation helpers."""

import base64
import builtins
import hashlib

import pytest

import eve_auth_manager.auth.code_challenge as code_challenge_module
from eve_auth_manager.auth.code_challenge import generate_code_challenge_and_verifier


def test_generate_code_challenge_and_verifier_returns_valid_pkce_pair(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Generated verifier and challenge should satisfy RFC 7636 expectations."""
    verifier = "A" * 64

    monkeypatch.setattr(
        code_challenge_module.secrets,
        "choice",
        lambda allowed_chars: "A",
    )

    result = generate_code_challenge_and_verifier()

    expected_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .decode("ascii")
        .rstrip("=")
    )
    assert result.code_verifier == verifier
    assert result.code_challenge == expected_challenge


def test_generate_code_challenge_and_verifier_rejects_invalid_length(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verifier generation should fail if an internal length invariant is broken."""
    monkeypatch.setattr(
        code_challenge_module,
        "range",
        lambda count: builtins.range(10),
        raising=False,
    )
    monkeypatch.setattr(
        code_challenge_module.secrets,
        "choice",
        lambda allowed_chars: "A",
    )

    with pytest.raises(
        ValueError, match="PKCE code_verifier length must be between 43 and 128"
    ):
        generate_code_challenge_and_verifier()


def test_generate_code_challenge_and_verifier_rejects_invalid_character(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verifier generation should fail if an internal character invariant is broken."""
    monkeypatch.setattr(
        code_challenge_module.secrets,
        "choice",
        lambda allowed_chars: "!",
    )

    with pytest.raises(
        ValueError, match="PKCE code_verifier contains invalid characters"
    ):
        generate_code_challenge_and_verifier()
