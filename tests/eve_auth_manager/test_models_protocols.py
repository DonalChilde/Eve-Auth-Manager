"""Tests for domain models and protocol exception types."""

from types import SimpleNamespace
from uuid import UUID

import pytest

import eve_auth_manager.models as models_module
from eve_auth_manager.models import (
    AuthorizedCharacter,
    AuthorizedDictRoot,
    OAuthMetadataTimestamped,
    OauthToken,
    ValidatedToken,
)
from eve_auth_manager.protocols import (
    AuthManagerError,
    CharacterNotFoundError,
    CharactersNotFoundError,
    CredentialNotFoundError,
)


def test_oauth_and_validated_token_accessors_expose_typed_values() -> None:
    """Token wrappers should expose the expected typed fields."""
    oauth_token = OauthToken(
        token_data={
            "access_token": "access-token",
            "refresh_token": "refresh-token",
            "expires_in": 1_800,
            "token_type": "Bearer",
        }
    )
    validated = ValidatedToken(
        token_data={
            "sub": "CHARACTER:EVE:42",
            "name": "Jane Capsuleer",
            "iat": 100,
            "exp": 200,
            "scp": ["esi-mail.read_mail.v1"],
        }
    )

    assert oauth_token.access_token == "access-token"
    assert oauth_token.refresh_token == "refresh-token"
    assert oauth_token.expires_in == 1_800
    assert oauth_token.token_type == "Bearer"

    assert validated.character_id == 42
    assert validated.character_name == "Jane Capsuleer"
    assert validated.issued_at == 100
    assert validated.expires_at == 200


def test_authorized_character_properties_forward_token_and_expiry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Authorized character helpers should derive headers and expiry correctly."""
    cred_id = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    oauth_token = OauthToken(
        token_data={
            "access_token": "access-token",
            "refresh_token": "refresh-token",
            "expires_in": 1_800,
            "token_type": "Bearer",
        }
    )
    character = AuthorizedCharacter(
        character_id=7,
        cred_id=cred_id,
        character_name="Test Pilot",
        expires_at=1_250,
        oauth_token=oauth_token,
    )

    class FakeInstant:
        @staticmethod
        def now() -> SimpleNamespace:
            return SimpleNamespace(timestamp=lambda: 1_000)

    monkeypatch.setattr(models_module, "Instant", FakeInstant)

    assert character.expires_in == 250
    assert character.auth_headers == {"Authorization": "Bearer access-token"}
    assert character.access_token == "access-token"


def test_oauth_metadata_timestamped_properties_normalize_and_forward_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """OAuth metadata wrapper should normalize issuers and expose endpoints."""
    metadata = {
        "issuer": "https://issuer.example",
        "authorization_endpoint": "https://issuer.example/authorize",
        "token_endpoint": "https://issuer.example/token",
        "jwks_uri": "https://issuer.example/jwks",
        "revocation_endpoint": "https://issuer.example/revoke",
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_signing_alg_values_supported": ["RS256"],
    }

    class FakeInstant:
        @staticmethod
        def from_timestamp(value: int) -> str:
            return f"instant:{value}"

    monkeypatch.setattr(models_module, "Instant", FakeInstant)
    wrapped = OAuthMetadataTimestamped(metadata=metadata, timestamp=500)

    assert wrapped.timestamp_instant == "instant:500"
    assert wrapped.issuers == ["https://issuer.example"]
    assert wrapped.authorization_endpoint == metadata["authorization_endpoint"]
    assert wrapped.token_endpoint == metadata["token_endpoint"]
    assert wrapped.jwks_uri == metadata["jwks_uri"]
    assert wrapped.revocation_endpoint == metadata["revocation_endpoint"]
    assert (
        wrapped.code_challenge_methods_supported
        == metadata["code_challenge_methods_supported"]
    )
    assert (
        wrapped.token_endpoint_auth_signing_alg_values_supported
        == metadata["token_endpoint_auth_signing_alg_values_supported"]
    )

    list_wrapped = OAuthMetadataTimestamped(
        metadata={**metadata, "issuer": ["https://issuer.example", "https://alt"]},
        timestamp=600,
    )
    assert list_wrapped.issuers == ["https://issuer.example", "https://alt"]


def test_authorized_dict_root_validates_public_character_shape() -> None:
    """Public authorized character payload should validate through the root model."""
    payload = AuthorizedDictRoot.model_validate(
        {
            "cred_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "character_id": 7,
            "character_name": "Test Pilot",
            "expires_at": 1_250,
            "access_token": "access-token",
        }
    )

    assert payload.root["character_name"] == "Test Pilot"
    assert payload.root["access_token"] == "access-token"


def test_protocol_exceptions_render_expected_messages() -> None:
    """Protocol error types should expose stable, user-facing messages."""
    cred_id = UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")

    assert str(AuthManagerError("boom")) == "boom"
    assert str(CredentialNotFoundError(cred_id=cred_id)) == (
        f"Credential with ID {cred_id} not found."
    )
    assert str(CredentialNotFoundError(cred_name="main")) == (
        "Credential with name main not found."
    )
    assert str(CredentialNotFoundError()) == "Credential not found."
    assert str(CharacterNotFoundError(cred_id=cred_id, character_id=7)) == (
        f"Character with ID 7 not found for credential ID {cred_id}."
    )
    assert str(CharactersNotFoundError(cred_id=cred_id)) == (
        f"Characters not found for credential ID {cred_id}."
    )
    assert str(CharactersNotFoundError(cred_id=cred_id, character_ids=[7, 9])) == (
        f"Characters not found for credential ID {cred_id}. Character IDs: 7, 9."
    )
