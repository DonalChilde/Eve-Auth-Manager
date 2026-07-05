"""Tests for high-level token helper wrappers."""

import asyncio
from uuid import UUID

import pytest

import eve_auth_manager.auth.token_tools as token_tools
from eve_auth_manager.models import OAuthMetadataTimestamped, OauthToken, ValidatedToken


def _oauth_metadata() -> OAuthMetadataTimestamped:
    """Create OAuth metadata for token helper tests."""
    return OAuthMetadataTimestamped(
        metadata={
            "issuer": ["https://issuer.example"],
            "authorization_endpoint": "https://issuer.example/authorize",
            "token_endpoint": "https://issuer.example/token",
            "jwks_uri": "https://issuer.example/jwks",
            "revocation_endpoint": "https://issuer.example/revoke",
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_signing_alg_values_supported": ["RS256"],
        },
        timestamp=123,
    )


def test_token_tool_request_refresh_revoke_validate_and_create_wrappers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Synchronous wrappers should delegate to oauth helpers with metadata."""
    metadata = _oauth_metadata()
    session = object()
    jwks_client = object()
    events: dict[str, dict[str, object]] = {}

    def fake_request_token(**kwargs: object) -> dict[str, object]:
        events["request"] = kwargs
        return {
            "access_token": "access",
            "refresh_token": "refresh",
            "expires_in": 10,
            "token_type": "Bearer",
        }

    def fake_refresh_token(**kwargs: object) -> dict[str, object]:
        events["refresh"] = kwargs
        return {
            "access_token": "fresh-access",
            "refresh_token": "fresh-refresh",
            "expires_in": 20,
            "token_type": "Bearer",
        }

    def fake_revoke_refresh_token(**kwargs: object) -> dict[str, object]:
        events["revoke"] = kwargs
        return {"revoked": True}

    def fake_validate_jwt_token(**kwargs: object) -> dict[str, object]:
        events["validate"] = kwargs
        return {
            "sub": "CHARACTER:EVE:99",
            "name": "Pilot 99",
            "iat": 100,
            "exp": 200,
        }

    monkeypatch.setattr(
        token_tools.oauth_helpers,
        "request_token",
        fake_request_token,
    )
    monkeypatch.setattr(
        token_tools.oauth_helpers,
        "refresh_token",
        fake_refresh_token,
    )
    monkeypatch.setattr(
        token_tools.oauth_helpers,
        "revoke_refresh_token",
        fake_revoke_refresh_token,
    )
    monkeypatch.setattr(
        token_tools.oauth_helpers,
        "validate_jwt_token",
        fake_validate_jwt_token,
    )

    requested = token_tools.request_new_token(
        session,
        client_id="client-id",
        authorization_code="auth-code",
        code_verifier="verifier",
        oauth_metadata=metadata,
    )
    refreshed = token_tools.refresh_existing_token(
        session,
        refresh_token="refresh-me",
        client_id="client-id",
        oauth_metadata=metadata,
    )
    revoked = token_tools.revoke_refresh_token(
        session,
        refresh_token="refresh-me",
        client_id="client-id",
        oauth_metadata=metadata,
    )
    validated = token_tools.validate_token(
        "jwt-token",
        jwks_client=jwks_client,  # type: ignore[arg-type]
        oauth_metadata=metadata,
    )
    created = token_tools.create_character_token(
        UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), refreshed, validated
    )

    assert isinstance(requested, OauthToken)
    assert requested.access_token == "access"
    assert isinstance(refreshed, OauthToken)
    assert refreshed.refresh_token == "fresh-refresh"
    assert revoked == {"revoked": True}
    assert isinstance(validated, ValidatedToken)
    assert validated.character_id == 99
    assert created.character_id == 99
    assert created.character_name == "Pilot 99"
    assert created.oauth_token is refreshed

    assert events["request"] == {
        "client_id": "client-id",
        "authorization_code": "auth-code",
        "code_verifier": "verifier",
        "token_endpoint": metadata.token_endpoint,
        "session": session,
    }
    assert events["refresh"] == {
        "refresh_token": "refresh-me",
        "client_id": "client-id",
        "token_endpoint": metadata.token_endpoint,
        "session": session,
    }
    assert events["revoke"] == {
        "refresh_token": "refresh-me",
        "revocation_endpoint": metadata.revocation_endpoint,
        "client_id": "client-id",
        "session": session,
    }
    assert events["validate"] == {
        "access_token": "jwt-token",
        "audience": token_tools.AUDIENCE,
        "jwks_client": jwks_client,
        "issuers": metadata.issuers,
    }


def test_async_token_tool_wrappers_delegate_to_async_oauth_helpers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Async wrappers should delegate and wrap results in OauthToken."""
    metadata = _oauth_metadata()
    session = object()
    events: dict[str, dict[str, object]] = {}

    async def fake_request_token(**kwargs: object) -> dict[str, object]:
        events["request"] = kwargs
        return {
            "access_token": "access",
            "refresh_token": "refresh",
            "expires_in": 10,
            "token_type": "Bearer",
        }

    async def fake_refresh_token(**kwargs: object) -> dict[str, object]:
        events["refresh"] = kwargs
        return {
            "access_token": "fresh-access",
            "refresh_token": "fresh-refresh",
            "expires_in": 20,
            "token_type": "Bearer",
        }

    monkeypatch.setattr(
        token_tools.oauth_helpers, "async_request_token", fake_request_token
    )
    monkeypatch.setattr(
        token_tools.oauth_helpers, "async_refresh_token", fake_refresh_token
    )

    requested = asyncio.run(
        token_tools.async_request_new_token(
            session,  # type: ignore[arg-type]
            client_id="client-id",
            authorization_code="auth-code",
            code_verifier="verifier",
            oauth_metadata=metadata,
        )
    )
    refreshed = asyncio.run(
        token_tools.async_refresh_existing_token(
            session,  # type: ignore[arg-type]
            refresh_token="refresh-me",
            client_id="client-id",
            oauth_metadata=metadata,
        )
    )

    assert requested.access_token == "access"
    assert refreshed.refresh_token == "fresh-refresh"
    assert events["request"]["token_endpoint"] == metadata.token_endpoint
    assert events["refresh"]["token_endpoint"] == metadata.token_endpoint
