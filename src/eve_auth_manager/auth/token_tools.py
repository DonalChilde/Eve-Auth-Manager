"""Helper functions for working with ESI Oauth tokens."""

import logging
from typing import Any
from uuid import UUID

from httpx2 import AsyncClient, Client
from jwt.jwks_client import PyJWKClient

from eve_auth_manager.auth import oauth_tokens as oauth_helpers
from eve_auth_manager.models import (
    AuthorizedCharacter,
    OAuthMetadataTimestamped,
    OauthToken,
    ValidatedToken,
)
from eve_auth_manager.settings import AUDIENCE

logger = logging.getLogger(__name__)


def request_new_token(
    session: Client,
    *,
    client_id: str,
    authorization_code: str,
    code_verifier: str,
    oauth_metadata: OAuthMetadataTimestamped,
) -> OauthToken:
    """Request a new token using the authorization code flow."""
    token_response = oauth_helpers.request_token(
        client_id=client_id,
        authorization_code=authorization_code,
        code_verifier=code_verifier,
        token_endpoint=oauth_metadata.token_endpoint,
        session=session,
    )
    return OauthToken(token_data=token_response)


async def async_request_new_token(
    session: AsyncClient,
    *,
    client_id: str,
    authorization_code: str,
    code_verifier: str,
    oauth_metadata: OAuthMetadataTimestamped,
) -> OauthToken:
    """Asynchronously request a new token using the authorization code flow."""
    token_response = await oauth_helpers.async_request_token(
        client_id=client_id,
        authorization_code=authorization_code,
        code_verifier=code_verifier,
        token_endpoint=oauth_metadata.token_endpoint,
        session=session,
    )
    return OauthToken(token_data=token_response)


def refresh_existing_token(
    session: Client,
    *,
    refresh_token: str,
    client_id: str,
    oauth_metadata: OAuthMetadataTimestamped,
) -> OauthToken:
    """Refresh an existing token using the refresh token."""
    token_response = oauth_helpers.refresh_token(
        refresh_token=refresh_token,
        client_id=client_id,
        token_endpoint=oauth_metadata.token_endpoint,
        session=session,
    )
    return OauthToken(token_data=token_response)


async def async_refresh_existing_token(
    session: AsyncClient,
    *,
    refresh_token: str,
    client_id: str,
    oauth_metadata: OAuthMetadataTimestamped,
) -> OauthToken:
    """Asynchronously refresh an existing token using the refresh token."""
    token_response = await oauth_helpers.async_refresh_token(
        refresh_token=refresh_token,
        client_id=client_id,
        token_endpoint=oauth_metadata.token_endpoint,
        session=session,
    )
    return OauthToken(token_data=token_response)


def revoke_refresh_token(
    session: Client,
    *,
    refresh_token: str,
    client_id: str,
    oauth_metadata: OAuthMetadataTimestamped,
) -> Any:
    """Revoke a refresh token."""
    return oauth_helpers.revoke_refresh_token(
        refresh_token=refresh_token,
        revocation_endpoint=oauth_metadata.revocation_endpoint,
        client_id=client_id,
        session=session,
    )


def validate_token(
    access_token: str,
    *,
    jwks_client: PyJWKClient,
    oauth_metadata: OAuthMetadataTimestamped,
    audience: str = AUDIENCE,
) -> ValidatedToken:
    """Validate an access token and return the decoded token data if valid."""
    validated_token_data = oauth_helpers.validate_jwt_token(
        access_token=access_token,
        audience=audience,
        jwks_client=jwks_client,
        issuers=oauth_metadata.issuers,
    )
    return ValidatedToken(token_data=validated_token_data)


def create_character_token(
    cred_id: UUID, oauth_token: OauthToken, validated_token: ValidatedToken
) -> AuthorizedCharacter:
    """Create a CharacterToken from a validated OauthToken by extracting character info."""
    return AuthorizedCharacter(
        oauth_token=oauth_token,
        character_id=validated_token.character_id,
        character_name=validated_token.character_name,
        cred_id=cred_id,
        expires_at=validated_token.expires_at,
    )
