"""High-level token helpers that wrap OAuth operations in eve_auth_manager models."""

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
    """Exchange an authorization code for an `OauthToken` model.

    Wraps the lower-level OAuth token request helper and converts the parsed
    token response into the application token model.

    Args:
        session: Configured HTTP client used to perform the request.
        client_id: OAuth client identifier for the application.
        authorization_code: Authorization code returned by the OAuth callback.
        code_verifier: PKCE verifier paired with the authorization request.
        oauth_metadata: OAuth endpoint metadata used to resolve the token
            endpoint.

    Returns:
        OauthToken built from the parsed token response.
    """
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
    """Asynchronously exchange an authorization code for an `OauthToken`.

    Wraps the lower-level async OAuth token request helper and converts the
    parsed token response into the application token model.

    Args:
        session: Configured async HTTP client used to perform the request.
        client_id: OAuth client identifier for the application.
        authorization_code: Authorization code returned by the OAuth callback.
        code_verifier: PKCE verifier paired with the authorization request.
        oauth_metadata: OAuth endpoint metadata used to resolve the token
            endpoint.

    Returns:
        OauthToken built from the parsed token response.
    """
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
    """Refresh an OAuth token and return the replacement `OauthToken` model.

    Args:
        session: Configured HTTP client used to perform the request.
        refresh_token: Refresh token issued by the OAuth provider.
        client_id: OAuth client identifier for the application.
        oauth_metadata: OAuth endpoint metadata used to resolve the token
            endpoint.

    Returns:
        OauthToken built from the parsed refresh response.
    """
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
    """Asynchronously refresh an OAuth token and return an `OauthToken`.

    Args:
        session: Configured async HTTP client used to perform the request.
        refresh_token: Refresh token issued by the OAuth provider.
        client_id: OAuth client identifier for the application.
        oauth_metadata: OAuth endpoint metadata used to resolve the token
            endpoint.

    Returns:
        OauthToken built from the parsed refresh response.
    """
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
    """Submit a refresh-token revocation request.

    Delegates to the lower-level OAuth helper using revocation metadata and
    returns the parsed response body unchanged.

    Args:
        session: Configured HTTP client used to perform the request.
        refresh_token: Refresh token to revoke.
        client_id: OAuth client identifier for the application.
        oauth_metadata: OAuth endpoint metadata used to resolve the revocation
            endpoint.

    Returns:
        Parsed response body returned by the revocation endpoint.
    """
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
    """Validate a JWT access token and return a `ValidatedToken` model.

    Uses the provided JWKS client and OAuth issuer metadata to verify the token
    signature and claims, then wraps the decoded claims in the application
    model.

    Args:
        access_token: JWT access token to validate.
        jwks_client: JWKS client used to resolve signing keys.
        oauth_metadata: OAuth metadata providing valid token issuers.
        audience: Expected token audience. Defaults to the configured
            application audience.

    Returns:
        ValidatedToken built from the verified token claims.
    """
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
    """Create an `AuthorizedCharacter` from validated token data.

    Combines credential ownership, raw OAuth token data, and validated
    character claims into the application model used to represent an
    authorized character.

    Args:
        cred_id: Credential identifier that owns the authorized character.
        oauth_token: Raw OAuth token response wrapped in the application model.
        validated_token: Validated token claims containing character identity
            and expiration data.

    Returns:
        AuthorizedCharacter model populated from the supplied token data.
    """
    return AuthorizedCharacter(
        oauth_token=oauth_token,
        character_id=validated_token.character_id,
        character_name=validated_token.character_name,
        cred_id=cred_id,
        expires_at=validated_token.expires_at,
    )
