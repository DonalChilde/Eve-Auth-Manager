"""Helpers for exchanging, refreshing, revoking, and validating EVE SSO tokens."""

import logging
from collections.abc import Sequence
from typing import Any

from httpx2 import AsyncClient, Client, HTTPError
from jwt import ExpiredSignatureError, PyJWKClient, decode, get_unverified_header

logger = logging.getLogger(__name__)


class TokenValidationError(Exception):
    def __init__(self, *args: object) -> None:
        """Raised when token validation cannot be completed successfully."""
        super().__init__(*args)


class NewTokenRequestError(Exception):
    def __init__(self, *args: object) -> None:
        """Raised when exchanging an authorization code for token data fails."""
        super().__init__(*args)


class TokenRefreshError(Exception):
    def __init__(self, *args: object) -> None:
        """Raised when refreshing an OAuth token fails."""
        super().__init__(*args)


class TokenRevocationError(Exception):
    def __init__(self, *args: object) -> None:
        """Raised when submitting a token revocation request fails."""
        super().__init__(*args)


class DecodeTokenError(Exception):
    def __init__(self, *args: object) -> None:
        """Raised when a JWT cannot be decoded and validated."""
        super().__init__(*args)


def request_token(
    client_id: str,
    authorization_code: str,
    code_verifier: str,
    token_endpoint: str,
    session: Client,
) -> dict[str, Any]:
    """Exchange an authorization code and PKCE verifier for OAuth token data.

    Args:
        client_id: OAuth client identifier for the EVE application.
        authorization_code: Authorization code returned by the SSO callback.
        code_verifier: Original PKCE verifier paired with the authorization
            request.
        token_endpoint: Token endpoint URI used for code exchange.
        session: Configured HTTP client used to perform the request.

    Returns:
        Parsed token response from the SSO, including access token metadata and
        typically a refresh token.

    Raises:
        NewTokenRequestError: If the HTTP request fails or the response cannot
            be processed.
    """
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
    }
    payload: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": authorization_code,
        "client_id": client_id,
        "code_verifier": code_verifier,
    }
    try:
        response = session.post(token_endpoint, headers=headers, data=payload)
        response.raise_for_status()
        result = response.json()
    except HTTPError as e:
        logger.error(f"HTTP error during token request: {e}")
        raise NewTokenRequestError(f"HTTP error during token request: {e}") from e
    except Exception as e:
        logger.error(f"Unexpected error during token request: {e}")
        raise NewTokenRequestError(f"Unexpected error during token request: {e}") from e

    return result


def refresh_token(
    refresh_token: str,
    client_id: str,
    token_endpoint: str,
    session: Client,
) -> dict[str, Any]:
    """Exchange a refresh token for a new OAuth token response.

    Args:
        refresh_token: Refresh token issued by the SSO.
        client_id: OAuth client identifier for the EVE application.
        token_endpoint: Token endpoint URI used for token refresh.
        session: Configured HTTP client used to perform the request.

    Returns:
        Parsed token response from the SSO, including a replacement access
        token and usually a replacement refresh token.

    Raises:
        TokenRefreshError: If the HTTP request fails or the response cannot be
            processed.
    """
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
    }
    payload: dict[str, str] = {
        "client_id": client_id,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }
    try:
        response = session.post(token_endpoint, headers=headers, data=payload)
        response.raise_for_status()
        result = response.json()
    except HTTPError as e:
        logger.error(f"HTTP error during token refresh: {e}")
        raise TokenRefreshError(f"HTTP error during token refresh: {e}") from e
    except Exception as e:
        logger.error(f"Unexpected error during token refresh: {e}")
        raise TokenRefreshError(f"Unexpected error during token refresh: {e}") from e
    return result


def revoke_refresh_token(
    refresh_token: str,
    revocation_endpoint: str,
    client_id: str,
    session: Client,
) -> Any:
    """Request revocation of a refresh token.

    Note:
        The revocation endpoint may return HTTP 200 even when the token is
        already invalid or previously revoked. A successful response confirms
        the request was accepted, not that later refresh attempts are
        guaranteed to fail.

    Args:
        refresh_token: Refresh token to submit for revocation.
        revocation_endpoint: Revocation endpoint URI.
        client_id: OAuth client identifier for the EVE application.
        session: Configured HTTP client used to perform the request.

    Returns:
        Parsed response body returned by the revocation endpoint.

    Raises:
        TokenRevocationError: If the HTTP request fails or the response cannot
            be processed.
    """
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
    }
    payload: dict[str, str] = {
        "token": refresh_token,
        "token_type_hint": "refresh_token",
        "client_id": client_id,
    }
    try:
        response = session.post(revocation_endpoint, headers=headers, data=payload)
        response.raise_for_status()
        return response.json()
    except HTTPError as e:
        logger.error(f"HTTP error during token revocation: {e}")
        raise TokenRevocationError(f"HTTP error during token revocation: {e}") from e
    except Exception as e:
        logger.error(f"Unexpected error during token revocation: {e}")
        raise TokenRevocationError(
            f"Unexpected error during token revocation: {e}"
        ) from e


async def async_request_token(
    client_id: str,
    authorization_code: str,
    code_verifier: str,
    token_endpoint: str,
    session: AsyncClient,
) -> dict[str, Any]:
    """Exchange an authorization code and PKCE verifier for OAuth token data.

    Args:
        client_id: OAuth client identifier for the EVE application.
        authorization_code: Authorization code returned by the SSO callback.
        code_verifier: Original PKCE verifier paired with the authorization
            request.
        token_endpoint: Token endpoint URI used for code exchange.
        session: Configured async HTTP client used to perform the request.

    Returns:
        Parsed token response from the SSO, including access token metadata and
        typically a refresh token.

    Raises:
        ValueError: If session is not initialized.
        NewTokenRequestError: If the HTTP request fails or the response cannot
            be processed.
    """
    if not session:
        raise ValueError("session must be initialized to request token.")
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
    }
    payload: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": authorization_code,
        "client_id": client_id,
        "code_verifier": code_verifier,
    }
    try:
        response = await session.post(token_endpoint, headers=headers, data=payload)
        response.raise_for_status()
        result = await response.json()
    except HTTPError as e:
        logger.error(f"HTTP error during async token request: {e}")
        raise NewTokenRequestError(f"HTTP error during async token request: {e}") from e
    except Exception as e:
        logger.error(f"Unexpected error during async token request: {e}")
        raise NewTokenRequestError(
            f"Unexpected error during async token request: {e}"
        ) from e

    return result


async def async_refresh_token(
    refresh_token: str,
    client_id: str,
    token_endpoint: str,
    session: AsyncClient,
) -> dict[str, Any]:
    """Exchange a refresh token for a new OAuth token response.

    Args:
        refresh_token: Refresh token issued by the SSO.
        client_id: OAuth client identifier for the EVE application.
        token_endpoint: Token endpoint URI used for token refresh.
        session: Configured async HTTP client used to perform the request.

    Returns:
        Parsed token response from the SSO, including a replacement access
        token and usually a replacement refresh token.

    Raises:
        ValueError: If session is not initialized.
        TokenRefreshError: If the HTTP request fails or the response cannot be
            processed.
    """
    if not session:
        raise ValueError("session must be initialized to refresh token.")
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
    }
    payload: dict[str, str] = {
        "client_id": client_id,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }
    try:
        response = await session.post(token_endpoint, headers=headers, data=payload)
        response.raise_for_status()
        result = await response.json()
    except HTTPError as e:
        logger.error(f"HTTP error during async token refresh: {e}")
        raise TokenRefreshError(f"HTTP error during async token refresh: {e}") from e
    except Exception as e:
        logger.error(f"Unexpected error during async token refresh: {e}")
        raise TokenRefreshError(
            f"Unexpected error during async token refresh: {e}"
        ) from e
    return result


async def async_revoke_refresh_token(
    refresh_token: str,
    revocation_endpoint: str,
    client_id: str,
    session: AsyncClient,
) -> Any:
    """Request revocation of a refresh token.

    Note:
        The revocation endpoint may return HTTP 200 even when the token is
        already invalid or previously revoked. A successful response confirms
        the request was accepted, not that later refresh attempts are
        guaranteed to fail.

    Args:
        refresh_token: Refresh token to submit for revocation.
        revocation_endpoint: Revocation endpoint URI.
        client_id: OAuth client identifier for the EVE application.
        session: Configured async HTTP client used to perform the request.

    Returns:
        None. Success is indicated by the request completing without raising.

    Raises:
        TokenRevocationError: If the HTTP request fails or the response cannot
            be processed.
    """
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
    }
    payload: dict[str, str] = {
        "token": refresh_token,
        "token_type_hint": "refresh_token",
        "client_id": client_id,
    }

    try:
        response = await session.post(
            revocation_endpoint, headers=headers, data=payload
        )
        response.raise_for_status()
        if response.status_code == 200:
            logger.info("Token revoked successfully")
    except HTTPError as e:
        logger.error(f"HTTP error during async token revocation: {e}")
        raise TokenRevocationError(
            f"HTTP error during async token revocation: {e}"
        ) from e
    except Exception as e:
        logger.error(f"Unexpected error during async token revocation: {e}")
        raise TokenRevocationError(
            f"Unexpected error during async token revocation: {e}"
        ) from e


def validate_jwt_token(
    access_token: str,
    jwks_client: PyJWKClient | None,
    audience: str,
    issuers: Sequence[str],
    user_agent: str | None = None,
    jwks_uri: str | None = None,
) -> dict[str, Any]:
    """Validate and decode a JWT access token.

    Args:
        access_token: JWT access token to validate.
        jwks_client: Optional JWKS client to reuse for signing-key lookups and
            caching. If omitted, a new client will be created.
        audience: Expected token audience enforced during validation.
        issuers: Allowed token issuers enforced during validation.
        user_agent: User-Agent header to use when creating a new JWKS client.
        jwks_uri: JWKS endpoint URI to use when creating a new JWKS client.

    Returns:
        Decoded token claims for a token that passed signature and claim
        validation.

    Raises:
        ValueError: If jwks_uri is not provided when jwks_client is None.
        DecodeTokenError: If the token is expired, invalid, or cannot be
            decoded.
    """
    # NOTE the jwks_client can cache the keys, so we dont have to fetch them every time.
    # Pass in a jwks_client if you have one.

    if jwks_client is None:
        headers = {"User-Agent": user_agent or "Token validation without User-Agent"}
        if not jwks_uri:
            raise ValueError("jwks_uri must be provided if jwks_client is None")
        if not user_agent:
            logger.warning(
                "User-Agent is empty when fetching JWKS keys with PyJWKClient. It's "
                "recommended to provide a User-Agent string when fetching JWKS keys."
            )
        jwks_client = PyJWKClient(jwks_uri, headers=headers)
    unverified_header = get_unverified_header(access_token)
    kid = unverified_header["kid"]
    alg = unverified_header["alg"]
    signing_key = jwks_client.get_signing_key(kid).key
    try:
        # Decode and validate the token
        valid_decoded_token = decode(
            jwt=access_token,
            key=signing_key,
            algorithms=[alg],
            audience=audience,
            issuer=issuers,
            options={"verify_aud": True, "verify_iss": True},
        )

        return valid_decoded_token
    except ExpiredSignatureError as e:
        logger.error("Token has expired")
        raise DecodeTokenError(f"Token has expired. {e}") from e
    except Exception as e:
        logger.error(f"Invalid token or other error: {e}")
        raise DecodeTokenError(f"Invalid token or other error: {e}") from e
