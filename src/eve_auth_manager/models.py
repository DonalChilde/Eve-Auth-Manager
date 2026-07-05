"""Domain models for Eve Auth Manager credentials, tokens, characters, and OAuth metadata."""

from dataclasses import dataclass, field
from typing import TypedDict
from uuid import UUID

from pydantic import RootModel
from whenever import Instant


@dataclass(slots=True, kw_only=True, frozen=True)
class EsiAppCredential:
    """EVE application credential.

    Field names match the JSON keys returned by the ESI app registration page.
    https://developers.eveonline.com/applications
    """

    name: str
    description: str
    clientId: str
    clientSecret: str
    callbackUrl: str
    scopes: list[str] = field(default_factory=list[str])


@dataclass(slots=True, kw_only=True, frozen=True)
class AuthCredential(EsiAppCredential):
    """Stored application credential with database identity and creation timestamp."""

    cred_id: UUID
    """Identifier used to distinguish between multiple credential sets."""
    created_at: int
    """The timestamp of when the credential was created, in seconds since the epoch."""


@dataclass(slots=True, frozen=True)
class OauthToken:
    """Wrapper around a raw OAuth token response payload.

    Exposes typed accessors for the token fields required by the application.
    The wrapped mapping is expected to contain the standard OAuth token keys
    returned by the EVE SSO.
    """

    token_data: dict[str, str | int]

    @property
    def access_token(self) -> str:
        """Return the access token string."""
        value = self.token_data["access_token"]
        assert isinstance(value, str)
        return value

    @property
    def refresh_token(self) -> str:
        """Return the refresh token string."""
        value = self.token_data["refresh_token"]
        assert isinstance(value, str)
        return value

    @property
    def expires_in(self) -> int:
        """Return the number of seconds until the token expires."""
        value = self.token_data["expires_in"]
        assert isinstance(value, int)
        return value

    @property
    def token_type(self) -> str:
        """Return the token type."""
        value = self.token_data["token_type"]
        assert isinstance(value, str)
        return value


@dataclass(slots=True, frozen=True)
class ValidatedToken:
    """Wrapper around validated JWT claims returned from token verification.

    Provides typed accessors for the EVE character identity and token timing
    claims used by the application.
    """

    token_data: dict[str, str | int | list[str]]

    @property
    def character_id(self) -> int:
        """Return the EVE character ID parsed from the JWT sub claim."""
        sub = self.token_data["sub"]
        assert isinstance(sub, str)
        prefix = "CHARACTER:EVE:"
        assert sub.startswith(prefix)
        character_id_str = sub[len(prefix) :]
        return int(character_id_str)

    @property
    def character_name(self) -> str:
        """Return the character name."""
        value = self.token_data["name"]
        assert isinstance(value, str)
        return value

    @property
    def issued_at(self) -> int:
        """Return the token issuance time as a UNIX timestamp."""
        value = self.token_data["iat"]
        assert isinstance(value, int)
        return value

    @property
    def expires_at(self) -> int:
        """Return the token expiration time as a UNIX timestamp."""
        value = self.token_data["exp"]
        assert isinstance(value, int)
        return value


@dataclass(slots=True, frozen=True)
class AuthorizedCharacter:
    """Authorized EVE character linked to a stored credential and token state."""

    character_id: int
    """The ID of the character."""
    cred_id: UUID
    """The ID of the credential."""
    character_name: str
    """The name of the character."""
    expires_at: int
    """Expiration time as a UNIX timestamp."""
    oauth_token: OauthToken
    """The OAuth token for the character."""

    @property
    def expires_in(self) -> int:
        """Return the number of seconds until the token expires."""
        return self.expires_at - Instant.now().timestamp()

    @property
    def auth_headers(self) -> dict[str, str]:
        """Return the auth headers to use for authenticated requests to ESI."""
        return {"Authorization": f"Bearer {self.oauth_token.access_token}"}

    @property
    def access_token(self) -> str:
        """Return the access token string."""
        return self.oauth_token.access_token


class OAuthMetadataTD(TypedDict):
    """TypedDict representing the OAuth provider metadata discovery document."""

    issuer: str | list[str]
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    revocation_endpoint: str
    code_challenge_methods_supported: list[str]
    token_endpoint_auth_signing_alg_values_supported: list[str]


@dataclass(slots=True, frozen=True)
class OAuthMetadataTimestamped:
    """OAuth metadata paired with the timestamp when it was fetched."""

    metadata: OAuthMetadataTD
    """The OAuth metadata as a dictionary."""
    timestamp: int
    """The timestamp of when the metadata was fetched, in seconds since the epoch."""

    @property
    def timestamp_instant(self) -> Instant:
        """Return the fetch timestamp as a whenever.Instant."""
        return Instant.from_timestamp(self.timestamp)

    @property
    def issuers(self) -> list[str]:
        """Return the issuer metadata normalized to a list of strings."""
        value = self.metadata["issuer"]
        if isinstance(value, str):
            return [value]
        return value

    @property
    def authorization_endpoint(self) -> str:
        """The authorization endpoint of the OAuth metadata."""
        return self.metadata["authorization_endpoint"]

    @property
    def token_endpoint(self) -> str:
        """The token endpoint of the OAuth metadata."""
        return self.metadata["token_endpoint"]

    @property
    def jwks_uri(self) -> str:
        """The JWKS URI of the OAuth metadata."""
        return self.metadata["jwks_uri"]

    @property
    def revocation_endpoint(self) -> str:
        """The revocation endpoint of the OAuth metadata."""
        return self.metadata["revocation_endpoint"]

    @property
    def code_challenge_methods_supported(self) -> list[str]:
        """The code challenge methods supported by the OAuth metadata."""
        return self.metadata["code_challenge_methods_supported"]

    @property
    def token_endpoint_auth_signing_alg_values_supported(self) -> list[str]:
        """The token endpoint auth signing algorithms supported by the OAuth metadata."""
        return self.metadata["token_endpoint_auth_signing_alg_values_supported"]


class AuthorizedDict(TypedDict):
    """TypedDict for an authorized character.

    This is the public representation of an authorized character.

    It should include just enough information to be used to make authenticated requests
    to ESI, without exposing sensitive information like the refresh token.
    """

    cred_id: str
    character_id: int
    character_name: str
    expires_at: int
    access_token: str


EsiAppCredentialRoot = RootModel[EsiAppCredential]
AuthorizedDictRoot = RootModel[AuthorizedDict]
