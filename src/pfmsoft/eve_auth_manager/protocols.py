"""Protocol and exception types for auth manager implementations."""

from collections.abc import Iterable
from typing import Annotated, Protocol
from uuid import UUID

from annotated_types import Ge, Le
from httpx2 import Client
from jwt import PyJWKClient

from pfmsoft.eve_auth_manager.models import (
    AuthCredential,
    AuthorizedCharacter,
    EsiAppCredential,
    OAuthMetadataTimestamped,
)


class AuthManagerError(Exception):
    """Base class for all AuthManager errors."""

    def __init__(self, *args: object) -> None:
        """Initialize the AuthManagerError with optional arguments."""
        super().__init__(*args)


class CredentialNotFoundError(AuthManagerError):
    """Raised when a credential is not found for a given ID or name."""

    def __init__(
        self, cred_id: UUID | None = None, cred_name: str | None = None, *args: object
    ) -> None:
        """Initialize the CredentialNotFoundError with the credential ID or name."""
        if cred_id is not None:
            message = f"Credential with ID {cred_id} not found."
        elif cred_name is not None:
            message = f"Credential with name {cred_name} not found."
        else:
            message = "Credential not found."
        super().__init__(message, *args)


class CharacterNotFoundError(AuthManagerError):
    """Raised when a character is not found for a given ID."""

    def __init__(self, cred_id: UUID, character_id: int, *args: object) -> None:
        """Initialize the CharacterNotFoundError with the character ID."""
        super().__init__(
            f"Character with ID {character_id} not found for credential ID {cred_id}.",
            *args,
        )


class CharactersNotFoundError(AuthManagerError):
    """Raised when characters are not found for a given credential ID.

    Could be raised when trying to revoke or refresh multiple characters and none of them are found.
    """

    def __init__(
        self, cred_id: UUID, character_ids: Iterable[int] | None = None, *args: object
    ) -> None:
        """Initialize the CharactersNotFoundError with the credential ID."""
        message = f"Characters not found for credential ID {cred_id}."
        if character_ids:
            message += f" Character IDs: {', '.join(map(str, character_ids))}."
        super().__init__(message, *args)


class AuthManagerProtocol(Protocol):
    """Behavioral contract for auth manager implementations.

    Defines the credential, authorized-character, token-refresh,
    token-revocation, and OAuth metadata access operations expected by the
    application.
    """

    def get_credential(
        self, *, cred_id: UUID | None = None, cred_name: str | None = None
    ) -> AuthCredential:
        """Get the credential for the given ID.

        Either `cred_id` or `cred_name` must be provided.

        Args:
            cred_id: The ID of the credential to retrieve.
            cred_name: The name of the credential to retrieve.

        Returns:
            The AuthCredential object if found.

        Raises:
            CredentialNotFoundError: If the credential with the given ID or name is not found.
        """
        ...

    def get_all_credentials(self) -> list[AuthCredential]:
        """Get all stored credentials.

        Returns:
            A list of all AuthCredential objects.
        """
        ...

    def add_credential(self, credential: EsiAppCredential) -> dict[UUID, str]:
        """Save the given credential and return its ID.

        Args:
            credential: The EsiAppCredential object to save.

        Returns:
            A dictionary mapping the UUID to the name of the saved credential.
        """
        ...

    def remove_credential(self, cred_id: UUID) -> dict[UUID, str]:
        """Remove the credential for the given ID.

        Also revokes all associated character tokens.

        Args:
            cred_id: The ID of the credential to remove.

        Returns:
            A dictionary mapping the removed credential ID to its name.

        Raises:
            CredentialNotFoundError: If the credential with the given ID is not found.
        """
        ...

    def get_character(self, cred_id: UUID, character_id: int) -> AuthorizedCharacter:
        """Get the authenticated character for the given character ID.

        Args:
            cred_id: The ID of the credential.
            character_id: The ID of the character to retrieve.

        Returns:
            The AuthorizedCharacter object if found.

        Raises:
            CharacterNotFoundError: If the character with the given ID is not found.
            CredentialNotFoundError: If the credential with the given ID is not found.
        """
        ...

    def add_character(
        self, cred_id: UUID, character: AuthorizedCharacter
    ) -> dict[int, str]:
        """Add an authenticated character.

        Args:
            cred_id: The ID of the credential.
            character: The AuthorizedCharacter object to add.

        Returns:
            A dictionary mapping character_id to name for the added character.

        Raises:
            CredentialNotFoundError: If the credential with the given ID is not found.
        """
        ...

    def revoke_character(self, cred_id: UUID, character_id: int) -> dict[int, str]:
        """Revoke the authenticated character for the given character ID.

        Also removes the character from the database.

        Args:
            cred_id: The ID of the credential.
            character_id: The ID of the character to revoke.

        Returns:
            A dictionary mapping character_id to name for the revoked character.

        Raises:
            CredentialNotFoundError: If the credential with the given ID is not found.
            CharacterNotFoundError: If the character with the given ID is not found.
        """
        ...

    def revoke_characters(
        self, cred_id: UUID, character_ids: set[int] | None = None
    ) -> dict[int, str]:
        """Revoke authorized characters for the given credential ID.

        If character_ids is None, revoke all authorized characters associated
        with the credential. Revoked characters are also removed from
        persistent storage.

        Args:
            cred_id: The ID of the credential.
            character_ids: The IDs of the characters to revoke. If None, revoke all
                characters.

        Returns:
            A dictionary mapping character_id to name for each revoked character.

        Raises:
            CredentialNotFoundError: If the credential with the given ID is not found.
        """
        ...

    def get_all_characters(self, cred_id: UUID) -> list[AuthorizedCharacter]:
        """Get all authorized characters for the given credential ID.

        Args:
            cred_id: The ID of the credential.

        Returns:
            A list of all AuthorizedCharacter objects.

        Raises:
            CredentialNotFoundError: If the credential with the given ID is not found.
        """
        ...

    def get_all_character_ids(self, cred_id: UUID) -> dict[int, str]:
        """Get all authorized character IDs for the given credential ID.

        Args:
            cred_id: The ID of the credential.

        Returns:
            A dictionary mapping character_id to name for each authenticated character.

        Raises:
            CredentialNotFoundError: If the credential with the given ID is not found.
        """
        ...

    def refresh_character(
        self,
        cred_id: UUID,
        character_id: int,
        *,
        min_seconds: Annotated[int, Ge(0), Le(1200)] = 300,
    ) -> AuthorizedCharacter:
        """Refresh the authorized character for the given character ID.

        Args:
            cred_id: The ID of the credential.
            character_id: The ID of the character to refresh.
            min_seconds: The minimum number of seconds until expiration before
                refreshing.

        Returns:
            The refreshed AuthorizedCharacter object.

        Raises:
            CredentialNotFoundError: If the credential with the given ID is not found.
            CharacterNotFoundError: If the character with the given ID is not found.
        """
        ...

    def refresh_characters(
        self,
        cred_id: UUID,
        character_ids: set[int] | None = None,
        *,
        min_seconds: Annotated[int, Ge(0), Le(1200)] = 300,
    ) -> list[AuthorizedCharacter]:
        """Refresh authorized characters for the given credential ID.

        If character_ids is None, refresh all authorized characters associated
        with the credential.

        Args:
            cred_id: The ID of the credential.
            character_ids: The IDs of the characters to refresh. If None, refresh all
                characters.
            min_seconds: The minimum number of seconds until expiration before
                refreshing.

        Returns:
            A list of refreshed AuthorizedCharacter objects.

        Raises:
            CredentialNotFoundError: If the credential with the given ID is not found.
        """
        ...

    @property
    def session(self) -> Client:
        """Return the HTTP client used for outbound requests.

        Raises:
            RuntimeError: If the implementation has not initialized its HTTP
                session.
        """
        ...

    @property
    def jwks_client(self) -> PyJWKClient:
        """Return the JWKS client used to verify ESI tokens.

        Raises:
            RuntimeError: If the implementation has not initialized its JWKS
                client.
        """
        ...

    @property
    def oauth_metadata(self) -> OAuthMetadataTimestamped:
        """Return the cached OAuth metadata used by the implementation.

        Raises:
            RuntimeError: If the implementation has not initialized or loaded
                OAuth metadata.
        """
        ...
