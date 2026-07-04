"""Protocol for the AuthManager class."""

from typing import Annotated, Protocol
from uuid import UUID

from annotated_types import Ge, Le

from eve_auth_manager.models import (
    AuthCredentials,
    AuthorizedCharacter,
    EsiAppCredentials,
    OAuthMetadataTimestamped,
)


class AuthManagerError(Exception):
    """Base class for all AuthManager errors."""

    def __init__(self, *args: object) -> None:
        """Initialize the AuthManagerError with optional arguments."""
        super().__init__(*args)


class CredentialsNotFoundError(AuthManagerError):
    """Raised when credentials are not found for a given ID."""

    def __init__(self, cred_id: UUID) -> None:
        """Initialize the CredentialsNotFoundError with the credentials ID."""
        super().__init__(f"Credentials with ID {cred_id} not found.")


class CharacterNotFoundError(AuthManagerError):
    """Raised when a character is not found for a given ID."""

    def __init__(self, cred_id: UUID, character_id: int) -> None:
        """Initialize the CharacterNotFoundError with the character ID."""
        super().__init__(
            f"Character with ID {character_id} not found for credentials ID {cred_id}."
        )


class AuthManagerProtocol(Protocol):
    """Protocol for the AuthManager class."""

    def get_credentials(self, cred_id: UUID) -> AuthCredentials:
        """Get the credentials for the given ID.

        Args:
            cred_id: The ID of the credentials to retrieve.

        Returns:
            The AuthCredentials object if found.

        Raises:
            CredentialsNotFoundError: If the credentials with the given ID are not found.
        """
        ...

    def get_all_credentials(self) -> list[AuthCredentials]:
        """Get all stored credentials.

        Returns:
            A list of all AuthCredentials objects.
        """
        ...

    def add_credentials(self, credentials: EsiAppCredentials) -> dict[UUID, str]:
        """Save the given credentials and return their ID.

        Args:
            credentials: The EsiAppCredentials object to save.

        Returns:
            A dictionary mapping the UUID to the name of the saved credentials.
        """
        ...

    def remove_credentials(self, cred_id: UUID) -> dict[UUID, str]:
        """Remove the credentials for the given ID.

        Also revokes all associated character tokens.

        Args:
            cred_id: The ID of the credentials to remove.

        Returns:
            A dictionary mapping the removed credentials ID to its name.

        Raises:
            CredentialsNotFoundError: If the credentials with the given ID are not found.
        """
        ...

    def get_character(self, cred_id: UUID, character_id: int) -> AuthorizedCharacter:
        """Get the authenticated character for the given character ID.

        Args:
            cred_id: The ID of the credentials.
            character_id: The ID of the character to retrieve.

        Returns:
            The AuthorizedCharacter object if found.

        Raises:
            CharacterNotFoundError: If the character with the given ID is not found.
            CredentialsNotFoundError: If the credentials with the given ID are not found.
        """
        ...

    def add_character(
        self, cred_id: UUID, character: AuthorizedCharacter
    ) -> dict[int, str]:
        """Add an authenticated character.

        Args:
            cred_id: The ID of the credentials.
            character: The AuthorizedCharacter object to add.

        Returns:
            A dictionary mapping character_id to name for the added character.

        Raises:
            CredentialsNotFoundError: If the credentials with the given ID are not found.
        """
        ...

    def revoke_character(self, cred_id: UUID, character_id: int) -> dict[int, str]:
        """Revoke the authenticated character for the given character ID.

        Also removes the character from the database.

        Args:
            cred_id: The ID of the credentials.
            character_id: The ID of the character to revoke.

        Returns:
            A dictionary mapping character_id to name for the revoked character.

        Raises:
            CredentialsNotFoundError: If the credentials with the given ID are not found.
            CharacterNotFoundError: If the character with the given ID is not found.
        """
        ...

    def revoke_characters(
        self, cred_id: UUID, character_ids: set[int] | None = None
    ) -> dict[int, str]:
        """Revoke all authenticated characters for the given credentials ID.

        Also removes the characters from the database.

        Args:
            cred_id: The ID of the credentials.
            character_ids: The IDs of the characters to revoke. If None, revoke all
                characters.

        Returns:
            A dictionary mapping character_id to name for each revoked character.

        Raises:
            CredentialsNotFoundError: If the credentials with the given ID are not found.
        """
        ...

    def get_all_characters(self, cred_id: UUID) -> list[AuthorizedCharacter]:
        """Get all authenticated characters for the given credentials ID.

        Args:
            cred_id: The ID of the credentials.

        Returns:
            A list of all AuthorizedCharacter objects.

        Raises:
            CredentialsNotFoundError: If the credentials with the given ID are not found.
        """
        ...

    def get_all_character_ids(self, cred_id: UUID) -> dict[int, str]:
        """Get all authenticated character IDs for the given credentials ID.

        Args:
            cred_id: The ID of the credentials.

        Returns:
            A dictionary mapping character_id to name for each authenticated character.

        Raises:
            CredentialsNotFoundError: If the credentials with the given ID are not found.
        """
        ...

    def refresh_character(
        self,
        cred_id: UUID,
        character_id: int,
        *,
        min_seconds: Annotated[int, Ge(0), Le(1200)] = 300,
    ) -> AuthorizedCharacter:
        """Refresh the authenticated character for the given character ID.

        Args:
            cred_id: The ID of the credentials.
            character_id: The ID of the character to refresh.
            min_seconds: The minimum number of seconds til expiration before refreshing.

        Returns:
            The refreshed AuthorizedCharacter object.

        Raises:
            CredentialsNotFoundError: If the credentials with the given ID are not found.
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
        """Refresh all authenticated characters for the given credentials ID.

        Args:
            cred_id: The ID of the credentials.
            character_ids: The IDs of the characters to refresh. If None, refresh all
                characters.
            min_seconds: The minimum number of seconds til expiration before refreshing.

        Returns:
            A list of refreshed AuthorizedCharacter objects.

        Raises:
            CredentialsNotFoundError: If the credentials with the given ID are not found.
        """
        ...

    def get_oauth_metadata(self) -> OAuthMetadataTimestamped:
        """Get the OAuth metadata.

        Returns:
            The OAuthMetadataTimestamped object containing the metadata and timestamp.
        """
        ...

    def refresh_oauth_metadata(self) -> OAuthMetadataTimestamped:
        """Refresh the OAuth metadata.

        Refresh the OAuth metadata from the EVE Online SSO and cache it in the database.
        This method should be called periodically to ensure that the metadata is
        up-to-date.

        Returns:
            The refreshed OAuthMetadataTimestamped object.
        """
        ...
