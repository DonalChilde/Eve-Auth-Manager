"""SQLite auth manager implementation stubs."""

import sqlite3
from pathlib import Path
from types import TracebackType
from typing import Annotated
from uuid import UUID

from annotated_types import Ge, Le
from httpx2 import AsyncClient, Client

from eve_auth_manager.helpers.http_session_factory import (
    config_async_http_client,
    config_http_client,
)
from eve_auth_manager.models import (
    AuthCredentials,
    AuthorizedCharacter,
    EsiAppCredentials,
    OAuthMetadataTimestamped,
)
from eve_auth_manager.protocols import AuthManagerProtocol
from eve_auth_manager.sqlite.connection_helpers import create_read_write_connection


class SqliteAuthManager(AuthManagerProtocol):
    """SQLite-backed implementation of the auth manager protocol."""

    def __init__(self, db_path: str | Path):
        """Initialize the auth manager with the SQLite database path.

        Args:
            db_path: Path to the SQLite database file.
        """
        self._db_path: Path = Path(db_path)
        self._sqlite_connection: sqlite3.Connection | None = None
        self._session: Client | None = None
        self._async_session: AsyncClient | None = None

    async def __aenter__(self) -> SqliteAuthManager:
        """Enter the async context manager.

        Opens a read/write SQLite connection and configures both sync and async
        HTTP clients used by auth operations.

        Returns:
            The initialized manager instance.
        """
        self._sqlite_connection = create_read_write_connection(self._db_path)
        self._session = config_http_client()
        self._async_session = await config_async_http_client()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Exit the async context manager.

        Ensures SQLite and HTTP client resources are closed.

        Args:
            exc_type: Exception type raised in the context body, if any.
            exc_value: Exception instance raised in the context body, if any.
            traceback: Traceback associated with the raised exception, if any.
        """
        if self._sqlite_connection:
            self._sqlite_connection.close()
        if self._session:
            self._session.close()
        if self._async_session:
            await self._async_session.aclose()

    def get_credentials(self, cred_id: UUID) -> AuthCredentials:
        """Get the credentials for the given ID.

        Args:
            cred_id: The ID of the credentials to retrieve.

        Returns:
            The AuthCredentials object if found.

        Raises:
            CredentialsNotFoundError: If the credentials with the given ID are
                not found.
        """
        raise NotImplementedError(
            "SqliteAuthManager.get_credentials is not implemented"
        )

    def get_all_credentials(self) -> list[AuthCredentials]:
        """Get all stored credentials.

        Returns:
            A list of all AuthCredentials objects.
        """
        raise NotImplementedError(
            "SqliteAuthManager.get_all_credentials is not implemented"
        )

    def add_credentials(self, credentials: EsiAppCredentials) -> dict[UUID, str]:
        """Save the given credentials and return their ID.

        Args:
            credentials: The EsiAppCredentials object to save.

        Returns:
            A dictionary mapping the UUID to the name of the saved credentials.
        """
        raise NotImplementedError(
            "SqliteAuthManager.add_credentials is not implemented"
        )

    async def remove_credentials(
        self,
        cred_id: UUID,
    ) -> dict[UUID, str]:
        """Remove the credentials for the given ID.

        Also revokes all associated character tokens.

        Args:
            cred_id: The ID of the credentials to remove.

        Returns:
            A dictionary mapping the removed credentials ID to its name.

        Raises:
            CredentialsNotFoundError: If the credentials with the given ID are
                not found.
        """
        raise NotImplementedError(
            "SqliteAuthManager.remove_credentials is not implemented"
        )

    def get_character(self, cred_id: UUID, character_id: int) -> AuthorizedCharacter:
        """Get the authenticated character for the given character ID.

        Args:
            cred_id: The ID of the credentials.
            character_id: The ID of the character to retrieve.

        Returns:
            The AuthorizedCharacter object if found.

        Raises:
            CharacterNotFoundError: If the character with the given ID is not
                found.
            CredentialsNotFoundError: If the credentials with the given ID are
                not found.
        """
        raise NotImplementedError("SqliteAuthManager.get_character is not implemented")

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
            CredentialsNotFoundError: If the credentials with the given ID are
                not found.
        """
        raise NotImplementedError("SqliteAuthManager.add_character is not implemented")

    def revoke_character(self, cred_id: UUID, character_id: int) -> dict[int, str]:
        """Revoke the authenticated character for the given character ID.

        Also removes the character from the database.

        Args:
            cred_id: The ID of the credentials.
            character_id: The ID of the character to revoke.

        Returns:
            A dictionary mapping the revoked character_id to its name.

        Raises:
            CredentialsNotFoundError: If the credentials with the given ID are
                not found.
            CharacterNotFoundError: If the character with the given ID is not
                found.
        """
        raise NotImplementedError(
            "SqliteAuthManager.revoke_character is not implemented"
        )

    async def revoke_characters(
        self, cred_id: UUID, character_ids: set[int] | None = None
    ) -> dict[int, str]:
        """Revoke the authenticated characters for the given character IDs.

        Also removes the characters from the database.

        Args:
            cred_id: The ID of the credentials.
            character_ids: The IDs of the characters to revoke.

        Returns:
            A dictionary mapping the revoked character_id to its name.

        Raises:
            CredentialsNotFoundError: If the credentials with the given ID are
                not found.
            CharacterNotFoundError: If any of the characters with the given IDs are not
                found.
        """
        raise NotImplementedError(
            "SqliteAuthManager.revoke_characters is not implemented"
        )

    def get_all_characters(self, cred_id: UUID) -> list[AuthorizedCharacter]:
        """Get all authenticated characters for the given credentials ID.

        Args:
            cred_id: The ID of the credentials.

        Returns:
            A list of all AuthorizedCharacter objects.

        Raises:
            CredentialsNotFoundError: If the credentials with the given ID are
                not found.
        """
        raise NotImplementedError(
            "SqliteAuthManager.get_all_characters is not implemented"
        )

    def get_all_character_ids(self, cred_id: UUID) -> dict[int, str]:
        """Get all authenticated character IDs for the given credentials ID.

        Args:
            cred_id: The ID of the credentials.

        Returns:
            A dictionary mapping the character_id to the name of all characters.

        Raises:
            CredentialsNotFoundError: If the credentials with the given ID are
                not found.
        """
        raise NotImplementedError(
            "SqliteAuthManager.get_all_character_ids is not implemented"
        )

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
            min_seconds: The minimum number of seconds til expiration before
                refreshing.

        Returns:
            The refreshed AuthorizedCharacter object.

        Raises:
            CredentialsNotFoundError: If the credentials with the given ID are
                not found.
            CharacterNotFoundError: If the character with the given ID is not
                found.
        """
        raise NotImplementedError(
            "SqliteAuthManager.refresh_character is not implemented"
        )

    async def refresh_characters(
        self,
        cred_id: UUID,
        character_ids: set[int] | None = None,
        *,
        min_seconds: Annotated[int, Ge(0), Le(1200)] = 300,
    ) -> list[AuthorizedCharacter]:
        """Refresh authenticated characters for the given credentials ID.

        Args:
            cred_id: The ID of the credentials.
            character_ids: The IDs of the characters to refresh. If None,
                refresh all characters.
            min_seconds: The minimum number of seconds til expiration before
                refreshing.

        Returns:
            A list of refreshed AuthorizedCharacter objects.

        Raises:
            CredentialsNotFoundError: If the credentials with the given ID are
                not found.
        """
        raise NotImplementedError(
            "SqliteAuthManager.refresh_characters is not implemented"
        )

    def get_oauth_metadata(self) -> OAuthMetadataTimestamped:
        """Get the OAuth metadata.

        Returns:
            The OAuthMetadataTimestamped object containing metadata and
            retrieval timestamp.
        """
        raise NotImplementedError(
            "SqliteAuthManager.get_oauth_metadata is not implemented"
        )

    def refresh_oauth_metadata(self) -> OAuthMetadataTimestamped:
        """Refresh the OAuth metadata.

        Returns:
            The refreshed OAuthMetadataTimestamped object.
        """
        raise NotImplementedError(
            "SqliteAuthManager.refresh_oauth_metadata is not implemented"
        )
