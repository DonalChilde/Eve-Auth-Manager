"""SQLite auth manager implementation stubs."""

import sqlite3
from pathlib import Path
from types import TracebackType
from typing import Annotated
from uuid import UUID, uuid4

from annotated_types import Ge, Le
from httpx2 import Client
from jwt.jwks_client import PyJWKClient
from whenever import Instant

from eve_auth_manager.auth import token_tools
from eve_auth_manager.helpers.http_session_factory import config_http_client
from eve_auth_manager.models import (
    AuthCredential,
    AuthorizedCharacter,
    EsiAppCredential,
    OAuthMetadataTimestamped,
)
from eve_auth_manager.protocols import (
    AuthManagerProtocol,
    CharacterNotFoundError,
    CharactersNotFoundError,
    CredentialNotFoundError,
)
from eve_auth_manager.settings import AUDIENCE, OAUTH_METADATA_URL, USER_AGENT
from eve_auth_manager.sqlite import query_helpers as query
from eve_auth_manager.sqlite.connection_helpers import create_read_write_connection


class SqliteAuthManager(AuthManagerProtocol):
    """SQLite-backed implementation of the auth manager protocol."""

    def __init__(
        self, db_path: str | Path, oauth_metadata_timeout: int = 604_800
    ) -> None:
        """Initialize the auth manager with the SQLite database path.

        Args:
            db_path: Path to the SQLite database file.
            oauth_metadata_timeout: Timeout for OAuth metadata in seconds. default is
                604,800 seconds (7 days).
        """
        self._db_path = Path(db_path)
        self._oauth_metadata_timeout = oauth_metadata_timeout
        self._sqlite_connection: sqlite3.Connection | None = None
        self._session: Client | None = None
        self._oauth_metadata: OAuthMetadataTimestamped | None = None
        self._jwks_client: PyJWKClient | None = None

    def __enter__(self) -> SqliteAuthManager:
        """Enter the async context manager.

        Opens a read/write SQLite connection and configures both sync and async
        HTTP clients used by auth operations.

        Returns:
            The initialized manager instance.
        """
        self._sqlite_connection = create_read_write_connection(self._db_path)
        self._session = config_http_client()
        self._ensure_oauth_metadata()
        return self

    def __exit__(
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

    def _fetch_oauth_metadata(self) -> OAuthMetadataTimestamped:
        """Fetch OAuth metadata from the ESI auth server.

        Returns:
            The OAuthMetadataTimestamped object containing metadata and
            retrieval timestamp.
        """
        if self._session is None:
            raise RuntimeError(
                "HTTP client session is not initialized. Use the context manager."
            )
        with self._session as session:
            response = session.get(
                OAUTH_METADATA_URL, headers={"User-Agent": USER_AGENT}
            )
            response.raise_for_status()
            metadata = response.json()
            return OAuthMetadataTimestamped(
                metadata=metadata, timestamp=Instant.now().timestamp()
            )

    def _ensure_oauth_metadata(self) -> None:
        """Ensure that OAuth metadata is loaded and the JWKS client is initialized.

        Must be called after the SQLite connection is established, and the HTTP client
        session is configured.
        """
        with self._connection_check() as conn:
            needs_refresh: bool = False
            self._oauth_metadata = query.query_oauth_metadata(conn)
            if self._oauth_metadata is None:
                needs_refresh = True
            if self._oauth_metadata is not None:
                cache_age = Instant.now().timestamp() - self._oauth_metadata.timestamp
                if cache_age > self._oauth_metadata_timeout:
                    needs_refresh = True
            if needs_refresh:
                self._oauth_metadata = self._fetch_oauth_metadata()
                query.write_oauth_metadata(conn, oauth_metadata=self._oauth_metadata)
        if self._oauth_metadata is None:
            raise RuntimeError("Failed to load OAuth metadata.")
        self._jwks_client = PyJWKClient(
            self._oauth_metadata.jwks_uri, headers={"User-Agent": USER_AGENT}
        )

    def _connection_check(self) -> sqlite3.Connection:
        """Ensure the SQLite connection is initialized and return it.

        Returns:
            The active SQLite connection.
        """
        if not self._sqlite_connection:
            raise RuntimeError("SQLite connection is not initialized.")
        return self._sqlite_connection

    def _session_check(self) -> Client:
        """Ensure the HTTP client session is initialized and return it.

        Returns:
            The active HTTP client session.
        """
        if not self._session:
            raise RuntimeError("HTTP client session is not initialized.")
        return self._session

    def _oauth_metadata_check(self) -> OAuthMetadataTimestamped:
        """Ensure the OAuth metadata is loaded and return it.

        Returns:
            The active OAuthMetadataTimestamped object.
        """
        if not self._oauth_metadata:
            raise RuntimeError("OAuth metadata is not loaded.")
        return self._oauth_metadata

    def _jwks_client_check(self) -> PyJWKClient:
        """Ensure the JWKS client is initialized and return it.

        Returns:
            The active PyJWKClient instance.
        """
        if not self._jwks_client:
            raise RuntimeError("JWKS client is not initialized.")
        return self._jwks_client

    def get_credential(
        self, *, cred_id: UUID | None = None, cred_name: str | None = None
    ) -> AuthCredential:
        """Get the credential for the given ID or name.

        Either `cred_id` or `cred_name` must be provided, but not both. If both are
        provided, `cred_id` takes precedence.

        Args:
            cred_id: The ID of the credential to retrieve.
            cred_name: The name of the credential to retrieve.

        Returns:
            The AuthCredential object if found.

        Raises:
            CredentialNotFoundError: If the credential with the given ID or name is
                not found.
        """
        with self._connection_check() as conn:
            if cred_id is not None:
                credential = query.query_credential(conn, cred_id=cred_id)
                if credential is None:
                    raise CredentialNotFoundError(cred_id=cred_id)
                return credential
            elif cred_name is not None:
                credential = query.query_credential_by_name(conn, cred_name=cred_name)
                if credential is None:
                    raise CredentialNotFoundError(cred_name=cred_name)
                return credential
            else:
                raise ValueError("Either cred_id or cred_name must be provided.")

    def get_all_credentials(self) -> list[AuthCredential]:
        """Get all stored credentials.

        Returns:
            A list of all AuthCredentials objects.
        """
        with self._connection_check() as conn:
            return query.query_credentials(conn)

    def add_credential(self, credential: EsiAppCredential) -> dict[UUID, str]:
        """Save the given credential and return its ID.

        Args:
            credential: The EsiAppCredential object to save.

        Returns:
            A dictionary mapping the UUID to the name of the saved credential.
        """
        with self._connection_check() as conn:
            auth_credential = AuthCredential(
                cred_id=uuid4(),
                name=credential.name,
                description=credential.description,
                clientId=credential.clientId,
                clientSecret=credential.clientSecret,
                callbackUrl=credential.callbackUrl,
                scopes=credential.scopes,
                created_at=Instant.now().timestamp(),
            )
            query.write_credentials(conn, credentials=auth_credential)
            return {auth_credential.cred_id: auth_credential.name}

    def remove_credential(
        self,
        cred_id: UUID,
    ) -> dict[UUID, str]:
        """Remove the credential for the given ID.

        Also revokes all associated character tokens.

        Args:
            cred_id: The ID of the credential to remove.

        Returns:
            A dictionary mapping the removed credential ID to its name.

        Raises:
            CredentialNotFoundError: If the credential with the given ID is
                not found.
        """
        with self._connection_check() as conn:
            credential = query.query_credential(conn, cred_id=cred_id)
            if credential is None:
                raise CredentialNotFoundError(cred_id=cred_id)
            characters = query.query_authorized_characters(conn, cred_id=cred_id)
            character_ids = [char.character_id for char in characters]
            if character_ids:
                self.revoke_characters(
                    cred_id=cred_id, character_ids=set(character_ids)
                )
            query.delete_credentials(conn, cred_id=cred_id)
            return {credential.cred_id: credential.name}

    def get_character(self, cred_id: UUID, character_id: int) -> AuthorizedCharacter:
        """Get the authenticated character for the given character ID.

        Args:
            cred_id: The ID of the credential.
            character_id: The ID of the character to retrieve.

        Returns:
            The AuthorizedCharacter object if found.

        Raises:
            CharacterNotFoundError: If the character with the given ID is not
                found.
            CredentialNotFoundError: If the credential with the given ID is
                not found.
        """
        with self._connection_check() as conn:
            credential = query.query_credential(conn, cred_id=cred_id)
            if credential is None:
                raise CredentialNotFoundError(cred_id=cred_id)
            character = query.query_authorized_character(
                conn, cred_id=cred_id, character_id=character_id
            )
            if character is None:
                raise CharacterNotFoundError(cred_id=cred_id, character_id=character_id)
            return character

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
            CredentialNotFoundError: If the credential with the given ID is
                not found.
        """
        with self._connection_check() as conn:
            credential = query.query_credential(conn, cred_id=cred_id)
            if credential is None:
                raise CredentialNotFoundError(cred_id=cred_id)
            query.write_authorized_character(conn, character=character)
            return {character.character_id: character.character_name}

    def revoke_character(self, cred_id: UUID, character_id: int) -> dict[int, str]:
        """Revoke the authenticated character for the given character ID.

        Also removes the character from the database.

        Args:
            cred_id: The ID of the credential.
            character_id: The ID of the character to revoke.

        Returns:
            A dictionary mapping the revoked character_id to its name.

        Raises:
            CredentialNotFoundError: If the credential with the given ID is
                not found.
            CharacterNotFoundError: If the character with the given ID is not
                found.
        """
        with self._connection_check() as conn:
            credential = query.query_credential(conn, cred_id=cred_id)
            if credential is None:
                raise CredentialNotFoundError(cred_id=cred_id)
            character = query.query_authorized_character(
                conn, cred_id=cred_id, character_id=character_id
            )
            if character is None:
                raise CharacterNotFoundError(cred_id=cred_id, character_id=character_id)
            session = self._session_check()
            oauth_metadata = self._oauth_metadata_check()
            token_tools.revoke_refresh_token(
                session=session,
                refresh_token=character.oauth_token.refresh_token,
                client_id=credential.clientId,
                oauth_metadata=oauth_metadata,
            )
            query.delete_authorized_character(
                conn, cred_id=cred_id, character_id=character_id
            )
            return {character.character_id: character.character_name}

    def revoke_characters(
        self, cred_id: UUID, character_ids: set[int] | None = None
    ) -> dict[int, str]:
        """Revoke the authenticated characters for the given character IDs.

        Also removes the characters from the database.

        Args:
            cred_id: The ID of the credential.
            character_ids: The IDs of the characters to revoke.

        Returns:
            A dictionary mapping the revoked character_id to its name.

        Raises:
            CredentialNotFoundError: If the credential with the given ID is not found.
            CharacterNotFoundError: If any of the characters with the given IDs are not
                found.
        """
        with self._connection_check() as conn:
            credential = query.query_credential(conn, cred_id=cred_id)
            if credential is None:
                raise CredentialNotFoundError(cred_id=cred_id)
            characters = query.query_authorized_characters(conn, cred_id=cred_id)
            # If character_ids is provided, filter the characters to only those specified.
            if character_ids is not None:
                available_character_ids = {char.character_id for char in characters}
                missing_character_ids = character_ids - available_character_ids
                # If any of the specified character IDs are not found, raise an error.
                if missing_character_ids:
                    raise CharactersNotFoundError(
                        cred_id=cred_id, character_ids=missing_character_ids
                    )
                characters = [
                    char for char in characters if char.character_id in character_ids
                ]
            session = self._session_check()
            oauth_metadata = self._oauth_metadata_check()
            revoked_characters: dict[int, str] = {}
            for character in characters:
                token_tools.revoke_refresh_token(
                    session=session,
                    refresh_token=character.oauth_token.refresh_token,
                    client_id=credential.clientId,
                    oauth_metadata=oauth_metadata,
                )
                query.delete_authorized_character(
                    conn, cred_id=cred_id, character_id=character.character_id
                )
                revoked_characters[character.character_id] = character.character_name
            return revoked_characters

    def get_all_characters(self, cred_id: UUID) -> list[AuthorizedCharacter]:
        """Get all authenticated characters for the given credential ID.

        Args:
            cred_id: The ID of the credential.

        Returns:
            A list of all AuthorizedCharacter objects.

        Raises:
            CredentialNotFoundError: If the credential with the given ID is
                not found.
        """
        with self._connection_check() as conn:
            credential = query.query_credential(conn, cred_id=cred_id)
            if credential is None:
                raise CredentialNotFoundError(cred_id=cred_id)
            return query.query_authorized_characters(conn, cred_id=cred_id)

    def get_all_character_ids(self, cred_id: UUID) -> dict[int, str]:
        """Get all authenticated character IDs for the given credential ID.

        Args:
            cred_id: The ID of the credential.

        Returns:
            A dictionary mapping the character_id to the name of all characters.

        Raises:
            CredentialNotFoundError: If the credential with the given ID is
                not found.
        """
        with self._connection_check() as conn:
            credential = query.query_credential(conn, cred_id=cred_id)
            if credential is None:
                raise CredentialNotFoundError(cred_id=cred_id)
            characters = query.query_authorized_characters(conn, cred_id=cred_id)
            return {char.character_id: char.character_name for char in characters}

    def refresh_character(
        self,
        cred_id: UUID,
        character_id: int,
        *,
        min_seconds: Annotated[int, Ge(0), Le(1200)] = 300,
    ) -> AuthorizedCharacter:
        """Refresh the authenticated character for the given character ID.

        Args:
            cred_id: The ID of the credential.
            character_id: The ID of the character to refresh.
            min_seconds: The minimum number of seconds til expiration before
                refreshing.

        Returns:
            The refreshed AuthorizedCharacter object.

        Raises:
            CredentialNotFoundError: If the credential with the given ID is not found.
            CharacterNotFoundError: If the character with the given ID is not found.
        """
        with self._connection_check() as conn:
            credential = query.query_credential(conn, cred_id=cred_id)
            if credential is None:
                raise CredentialNotFoundError(cred_id=cred_id)
            character = query.query_authorized_character(
                conn, cred_id=cred_id, character_id=character_id
            )
            if character is None:
                raise CharacterNotFoundError(cred_id=cred_id, character_id=character_id)
            # Check if the token needs to be refreshed based on min_seconds.
            if character.expires_in < min_seconds:
                session = self._session_check()
                oauth_metadata = self._oauth_metadata_check()
                refreshed_token = token_tools.refresh_existing_token(
                    session=session,
                    refresh_token=character.oauth_token.refresh_token,
                    client_id=credential.clientId,
                    oauth_metadata=oauth_metadata,
                )
                validated_token = token_tools.validate_token(
                    access_token=refreshed_token.access_token,
                    audience=AUDIENCE,
                    jwks_client=self._jwks_client_check(),
                    oauth_metadata=oauth_metadata,
                )
                updated_character = token_tools.create_character_token(
                    cred_id=cred_id,
                    oauth_token=refreshed_token,
                    validated_token=validated_token,
                )
                query.write_authorized_character(conn, character=updated_character)
                return updated_character
            else:
                return character

    def refresh_characters(
        self,
        cred_id: UUID,
        character_ids: set[int] | None = None,
        *,
        min_seconds: Annotated[int, Ge(0), Le(1200)] = 300,
    ) -> list[AuthorizedCharacter]:
        """Refresh authenticated characters for the given credential ID.

        Args:
            cred_id: The ID of the credential.
            character_ids: The IDs of the characters to refresh. If None,
                refresh all characters.
            min_seconds: The minimum number of seconds til expiration before
                refreshing.

        Returns:
            A list of refreshed AuthorizedCharacter objects.

        Raises:
            CredentialNotFoundError: If the credential with the given ID is not found.
        """
        with self._connection_check() as conn:
            credential = query.query_credential(conn, cred_id=cred_id)
            if credential is None:
                raise CredentialNotFoundError(cred_id=cred_id)
            characters = query.query_authorized_characters(conn, cred_id=cred_id)
            # If character_ids is provided, filter the characters to only those specified.
            if character_ids is not None:
                available_character_ids = {char.character_id for char in characters}
                missing_character_ids = character_ids - available_character_ids
                # If any of the specified character IDs are not found, raise an error.
                if missing_character_ids:
                    raise CharactersNotFoundError(
                        cred_id=cred_id, character_ids=missing_character_ids
                    )
                characters = [
                    char for char in characters if char.character_id in character_ids
                ]
            session = self._session_check()
            oauth_metadata = self._oauth_metadata_check()
            refreshed_characters: list[AuthorizedCharacter] = []
            for character in characters:
                if character.expires_in < min_seconds:
                    refreshed_token = token_tools.refresh_existing_token(
                        session=session,
                        refresh_token=character.oauth_token.refresh_token,
                        client_id=credential.clientId,
                        oauth_metadata=oauth_metadata,
                    )
                    validated_token = token_tools.validate_token(
                        access_token=refreshed_token.access_token,
                        audience=AUDIENCE,
                        jwks_client=self._jwks_client_check(),
                        oauth_metadata=oauth_metadata,
                    )
                    updated_character = token_tools.create_character_token(
                        cred_id=cred_id,
                        oauth_token=refreshed_token,
                        validated_token=validated_token,
                    )
                    query.write_authorized_character(conn, character=updated_character)
                    refreshed_characters.append(updated_character)
                else:
                    refreshed_characters.append(character)
            return refreshed_characters

    @property
    def session(self) -> Client:
        """Get the synchronous HTTP client session.

        Returns:
            The configured Client instance.

        Raises:
            RuntimeError: If the session is not initialized.
        """
        return self._session_check()

    @property
    def oauth_metadata(self) -> OAuthMetadataTimestamped:
        """Get the OAuth metadata.

        Returns:
            The OAuthMetadataTimestamped object.

        Raises:
            RuntimeError: If the OAuth metadata is not loaded.
        """
        return self._oauth_metadata_check()

    @property
    def jwks_client(self) -> PyJWKClient:
        """Get the JWKS client for verifying ESI tokens.

        Returns:
            The configured PyJWKClient instance.

        Raises:
            RuntimeError: If the JWKS client is not initialized.
        """
        return self._jwks_client_check()
