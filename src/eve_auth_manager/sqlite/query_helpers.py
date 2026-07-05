"""Helper functions for querying the SQLite database.

Functions that contain sql should reside in this module.
"""

import sqlite3
from uuid import UUID

from eve_auth_manager.helpers import json_io
from eve_auth_manager.models import (
    AuthCredential,
    AuthorizedCharacter,
    OAuthMetadataTimestamped,
)


def write_credentials(
    connection: sqlite3.Connection, *, credentials: AuthCredential
) -> None:
    """Write an AuthCredentials to the database."""
    with connection:
        connection.execute(
            """
            INSERT INTO credentials (
                cred_id,
                name,
                description,
                client_id,
                client_secret,
                callback_url,
                scopes,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(credentials.cred_id),
                credentials.name,
                credentials.description,
                credentials.clientId,
                credentials.clientSecret,
                credentials.callbackUrl,
                json_io.json_dumps(credentials.scopes),
                credentials.created_at,
            ),
        )


def query_credential(
    connection: sqlite3.Connection, *, cred_id: UUID
) -> AuthCredential | None:
    """Query the database for a credential by its ID."""
    cursor = connection.execute(
        "SELECT * FROM credentials WHERE cred_id = ?", (str(cred_id),)
    )
    row = cursor.fetchone()
    if row is None:
        return None
    return AuthCredential(
        cred_id=UUID(row["cred_id"]),
        name=row["name"],
        description=row["description"],
        clientId=row["client_id"],
        clientSecret=row["client_secret"],
        callbackUrl=row["callback_url"],
        scopes=json_io.json_loads(row["scopes"]),
        created_at=row["created_at"],
    )


def query_credential_by_name(
    connection: sqlite3.Connection, *, cred_name: str
) -> AuthCredential | None:
    """Query the database for a credential by its name."""
    cursor = connection.execute(
        "SELECT * FROM credentials WHERE name = ?", (cred_name,)
    )
    row = cursor.fetchone()
    if row is None:
        return None
    return AuthCredential(
        cred_id=UUID(row["cred_id"]),
        name=row["name"],
        description=row["description"],
        clientId=row["client_id"],
        clientSecret=row["client_secret"],
        callbackUrl=row["callback_url"],
        scopes=json_io.json_loads(row["scopes"]),
        created_at=row["created_at"],
    )


def query_credentials(connection: sqlite3.Connection) -> list[AuthCredential]:
    """Query the database for all credentials."""
    cursor = connection.execute("SELECT * FROM credentials")
    rows = cursor.fetchall()
    return [
        AuthCredential(
            cred_id=UUID(row["cred_id"]),
            name=row["name"],
            description=row["description"],
            clientId=row["client_id"],
            clientSecret=row["client_secret"],
            callbackUrl=row["callback_url"],
            scopes=json_io.json_loads(row["scopes"]),
            created_at=row["created_at"],
        )
        for row in rows
    ]


def delete_credentials(connection: sqlite3.Connection, *, cred_id: UUID) -> None:
    """Delete an AuthCredentials from the database."""
    with connection:
        connection.execute("DELETE FROM credentials WHERE cred_id = ?", (str(cred_id),))


def write_authorized_character(
    connection: sqlite3.Connection, *, character: AuthorizedCharacter
) -> None:
    """Write an AuthorizedCharacter to the database."""
    with connection:
        connection.execute(
            """
            INSERT INTO authorized_characters (
                character_id,
                cred_id,
                character_name,
                expires_at,
                oauth_token
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (cred_id, character_id) DO UPDATE SET
            character_name = excluded.character_name,
            expires_at = excluded.expires_at,
            oauth_token = excluded.oauth_token;
            """,
            (
                character.character_id,
                str(character.cred_id),
                character.character_name,
                character.expires_at,
                json_io.json_dumps(character.oauth_token.token_data),
            ),
        )


def query_authorized_character(
    connection: sqlite3.Connection, *, cred_id: UUID, character_id: int
) -> AuthorizedCharacter | None:
    """Query the database for an authorized character by its ID."""
    cursor = connection.execute(
        "SELECT * FROM authorized_characters WHERE cred_id = ? AND character_id = ?",
        (str(cred_id), character_id),
    )
    row = cursor.fetchone()
    if row is None:
        return None
    return AuthorizedCharacter(
        character_id=row["character_id"],
        cred_id=UUID(row["cred_id"]),
        character_name=row["character_name"],
        expires_at=row["expires_at"],
        oauth_token=json_io.json_loads(row["oauth_token"]),
    )


def query_authorized_characters(
    connection: sqlite3.Connection, *, cred_id: UUID
) -> list[AuthorizedCharacter]:
    """Query the database for all authorized characters for a given credential ID."""
    cursor = connection.execute(
        "SELECT * FROM authorized_characters WHERE cred_id = ?", (str(cred_id),)
    )
    rows = cursor.fetchall()
    return [
        AuthorizedCharacter(
            character_id=row["character_id"],
            cred_id=UUID(row["cred_id"]),
            character_name=row["character_name"],
            expires_at=row["expires_at"],
            oauth_token=json_io.json_loads(row["oauth_token"]),
        )
        for row in rows
    ]


def delete_authorized_character(
    connection: sqlite3.Connection, *, cred_id: UUID, character_id: int
) -> None:
    """Delete an authorized character from the database."""
    with connection:
        connection.execute(
            "DELETE FROM authorized_characters WHERE cred_id = ? AND character_id = ?",
            (str(cred_id), character_id),
        )


def write_oauth_metadata(
    connection: sqlite3.Connection, *, oauth_metadata: OAuthMetadataTimestamped
) -> None:
    """Write the OAuth metadata to the database."""
    with connection:
        connection.execute(
            "INSERT OR REPLACE INTO oauth_metadata (row_id, created_at, oauth_metadata) VALUES (1, ?, ?)",
            (oauth_metadata.timestamp, json_io.json_dumps(oauth_metadata.metadata)),
        )


def query_oauth_metadata(
    connection: sqlite3.Connection,
) -> OAuthMetadataTimestamped | None:
    """Query the database for the OAuth metadata."""
    cursor = connection.execute("SELECT * FROM oauth_metadata WHERE row_id = 1")
    row = cursor.fetchone()
    if row is None:
        return None
    return OAuthMetadataTimestamped(
        timestamp=row["created_at"],
        metadata=json_io.json_loads(row["oauth_metadata"]),
    )
