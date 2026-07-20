"""Tests for SQLite-backed query helper functions."""

import sqlite3
from pathlib import Path
from uuid import UUID

from pfmsoft.eve_snippets.sqlite3.connection_helpers import (
    create_read_write_connection,
)

from pfmsoft.eve_auth_manager.models import (
    AuthCredential,
    AuthorizedCharacter,
    OAuthMetadataTimestamped,
    OauthToken,
)
from pfmsoft.eve_auth_manager.sqlite.query_helpers import (
    delete_authorized_character,
    delete_credentials,
    load_table_definitions,
    query_authorized_character,
    query_authorized_characters,
    query_credential,
    query_credential_by_name,
    query_credentials,
    query_oauth_metadata,
    write_authorized_character,
    write_credentials,
    write_oauth_metadata,
)


def _make_credential(*, cred_id: UUID, name: str) -> AuthCredential:
    """Create a stored credential fixture."""
    return AuthCredential(
        cred_id=cred_id,
        created_at=1_234,
        name=name,
        description=f"Description for {name}",
        clientId=f"{name}-client-id",
        clientSecret=f"{name}-secret",
        callbackUrl=f"https://example.com/{name}",
        scopes=["scope.one", "scope.two"],
    )


def _make_character(*, cred_id: UUID, character_id: int) -> AuthorizedCharacter:
    """Create an authorized character fixture."""
    return AuthorizedCharacter(
        character_id=character_id,
        cred_id=cred_id,
        character_name=f"Character {character_id}",
        expires_at=4_600 + character_id,
        oauth_token=OauthToken(
            token_data={
                "access_token": f"access-token-{character_id}",
                "refresh_token": f"refresh-token-{character_id}",
                "expires_in": 3_600,
                "token_type": "Bearer",
            }
        ),
    )


def _open_db(tmp_path: Path) -> sqlite3.Connection:
    """Create a schema-initialized SQLite connection for tests."""
    return create_read_write_connection(
        tmp_path / "auth.db", init_sql=load_table_definitions()
    )


def test_credential_queries_round_trip_and_delete(tmp_path: Path) -> None:
    """Credential helpers should write, fetch, list, and delete credentials."""
    first = _make_credential(
        cred_id=UUID("11111111-1111-1111-1111-111111111111"),
        name="primary-app",
    )
    second = _make_credential(
        cred_id=UUID("22222222-2222-2222-2222-222222222222"),
        name="backup-app",
    )
    connection = _open_db(tmp_path)
    try:
        assert query_credential(connection, cred_id=first.cred_id) is None
        assert query_credential_by_name(connection, cred_name=first.name) is None

        write_credentials(connection, credentials=first)
        write_credentials(connection, credentials=second)

        assert query_credential(connection, cred_id=first.cred_id) == first
        assert query_credential_by_name(connection, cred_name=second.name) == second
        assert query_credentials(connection) == [first, second]

        delete_credentials(connection, cred_id=first.cred_id)

        assert query_credential(connection, cred_id=first.cred_id) is None
        assert query_credentials(connection) == [second]
    finally:
        connection.close()


def test_authorized_character_queries_round_trip_update_and_delete(
    tmp_path: Path,
) -> None:
    """Authorized character helpers should upsert, fetch, list, and delete rows."""
    credential = _make_credential(
        cred_id=UUID("33333333-3333-3333-3333-333333333333"),
        name="primary-app",
    )
    first = _make_character(cred_id=credential.cred_id, character_id=7)
    second = _make_character(cred_id=credential.cred_id, character_id=9)
    updated_first = AuthorizedCharacter(
        character_id=first.character_id,
        cred_id=first.cred_id,
        character_name="Updated Character 7",
        expires_at=9_999,
        oauth_token=OauthToken(
            token_data={
                "access_token": "updated-access-token",
                "refresh_token": "updated-refresh-token",
                "expires_in": 7_200,
                "token_type": "Bearer",
            }
        ),
    )
    connection = _open_db(tmp_path)
    try:
        write_credentials(connection, credentials=credential)

        assert (
            query_authorized_character(
                connection, cred_id=credential.cred_id, character_id=first.character_id
            )
            is None
        )

        write_authorized_character(connection, character=first)
        write_authorized_character(connection, character=second)

        assert (
            query_authorized_character(
                connection, cred_id=credential.cred_id, character_id=first.character_id
            )
            == first
        )
        assert query_authorized_characters(connection, cred_id=credential.cred_id) == [
            first,
            second,
        ]

        write_authorized_character(connection, character=updated_first)

        assert (
            query_authorized_character(
                connection,
                cred_id=credential.cred_id,
                character_id=updated_first.character_id,
            )
            == updated_first
        )

        delete_authorized_character(
            connection, cred_id=credential.cred_id, character_id=second.character_id
        )

        assert query_authorized_characters(connection, cred_id=credential.cred_id) == [
            updated_first
        ]
    finally:
        connection.close()


def test_oauth_metadata_queries_round_trip_singleton_cache(tmp_path: Path) -> None:
    """OAuth metadata helpers should replace and fetch the singleton cache row."""
    first = OAuthMetadataTimestamped(
        metadata={
            "issuer": "issuer-a",
            "authorization_endpoint": "https://example.com/authorize",
            "token_endpoint": "https://example.com/token",
            "jwks_uri": "https://example.com/jwks",
            "revocation_endpoint": "https://example.com/revoke",
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_signing_alg_values_supported": ["RS256"],
        },
        timestamp=111,
    )
    second = OAuthMetadataTimestamped(
        metadata={
            "issuer": ["issuer-b", "issuer-c"],
            "authorization_endpoint": "https://example.com/authorize2",
            "token_endpoint": "https://example.com/token2",
            "jwks_uri": "https://example.com/jwks2",
            "revocation_endpoint": "https://example.com/revoke2",
            "code_challenge_methods_supported": ["S256", "plain"],
            "token_endpoint_auth_signing_alg_values_supported": ["RS256", "ES256"],
        },
        timestamp=222,
    )
    connection = _open_db(tmp_path)
    try:
        assert query_oauth_metadata(connection) is None

        write_oauth_metadata(connection, oauth_metadata=first)
        assert query_oauth_metadata(connection) == first

        write_oauth_metadata(connection, oauth_metadata=second)
        assert query_oauth_metadata(connection) == second
    finally:
        connection.close()
