"""Tests for the SQLite-backed auth manager."""

# pyright: standard
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid5

import pytest
from pfmsoft.eve_snippets.sqlite3.connection_helpers import (
    create_read_write_connection,
)
from whenever import Instant

import pfmsoft.eve_auth_manager.sqlite.manager as manager_module
from pfmsoft.eve_auth_manager.models import (
    AuthCredential,
    AuthorizedCharacter,
    EsiAppCredential,
    OAuthMetadataTimestamped,
    OauthToken,
)
from pfmsoft.eve_auth_manager.protocols import (
    CharacterNotFoundError,
    CharactersNotFoundError,
    CredentialNotFoundError,
)
from pfmsoft.eve_auth_manager.settings import APP_NAMESPACE
from pfmsoft.eve_auth_manager.sqlite.manager import SqliteAuthManager
from pfmsoft.eve_auth_manager.sqlite.query_helpers import load_table_definitions


def _metadata_payload() -> dict[str, object]:
    """Build OAuth metadata with the fields required by the manager."""
    return {
        "issuer": "https://login.eveonline.com",
        "authorization_endpoint": "https://login.eveonline.com/authorize",
        "token_endpoint": "https://login.eveonline.com/token",
        "jwks_uri": "https://login.eveonline.com/jwks",
        "revocation_endpoint": "https://login.eveonline.com/revoke",
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_signing_alg_values_supported": ["RS256"],
    }


def _make_app_credential(name: str = "primary-app") -> EsiAppCredential:
    """Create an app credential fixture."""
    return EsiAppCredential(
        name=name,
        description=f"Description for {name}",
        clientId=f"{name}-client-id",
        clientSecret=f"{name}-client-secret",
        callbackUrl=f"https://example.com/{name}",
        scopes=["scope.one", "scope.two"],
    )


def _make_authorized_character(
    *, cred_id: UUID, character_id: int
) -> AuthorizedCharacter:
    """Create an authorized character fixture with a live-ish token payload."""
    return AuthorizedCharacter(
        character_id=character_id,
        cred_id=cred_id,
        character_name=f"Character {character_id}",
        expires_at=Instant.now().timestamp() + 3_600,
        oauth_token=OauthToken(
            token_data={
                "access_token": f"access-token-{character_id}",
                "refresh_token": f"refresh-token-{character_id}",
                "expires_in": 3_600,
                "token_type": "Bearer",
            }
        ),
    )


def _enter_manager(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    fetched_timestamp: int = 1_000,
) -> tuple[SqliteAuthManager, dict[str, object]]:
    """Enter a manager with mocked HTTP metadata fetch and JWKS setup."""
    events: dict[str, object] = {"closed": False, "get_calls": []}
    db_path = tmp_path / "auth.db"
    metadata = _metadata_payload()

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return metadata

    class FakeSession:
        def get(self, url: str, headers: dict[str, str]) -> FakeResponse:
            events["get_calls"].append({"url": url, "headers": headers})
            return FakeResponse()

        def close(self) -> None:
            events["closed"] = True

    class FakeInstant:
        @staticmethod
        def now() -> SimpleNamespace:
            return SimpleNamespace(timestamp=lambda: fetched_timestamp)

    monkeypatch.setattr(manager_module, "config_http_client", lambda: FakeSession())
    monkeypatch.setattr(
        manager_module,
        "PyJWKClient",
        lambda url, headers=None: SimpleNamespace(url=url, headers=headers),
    )
    monkeypatch.setattr(manager_module, "Instant", FakeInstant)

    manager = SqliteAuthManager(db_path)
    manager.__enter__()
    return manager, events


def test_manager_guard_methods_raise_before_initialization(tmp_path: Path) -> None:
    """Guard helpers and properties should fail before the manager is entered."""
    manager = SqliteAuthManager(tmp_path / "auth.db")

    with pytest.raises(RuntimeError, match="HTTP client session is not initialized"):
        manager._fetch_oauth_metadata()
    with pytest.raises(RuntimeError, match="SQLite connection is not initialized"):
        manager._connection_check()
    with pytest.raises(RuntimeError, match="HTTP client session is not initialized"):
        manager._session_check()
    with pytest.raises(RuntimeError, match="OAuth metadata is not loaded"):
        manager._oauth_metadata_check()
    with pytest.raises(RuntimeError, match="JWKS client is not initialized"):
        manager._jwks_client_check()
    with pytest.raises(RuntimeError, match="HTTP client session is not initialized"):
        _ = manager.session
    with pytest.raises(RuntimeError, match="OAuth metadata is not loaded"):
        _ = manager.oauth_metadata
    with pytest.raises(RuntimeError, match="JWKS client is not initialized"):
        _ = manager.jwks_client


def test_manager_enter_fetches_and_caches_oauth_metadata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Entering the manager should fetch metadata once and reuse the cache."""
    manager, events = _enter_manager(tmp_path, monkeypatch)
    try:
        assert manager.oauth_metadata.metadata == _metadata_payload()
        assert manager.jwks_client.url == _metadata_payload()["jwks_uri"]
        assert len(events["get_calls"]) == 1
    finally:
        manager.__exit__(None, None, None)

    assert events["closed"] is True

    class FailSession:
        def get(self, url: str, headers: dict[str, str]) -> object:
            raise AssertionError("metadata should have been loaded from cache")

        def close(self) -> None:
            return None

    monkeypatch.setattr(manager_module, "config_http_client", lambda: FailSession())
    monkeypatch.setattr(
        manager_module,
        "PyJWKClient",
        lambda url, headers=None: SimpleNamespace(url=url, headers=headers),
    )

    second = SqliteAuthManager(tmp_path / "auth.db")
    second.__enter__()
    try:
        assert second.oauth_metadata.metadata == _metadata_payload()
    finally:
        second.__exit__(None, None, None)


def test_manager_refreshes_stale_cached_oauth_metadata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Entering the manager should refresh cached metadata when it is stale."""
    db_path = tmp_path / "auth.db"
    conn = create_read_write_connection(db_path, init_sql=load_table_definitions())
    try:
        manager_module.query.write_oauth_metadata(
            conn,
            oauth_metadata=OAuthMetadataTimestamped(
                metadata=_metadata_payload(),
                timestamp=1,
            ),
        )
    finally:
        conn.close()

    manager, events = _enter_manager(tmp_path, monkeypatch, fetched_timestamp=100)
    manager._oauth_metadata_timeout = 10
    try:
        manager._ensure_oauth_metadata()
        assert len(events["get_calls"]) == 1
        assert manager.oauth_metadata.timestamp == 100
    finally:
        manager.__exit__(None, None, None)


def test_manager_ensure_oauth_metadata_raises_when_fetch_returns_none(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Manager should fail if metadata still is not available after refresh."""
    manager = SqliteAuthManager(tmp_path / "auth.db")
    manager._sqlite_connection = create_read_write_connection(
        tmp_path / "auth.db", init_sql=load_table_definitions()
    )
    manager._session = SimpleNamespace(close=lambda: None)
    monkeypatch.setattr(manager, "_fetch_oauth_metadata", lambda: None)
    monkeypatch.setattr(
        manager_module.query, "write_oauth_metadata", lambda *args, **kwargs: None
    )

    try:
        with pytest.raises(RuntimeError, match="Failed to load OAuth metadata"):
            manager._ensure_oauth_metadata()
    finally:
        manager._sqlite_connection.close()


def test_manager_exit_closes_only_initialized_connection(tmp_path: Path) -> None:
    """Manager exit should close the database connection even without a session."""
    manager = SqliteAuthManager(tmp_path / "auth.db")
    events: list[str] = []
    manager._sqlite_connection = SimpleNamespace(close=lambda: events.append("conn"))

    manager.__exit__(None, None, None)

    assert events == ["conn"]


def test_manager_exit_handles_missing_resources(tmp_path: Path) -> None:
    """Manager exit should succeed even when no managed resources were initialized."""
    manager = SqliteAuthManager(tmp_path / "auth.db")

    manager.__exit__(None, None, None)


def test_manager_credential_lifecycle_and_remove_with_revoke(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Manager should add, fetch, list, and remove credentials."""

    class FakeInstant:
        @staticmethod
        def now() -> SimpleNamespace:
            return SimpleNamespace(timestamp=lambda: 1_234)

    manager, _events = _enter_manager(tmp_path, monkeypatch)
    monkeypatch.setattr(manager_module, "Instant", FakeInstant)
    try:
        with pytest.raises(
            ValueError, match="Either cred_id or cred_name must be provided"
        ):
            manager.get_credential()

        app_credential = _make_app_credential()
        expected_cred_id = uuid5(APP_NAMESPACE, app_credential.clientId)
        added = manager.add_credential(app_credential)

        assert added == {expected_cred_id: app_credential.name}
        fetched = manager.get_credential(cred_id=expected_cred_id)
        assert fetched == AuthCredential(
            cred_id=expected_cred_id,
            name=app_credential.name,
            description=app_credential.description,
            clientId=app_credential.clientId,
            clientSecret=app_credential.clientSecret,
            callbackUrl=app_credential.callbackUrl,
            scopes=app_credential.scopes,
            created_at=1_234,
        )
        assert manager.get_credential(cred_name=app_credential.name) == fetched
        assert manager.get_all_credentials() == [fetched]

        with pytest.raises(CredentialNotFoundError):
            manager.get_credential(cred_id=UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"))

        calls: list[tuple[UUID, set[int] | None]] = []
        monkeypatch.setattr(
            manager,
            "revoke_characters",
            lambda cred_id, character_ids=None: (
                calls.append((cred_id, character_ids)) or {}
            ),
        )
        assert manager.remove_credential(expected_cred_id) == {
            expected_cred_id: app_credential.name
        }
        assert calls == []
        with pytest.raises(CredentialNotFoundError):
            manager.remove_credential(expected_cred_id)
    finally:
        manager.__exit__(None, None, None)


def test_manager_get_credential_by_name_and_remove_existing_characters(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Manager should raise for missing credential names and revoke existing characters on remove."""
    manager, _events = _enter_manager(tmp_path, monkeypatch)
    try:
        app_credential = _make_app_credential("named-app")
        expected_cred_id = uuid5(APP_NAMESPACE, app_credential.clientId)
        manager.add_credential(app_credential)
        manager.add_character(
            expected_cred_id,
            _make_authorized_character(cred_id=expected_cred_id, character_id=77),
        )

        with pytest.raises(CredentialNotFoundError):
            manager.get_credential(cred_name="missing-name")

        calls: list[tuple[UUID, set[int] | None]] = []
        monkeypatch.setattr(
            manager,
            "revoke_characters",
            lambda cred_id, character_ids=None: (
                calls.append((cred_id, character_ids)) or {77: "Character 77"}
            ),
        )

        assert manager.remove_credential(expected_cred_id) == {
            expected_cred_id: "named-app"
        }
        assert calls == [(expected_cred_id, {77})]
    finally:
        manager.__exit__(None, None, None)


def test_manager_character_and_revocation_operations(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Manager should add, fetch, revoke, and validate character operations."""
    credential_id = UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")
    manager, _events = _enter_manager(tmp_path, monkeypatch)
    try:
        app_credential = _make_app_credential()
        credential = AuthCredential(
            cred_id=credential_id,
            name=app_credential.name,
            description=app_credential.description,
            clientId=app_credential.clientId,
            clientSecret=app_credential.clientSecret,
            callbackUrl=app_credential.callbackUrl,
            scopes=app_credential.scopes,
            created_at=1_234,
        )
        manager_module.query.write_credentials(
            manager._connection_check(), credentials=credential
        )
        first = _make_authorized_character(cred_id=credential_id, character_id=7)
        second = _make_authorized_character(cred_id=credential_id, character_id=9)

        with pytest.raises(CredentialNotFoundError):
            manager.add_character(UUID("dddddddd-dddd-dddd-dddd-dddddddddddd"), first)

        assert manager.add_character(credential_id, first) == {7: "Character 7"}
        assert manager.add_character(credential_id, second) == {9: "Character 9"}
        assert manager.get_character(credential_id, 7) == first
        assert manager.get_all_characters(credential_id) == [first, second]
        assert manager.get_all_character_ids(credential_id) == {
            7: "Character 7",
            9: "Character 9",
        }

        with pytest.raises(CharacterNotFoundError):
            manager.get_character(credential_id, 404)
        with pytest.raises(CredentialNotFoundError):
            manager.get_all_characters(UUID("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"))

        revoked_calls: list[dict[str, object]] = []
        monkeypatch.setattr(
            manager_module.token_tools,
            "revoke_refresh_token",
            lambda **kwargs: revoked_calls.append(kwargs),
        )
        assert manager.revoke_character(credential_id, 7) == {7: "Character 7"}
        assert revoked_calls[0]["refresh_token"] == first.oauth_token.refresh_token
        with pytest.raises(CharacterNotFoundError):
            manager.revoke_character(credential_id, 7)

        with pytest.raises(CharactersNotFoundError):
            manager.revoke_characters(credential_id, {999})

        assert manager.revoke_characters(credential_id, {9}) == {9: "Character 9"}
        assert len(revoked_calls) == 2
        assert manager.get_all_character_ids(credential_id) == {}
    finally:
        manager.__exit__(None, None, None)


def test_manager_missing_credential_branches_raise_consistently(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Character and refresh operations should raise when the credential is missing."""
    missing_cred_id = UUID("efefefef-efef-efef-efef-efefefefefef")
    manager, _events = _enter_manager(tmp_path, monkeypatch)
    try:
        with pytest.raises(CredentialNotFoundError):
            manager.get_character(missing_cred_id, 1)
        with pytest.raises(CredentialNotFoundError):
            manager.revoke_character(missing_cred_id, 1)
        with pytest.raises(CredentialNotFoundError):
            manager.revoke_characters(missing_cred_id)
        with pytest.raises(CredentialNotFoundError):
            manager.get_all_character_ids(missing_cred_id)
        with pytest.raises(CredentialNotFoundError):
            manager.refresh_character(missing_cred_id, 1)
        with pytest.raises(CredentialNotFoundError):
            manager.refresh_characters(missing_cred_id)
    finally:
        manager.__exit__(None, None, None)


def test_manager_revoke_characters_without_id_filter_revokes_all(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Bulk revoke should revoke all stored characters when no ID filter is provided."""
    credential_id = UUID("34343434-3434-3434-3434-343434343434")
    manager, _events = _enter_manager(tmp_path, monkeypatch)
    try:
        app_credential = _make_app_credential("bulk-revoke-app")
        credential = AuthCredential(
            cred_id=credential_id,
            name=app_credential.name,
            description=app_credential.description,
            clientId=app_credential.clientId,
            clientSecret=app_credential.clientSecret,
            callbackUrl=app_credential.callbackUrl,
            scopes=app_credential.scopes,
            created_at=1_234,
        )
        manager_module.query.write_credentials(
            manager._connection_check(), credentials=credential
        )
        first = _make_authorized_character(cred_id=credential_id, character_id=7)
        second = _make_authorized_character(cred_id=credential_id, character_id=9)
        manager_module.query.write_authorized_character(
            manager._connection_check(), character=first
        )
        manager_module.query.write_authorized_character(
            manager._connection_check(), character=second
        )

        revoked_calls: list[str] = []
        monkeypatch.setattr(
            manager_module.token_tools,
            "revoke_refresh_token",
            lambda **kwargs: revoked_calls.append(kwargs["refresh_token"]),
        )

        assert manager.revoke_characters(credential_id) == {
            7: "Character 7",
            9: "Character 9",
        }
        assert revoked_calls == ["refresh-token-7", "refresh-token-9"]
        assert manager.get_all_character_ids(credential_id) == {}
    finally:
        manager.__exit__(None, None, None)


def test_manager_refresh_operations_update_only_needed_characters(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Manager should refresh expiring characters and leave fresh ones unchanged."""
    credential_id = UUID("ffffffff-ffff-ffff-ffff-ffffffffffff")
    current_timestamp = Instant.now().timestamp()
    manager, _events = _enter_manager(tmp_path, monkeypatch)
    try:
        app_credential = _make_app_credential()
        credential = AuthCredential(
            cred_id=credential_id,
            name=app_credential.name,
            description=app_credential.description,
            clientId=app_credential.clientId,
            clientSecret=app_credential.clientSecret,
            callbackUrl=app_credential.callbackUrl,
            scopes=app_credential.scopes,
            created_at=1_234,
        )
        manager_module.query.write_credentials(
            manager._connection_check(), credentials=credential
        )
        expiring = AuthorizedCharacter(
            character_id=7,
            cred_id=credential_id,
            character_name="Expiring Character",
            expires_at=current_timestamp - 10,
            oauth_token=OauthToken(
                token_data={
                    "access_token": "old-access-token",
                    "refresh_token": "old-refresh-token",
                    "expires_in": 3_600,
                    "token_type": "Bearer",
                }
            ),
        )
        fresh = AuthorizedCharacter(
            character_id=9,
            cred_id=credential_id,
            character_name="Fresh Character",
            expires_at=current_timestamp + 50_000,
            oauth_token=OauthToken(
                token_data={
                    "access_token": "fresh-access-token",
                    "refresh_token": "fresh-refresh-token",
                    "expires_in": 3_600,
                    "token_type": "Bearer",
                }
            ),
        )
        manager_module.query.write_authorized_character(
            manager._connection_check(), character=expiring
        )
        manager_module.query.write_authorized_character(
            manager._connection_check(), character=fresh
        )

        refreshed_token = OauthToken(
            token_data={
                "access_token": "new-access-token",
                "refresh_token": "new-refresh-token",
                "expires_in": 7_200,
                "token_type": "Bearer",
            }
        )
        refreshed_character = AuthorizedCharacter(
            character_id=7,
            cred_id=credential_id,
            character_name="Expiring Character",
            expires_at=current_timestamp + 7_200,
            oauth_token=refreshed_token,
        )
        calls: dict[str, list[dict[str, object]]] = {
            "refresh": [],
            "validate": [],
            "create": [],
        }
        monkeypatch.setattr(
            manager_module.token_tools,
            "refresh_existing_token",
            lambda **kwargs: calls["refresh"].append(kwargs) or refreshed_token,
        )
        monkeypatch.setattr(
            manager_module.token_tools,
            "validate_token",
            lambda **kwargs: (
                calls["validate"].append(kwargs)
                or SimpleNamespace(character_id=7, character_name="Expiring Character")
            ),
        )
        monkeypatch.setattr(
            manager_module.token_tools,
            "create_character_token",
            lambda **kwargs: calls["create"].append(kwargs) or refreshed_character,
        )

        updated = manager.refresh_character(credential_id, 7, min_seconds=300)
        assert updated == refreshed_character
        assert manager.refresh_character(credential_id, 9, min_seconds=300) == fresh
        with pytest.raises(CharacterNotFoundError):
            manager.refresh_character(credential_id, 404, min_seconds=300)

        refreshed_all = manager.refresh_characters(credential_id, min_seconds=300)
        assert refreshed_all == [refreshed_character, fresh]
        assert calls == {
            "refresh": [
                {
                    "session": manager.session,
                    "refresh_token": "old-refresh-token",
                    "client_id": credential.clientId,
                    "oauth_metadata": manager.oauth_metadata,
                }
            ],
            "validate": [
                {
                    "access_token": "new-access-token",
                    "audience": manager_module.AUDIENCE,
                    "jwks_client": manager.jwks_client,
                    "oauth_metadata": manager.oauth_metadata,
                }
            ],
            "create": [
                {
                    "cred_id": credential_id,
                    "oauth_token": refreshed_token,
                    "validated_token": SimpleNamespace(
                        character_id=7, character_name="Expiring Character"
                    ),
                }
            ],
        }
        assert manager.get_character(credential_id, 7) == refreshed_character

        with pytest.raises(CharactersNotFoundError):
            manager.refresh_characters(credential_id, {999}, min_seconds=300)
    finally:
        manager.__exit__(None, None, None)


def test_manager_refresh_characters_subset_refreshes_only_selected_expiring_rows(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Bulk refresh should filter to requested IDs and refresh only expiring matches."""
    credential_id = UUID("cdcdcdcd-cdcd-cdcd-cdcd-cdcdcdcdcdcd")
    current_timestamp = Instant.now().timestamp()
    manager, _events = _enter_manager(tmp_path, monkeypatch)
    try:
        app_credential = _make_app_credential("subset-app")
        credential = AuthCredential(
            cred_id=credential_id,
            name=app_credential.name,
            description=app_credential.description,
            clientId=app_credential.clientId,
            clientSecret=app_credential.clientSecret,
            callbackUrl=app_credential.callbackUrl,
            scopes=app_credential.scopes,
            created_at=1_234,
        )
        manager_module.query.write_credentials(
            manager._connection_check(), credentials=credential
        )
        expiring = AuthorizedCharacter(
            character_id=7,
            cred_id=credential_id,
            character_name="Expiring Character",
            expires_at=current_timestamp - 1,
            oauth_token=OauthToken(
                token_data={
                    "access_token": "old-access-token",
                    "refresh_token": "old-refresh-token",
                    "expires_in": 3_600,
                    "token_type": "Bearer",
                }
            ),
        )
        other = AuthorizedCharacter(
            character_id=9,
            cred_id=credential_id,
            character_name="Other Character",
            expires_at=current_timestamp - 1,
            oauth_token=OauthToken(
                token_data={
                    "access_token": "other-access-token",
                    "refresh_token": "other-refresh-token",
                    "expires_in": 3_600,
                    "token_type": "Bearer",
                }
            ),
        )
        manager_module.query.write_authorized_character(
            manager._connection_check(), character=expiring
        )
        manager_module.query.write_authorized_character(
            manager._connection_check(), character=other
        )

        refreshed_token = OauthToken(
            token_data={
                "access_token": "new-access-token",
                "refresh_token": "new-refresh-token",
                "expires_in": 7_200,
                "token_type": "Bearer",
            }
        )
        refreshed_character = AuthorizedCharacter(
            character_id=7,
            cred_id=credential_id,
            character_name="Expiring Character",
            expires_at=current_timestamp + 7_200,
            oauth_token=refreshed_token,
        )
        calls: dict[str, list[dict[str, object]]] = {
            "refresh": [],
            "validate": [],
            "create": [],
        }
        monkeypatch.setattr(
            manager_module.token_tools,
            "refresh_existing_token",
            lambda **kwargs: calls["refresh"].append(kwargs) or refreshed_token,
        )
        monkeypatch.setattr(
            manager_module.token_tools,
            "validate_token",
            lambda **kwargs: (
                calls["validate"].append(kwargs)
                or SimpleNamespace(character_id=7, character_name="Expiring Character")
            ),
        )
        monkeypatch.setattr(
            manager_module.token_tools,
            "create_character_token",
            lambda **kwargs: calls["create"].append(kwargs) or refreshed_character,
        )

        result = manager.refresh_characters(credential_id, {7}, min_seconds=300)

        assert result == [refreshed_character]
        assert calls["refresh"][0]["refresh_token"] == "old-refresh-token"
        assert manager.get_character(credential_id, 7) == refreshed_character
        assert manager.get_character(credential_id, 9) == other
    finally:
        manager.__exit__(None, None, None)
