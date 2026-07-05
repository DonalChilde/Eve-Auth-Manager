"""Tests for the SQLite-backed auth manager."""

from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest
from whenever import Instant

import eve_auth_manager.sqlite.manager as manager_module
from eve_auth_manager.models import (
    AuthCredential,
    AuthorizedCharacter,
    EsiAppCredential,
    OAuthMetadataTimestamped,
    OauthToken,
)
from eve_auth_manager.protocols import (
    CharacterNotFoundError,
    CharactersNotFoundError,
    CredentialNotFoundError,
)
from eve_auth_manager.sqlite.connection_helpers import create_read_write_connection
from eve_auth_manager.sqlite.manager import SqliteAuthManager


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


def test_manager_credential_lifecycle_and_remove_with_revoke(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Manager should add, fetch, list, and remove credentials."""
    fixed_uuid = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

    class FakeInstant:
        @staticmethod
        def now() -> SimpleNamespace:
            return SimpleNamespace(timestamp=lambda: 1_234)

    manager, _events = _enter_manager(tmp_path, monkeypatch)
    monkeypatch.setattr(manager_module, "uuid4", lambda: fixed_uuid)
    monkeypatch.setattr(manager_module, "Instant", FakeInstant)
    try:
        with pytest.raises(
            ValueError, match="Either cred_id or cred_name must be provided"
        ):
            manager.get_credential()

        app_credential = _make_app_credential()
        added = manager.add_credential(app_credential)

        assert added == {fixed_uuid: app_credential.name}
        fetched = manager.get_credential(cred_id=fixed_uuid)
        assert fetched == AuthCredential(
            cred_id=fixed_uuid,
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
        assert manager.remove_credential(fixed_uuid) == {
            fixed_uuid: app_credential.name
        }
        assert calls == []
        with pytest.raises(CredentialNotFoundError):
            manager.remove_credential(fixed_uuid)
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
