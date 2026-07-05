"""Tests for the characters refresh CLI command."""

from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest
import typer

import eve_auth_manager.cli.characters.refresh as refresh_module
from eve_auth_manager.cli.characters.refresh import refresh
from eve_auth_manager.models import AuthorizedCharacter, OauthToken
from eve_auth_manager.settings import EveAuthManagerSettings


def _make_context(tmp_path: Path) -> SimpleNamespace:
    """Build a minimal context object with configured settings."""
    settings = EveAuthManagerSettings(
        auth_db_path=tmp_path / "auth.db",
        logging_directory=tmp_path / "logs",
    )
    return SimpleNamespace(obj={"eve-auth-manager-settings": settings})


def _make_character(*, cred_id: UUID, character_id: int) -> AuthorizedCharacter:
    """Create a mocked authorized character value."""
    return AuthorizedCharacter(
        character_id=character_id,
        cred_id=cred_id,
        character_name=f"Character {character_id}",
        expires_at=4_600,
        oauth_token=OauthToken(
            token_data={
                "access_token": "access-token",
                "refresh_token": "refresh-token",
                "expires_in": 3_600,
                "token_type": "Bearer",
            }
        ),
    )


def test_refresh_requires_credential_selector(tmp_path: Path) -> None:
    """Refresh should require either a credential ID or credential name."""
    ctx = _make_context(tmp_path)

    with pytest.raises(typer.Exit) as exc_info:
        refresh(ctx, quiet=True)  # type: ignore[arg-type]

    assert exc_info.value.exit_code == 1


def test_refresh_single_character_delegates_to_refresh_character(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Refresh should call the single-character refresh path when an ID is given."""
    ctx = _make_context(tmp_path)
    cred_id = UUID("44444444-4444-4444-4444-444444444444")
    calls: dict[str, object] = {}

    class FakeManager:
        def __enter__(self) -> "FakeManager":
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        def get_credential(
            self, *, cred_id: UUID | None = None, cred_name: str | None = None
        ) -> object:
            calls["get_credential"] = {"cred_id": cred_id, "cred_name": cred_name}
            return SimpleNamespace(cred_id=cred_id)

        def refresh_character(
            self,
            credential_id: UUID,
            character_id: int,
            *,
            min_seconds: int,
        ) -> AuthorizedCharacter:
            calls["refresh_character"] = {
                "cred_id": credential_id,
                "character_id": character_id,
                "min_seconds": min_seconds,
            }
            return _make_character(cred_id=credential_id, character_id=character_id)

    monkeypatch.setattr(refresh_module, "SqliteAuthManager", lambda path: FakeManager())

    refresh(
        ctx,
        cred_id=cred_id,
        character_id=55,
        min_seconds=180,
        quiet=True,
    )  # type: ignore[arg-type]

    assert calls["get_credential"] == {"cred_id": cred_id, "cred_name": None}
    assert calls["refresh_character"] == {
        "cred_id": cred_id,
        "character_id": 55,
        "min_seconds": 180,
    }


def test_refresh_all_characters_exits_cleanly_when_none_found(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Refresh should exit successfully when no characters exist for the credential."""
    ctx = _make_context(tmp_path)
    resolved_cred_id = UUID("55555555-5555-5555-5555-555555555555")
    calls: dict[str, object] = {}

    class FakeManager:
        def __enter__(self) -> "FakeManager":
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        def get_credential(
            self, *, cred_id: UUID | None = None, cred_name: str | None = None
        ) -> object:
            calls["get_credential"] = {"cred_id": cred_id, "cred_name": cred_name}
            return SimpleNamespace(cred_id=cred_id or resolved_cred_id)

        def refresh_characters(
            self,
            credential_id: UUID,
            *,
            character_ids: object,
            min_seconds: int,
        ) -> list[AuthorizedCharacter]:
            calls["refresh_characters"] = {
                "cred_id": credential_id,
                "character_ids": character_ids,
                "min_seconds": min_seconds,
            }
            return []

    monkeypatch.setattr(refresh_module, "SqliteAuthManager", lambda path: FakeManager())

    with pytest.raises(typer.Exit) as exc_info:
        refresh(ctx, cred_name="main", quiet=True)  # type: ignore[arg-type]

    assert exc_info.value.exit_code == 0
    assert calls["get_credential"] == {"cred_id": None, "cred_name": "main"}
    assert calls["refresh_characters"] == {
        "cred_id": resolved_cred_id,
        "character_ids": None,
        "min_seconds": 300,
    }
