"""Tests for character display markdown generation."""

import re
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest
import typer

import eve_auth_manager.cli.characters.display as display_module
from eve_auth_manager.cli.characters.display import (
    detailed_display,
    display,
    display_characters_summary,
)
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
    """Create an authorized character fixture for display tests."""
    return AuthorizedCharacter(
        character_id=character_id,
        cred_id=cred_id,
        character_name=f"Character {character_id}",
        expires_at=4_600,
        oauth_token=OauthToken(
            token_data={
                "access_token": f"access-token-{character_id}",
                "refresh_token": f"refresh-token-{character_id}",
                "expires_in": 3_600,
                "token_type": "Bearer",
            }
        ),
    )


def test_detailed_display_includes_all_character_fields() -> None:
    """Detailed display should include stored and computed character data."""
    character = AuthorizedCharacter(
        character_id=42,
        cred_id=UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        character_name="Jane Capsuleer",
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

    output = detailed_display(character)

    assert "# Character Details" in output
    assert "character_id" in output
    assert "42" in output
    assert "cred_id" in output
    assert "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" in output
    assert "character_name" in output
    assert "Jane Capsuleer" in output
    assert "expires_at" in output
    assert "4600" in output
    assert "oauth_token" in output
    assert "OauthToken(token_data={'access_token': 'access-token'" in output
    assert "expires_in" in output
    assert re.search(r"\|\s*expires_in\s*\|\s*-?\d+\s*\|", output)


def test_character_summary_lists_requested_columns() -> None:
    """Summary display should list identity, credential, and expiration data."""
    first = AuthorizedCharacter(
        character_id=42,
        cred_id=UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        character_name="Jane Capsuleer",
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
    second = AuthorizedCharacter(
        character_id=84,
        cred_id=UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
        character_name="John Capsuleer",
        expires_at=8_200,
        oauth_token=OauthToken(
            token_data={
                "access_token": "other-access-token",
                "refresh_token": "other-refresh-token",
                "expires_in": 7_200,
                "token_type": "Bearer",
            }
        ),
    )

    output = display_characters_summary([first, second])

    assert "# Characters Summary" in output
    assert "character_id" in output
    assert "character_name" in output
    assert "cred_id" in output
    assert "expires_in" in output
    assert "42" in output
    assert "Jane Capsuleer" in output
    assert "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" in output
    assert "84" in output
    assert "John Capsuleer" in output
    assert "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb" in output
    assert re.search(
        r"\|\s*42\s*\|\s*Jane Capsuleer\s*\|\s*aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\s*\|\s*-?\d+\s*\|",
        output,
    )
    assert re.search(
        r"\|\s*84\s*\|\s*John Capsuleer\s*\|\s*bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb\s*\|\s*-?\d+\s*\|",
        output,
    )


def test_display_requires_credential_selector(tmp_path: Path) -> None:
    """Display should require either a credential ID or credential name."""
    ctx = _make_context(tmp_path)

    with pytest.raises(typer.Exit) as exc_info:
        display(ctx, quiet=True)  # type: ignore[arg-type]

    assert exc_info.value.exit_code == 1


def test_display_exits_cleanly_when_no_characters_found(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Display should exit successfully when no characters exist for a credential."""
    ctx = _make_context(tmp_path)
    resolved_cred_id = UUID("12121212-1212-1212-1212-121212121212")

    class FakeManager:
        def __enter__(self) -> "FakeManager":
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        def get_credential(
            self, *, cred_id: UUID | None = None, cred_name: str | None = None
        ) -> object:
            return SimpleNamespace(cred_id=cred_id or resolved_cred_id)

        def get_all_characters(self, credential_id: UUID) -> list[AuthorizedCharacter]:
            assert credential_id == resolved_cred_id
            return []

    monkeypatch.setattr(display_module, "SqliteAuthManager", lambda path: FakeManager())

    with pytest.raises(typer.Exit) as exc_info:
        display(ctx, cred_name="main", quiet=True)  # type: ignore[arg-type]

    assert exc_info.value.exit_code == 0


def test_display_prints_plain_detailed_markdown_to_stdout(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Display should print plain markdown for a detailed single-character view."""
    ctx = _make_context(tmp_path)
    cred_id = UUID("13131313-1313-1313-1313-131313131313")
    character = _make_character(cred_id=cred_id, character_id=42)

    class FakeManager:
        def __enter__(self) -> "FakeManager":
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        def get_credential(
            self, *, cred_id: UUID | None = None, cred_name: str | None = None
        ) -> object:
            return SimpleNamespace(cred_id=cred_id)

        def get_character(
            self, credential_id: UUID, character_id: int
        ) -> AuthorizedCharacter:
            assert credential_id == cred_id
            assert character_id == 42
            return character

    monkeypatch.setattr(display_module, "SqliteAuthManager", lambda path: FakeManager())
    monkeypatch.setattr(
        display_module,
        "detailed_display",
        lambda requested_character: "# Character Detail\n\nbody",
    )

    display(ctx, cred_id=cred_id, character_id=42, plain=True, quiet=True)  # type: ignore[arg-type]

    assert capsys.readouterr().out == "# Character Detail\n\nbody\n"


def test_display_writes_summary_markdown_to_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Display should write summary markdown to a requested file path."""
    ctx = _make_context(tmp_path)
    resolved_cred_id = UUID("14141414-1414-1414-1414-141414141414")
    characters = [
        _make_character(cred_id=resolved_cred_id, character_id=7),
        _make_character(cred_id=resolved_cred_id, character_id=9),
    ]
    output_path = tmp_path / "characters.md"

    class FakeManager:
        def __enter__(self) -> "FakeManager":
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        def get_credential(
            self, *, cred_id: UUID | None = None, cred_name: str | None = None
        ) -> object:
            return SimpleNamespace(cred_id=cred_id or resolved_cred_id)

        def get_all_characters(self, credential_id: UUID) -> list[AuthorizedCharacter]:
            assert credential_id == resolved_cred_id
            return characters

    monkeypatch.setattr(display_module, "SqliteAuthManager", lambda path: FakeManager())
    monkeypatch.setattr(
        display_module,
        "display_characters_summary",
        lambda requested_characters: "# Characters Summary\n\ncontent",
    )

    display(  # type: ignore[arg-type]
        ctx,
        cred_name="main",
        file_path=output_path,
        overwrite=True,
        quiet=True,
    )

    assert output_path.read_text(encoding="utf-8") == "# Characters Summary\n\ncontent"
