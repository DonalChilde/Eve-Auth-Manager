"""Tests for the authorize CLI command."""

import json
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest
import typer

import pfmsoft.eve_auth_manager.cli.authorize as authorize_module
from pfmsoft.eve_auth_manager.cli.authorize import authorize
from pfmsoft.eve_auth_manager.models import AuthorizedCharacter, OauthToken
from pfmsoft.eve_auth_manager.settings import SETTINGS_KEY, EveAuthManagerSettings


def _make_context(tmp_path: Path) -> SimpleNamespace:
    """Build a minimal Typer context replacement with configured settings."""
    settings = EveAuthManagerSettings(
        application_directory=tmp_path,
        authorization_database_path=tmp_path / "auth.db",
        logging_directory=tmp_path / "logs",
    )
    return SimpleNamespace(obj={SETTINGS_KEY: settings})


def _make_character(*, cred_id: UUID, character_id: int) -> AuthorizedCharacter:
    """Create an authorized character fixture for mocked auth manager calls."""
    return AuthorizedCharacter(
        character_id=character_id,
        cred_id=cred_id,
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


def test_authorize_requires_credential_selector(tmp_path: Path) -> None:
    """Authorize should require either a credential ID or credential name."""
    ctx = _make_context(tmp_path)

    with pytest.raises(typer.BadParameter, match="Either --cred-id or --cred-name"):
        authorize(ctx, character_id=42, quiet=True)  # type: ignore[arg-type]


def test_authorize_prints_authorized_json_to_stdout(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Authorize should emit the authorized payload to stdout by default."""
    ctx = _make_context(tmp_path)
    resolved_cred_id = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    calls: dict[str, object] = {}

    class FakeManager:
        def __enter__(self) -> "FakeManager":
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        def get_credential(
            self, *, cred_id: UUID | None, cred_name: str | None
        ) -> object:
            calls["get_credential"] = {"cred_id": cred_id, "cred_name": cred_name}
            return SimpleNamespace(cred_id=resolved_cred_id)

        def refresh_character(
            self,
            *,
            cred_id: UUID,
            character_id: int,
            min_seconds: int,
        ) -> AuthorizedCharacter:
            calls["refresh_character"] = {
                "cred_id": cred_id,
                "character_id": character_id,
                "min_seconds": min_seconds,
            }
            return _make_character(cred_id=cred_id, character_id=character_id)

    monkeypatch.setattr(
        authorize_module, "SqliteAuthManager", lambda path: FakeManager()
    )

    authorize(
        ctx,
        cred_name="main-credential",
        character_id=42,
        min_seconds=120,
        quiet=True,
    )  # type: ignore[arg-type]

    payload = json.loads(capsys.readouterr().out)

    assert calls["get_credential"] == {
        "cred_id": None,
        "cred_name": "main-credential",
    }
    assert calls["refresh_character"] == {
        "cred_id": resolved_cred_id,
        "character_id": 42,
        "min_seconds": 120,
    }
    assert payload == {
        "cred_id": str(resolved_cred_id),
        "character_id": 42,
        "character_name": "Jane Capsuleer",
        "access_token": "access-token",
        "expires_at": 4600,
    }


def test_authorize_reads_json_from_stdin_when_requested(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Authorize should parse JSON from stdin when --from - is used."""
    ctx = _make_context(tmp_path)
    cred_id = UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    calls: dict[str, object] = {}

    class FakeManager:
        def __enter__(self) -> "FakeManager":
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        def get_credential(
            self, *, cred_id: UUID | None, cred_name: str | None
        ) -> object:
            calls["get_credential"] = {"cred_id": cred_id, "cred_name": cred_name}
            return SimpleNamespace(cred_id=cred_id)

        def refresh_character(
            self,
            *,
            cred_id: UUID,
            character_id: int,
            min_seconds: int,
        ) -> AuthorizedCharacter:
            calls["refresh_character"] = {
                "cred_id": cred_id,
                "character_id": character_id,
                "min_seconds": min_seconds,
            }
            return _make_character(cred_id=cred_id, character_id=character_id)

    monkeypatch.setattr(
        authorize_module, "SqliteAuthManager", lambda path: FakeManager()
    )
    monkeypatch.setattr(
        authorize_module,
        "get_stdin",
        lambda: '{"cred_name": "stdin-credential", "ignored": true}',
    )

    authorize(
        ctx,
        json_args=Path("-"),
        cred_id=cred_id,
        character_id=84,
        min_seconds=180,
        quiet=True,
    )  # type: ignore[arg-type]

    payload = json.loads(capsys.readouterr().out)

    assert calls["get_credential"] == {"cred_id": cred_id, "cred_name": None}
    assert calls["refresh_character"] == {
        "cred_id": cred_id,
        "character_id": 84,
        "min_seconds": 180,
    }
    assert payload["cred_id"] == str(cred_id)
    assert payload["character_id"] == 84


def test_authorize_writes_authorized_json_to_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Authorize should write the payload to the requested file path."""
    ctx = _make_context(tmp_path)
    cred_id = UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")
    input_path = tmp_path / "authorize-args.json"
    input_path.write_text(
        json.dumps({"cred_name": "file-credential", "character_id": 7}),
        encoding="utf-8",
    )
    output_path = tmp_path / "authorized.json"
    calls: dict[str, object] = {}

    class FakeManager:
        def __enter__(self) -> "FakeManager":
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        def get_credential(
            self, *, cred_id: UUID | None, cred_name: str | None
        ) -> object:
            calls["get_credential"] = {"cred_id": cred_id, "cred_name": cred_name}
            return SimpleNamespace(cred_id=cred_id)

        def refresh_character(
            self,
            *,
            cred_id: UUID,
            character_id: int,
            min_seconds: int,
        ) -> AuthorizedCharacter:
            calls["refresh_character"] = {
                "cred_id": cred_id,
                "character_id": character_id,
                "min_seconds": min_seconds,
            }
            return _make_character(cred_id=cred_id, character_id=character_id)

    monkeypatch.setattr(
        authorize_module, "SqliteAuthManager", lambda path: FakeManager()
    )

    authorize(
        ctx,
        json_args=input_path,
        file_out=output_path,
        cred_id=cred_id,
        character_id=7,
        min_seconds=240,
        overwrite=True,
        quiet=True,
    )  # type: ignore[arg-type]

    payload = json.loads(output_path.read_text(encoding="utf-8"))

    assert calls["get_credential"] == {"cred_id": cred_id, "cred_name": None}
    assert calls["refresh_character"] == {
        "cred_id": cred_id,
        "character_id": 7,
        "min_seconds": 240,
    }
    assert payload == {
        "cred_id": str(cred_id),
        "character_id": 7,
        "character_name": "Jane Capsuleer",
        "access_token": "access-token",
        "expires_at": 4600,
    }


def test_authorize_reports_saved_output_path_when_not_quiet(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Authorize should print the saved file path when writing output."""
    ctx = _make_context(tmp_path)
    cred_id = UUID("dddddddd-dddd-dddd-dddd-dddddddddddd")
    output_path = tmp_path / "authorized.json"
    printed: list[object] = []
    console_kwargs: list[dict[str, object]] = []

    class FakeConsole:
        def __init__(self, **kwargs: object) -> None:
            console_kwargs.append(dict(kwargs))

        def print(self, message: object) -> None:
            printed.append(message)

    class FakeManager:
        def __enter__(self) -> "FakeManager":
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        def get_credential(
            self, *, cred_id: UUID | None, cred_name: str | None
        ) -> object:
            return SimpleNamespace(cred_id=cred_id)

        def refresh_character(
            self,
            *,
            cred_id: UUID,
            character_id: int,
            min_seconds: int,
        ) -> AuthorizedCharacter:
            return _make_character(cred_id=cred_id, character_id=character_id)

    monkeypatch.setattr(authorize_module, "Console", FakeConsole)
    monkeypatch.setattr(
        authorize_module, "SqliteAuthManager", lambda path: FakeManager()
    )

    authorize(
        ctx,
        cred_id=cred_id,
        character_id=9,
        file_out=output_path,
        overwrite=True,
        quiet=False,
    )  # type: ignore[arg-type]

    assert console_kwargs == [{"stderr": True}]
    assert printed == [f"AuthorizedDict saved to {output_path}"]
