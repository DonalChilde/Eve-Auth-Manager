"""Tests for the reset CLI command."""

from pathlib import Path
from types import SimpleNamespace

import pytest
import typer

import eve_auth_manager.cli.util.reset as reset_module
from eve_auth_manager.cli.util.reset import reset_database
from eve_auth_manager.settings import EveAuthManagerSettings


def _make_context(tmp_path: Path) -> SimpleNamespace:
    """Build a minimal context object with configured settings."""
    settings = EveAuthManagerSettings(
        application_directory=tmp_path,
        authorization_database_path=tmp_path / "auth.db",
        logging_directory=tmp_path / "logs",
    )
    return SimpleNamespace(obj={"eve-auth-manager-settings": settings})


def test_reset_database_rejects_quiet_without_force() -> None:
    """Quiet mode should require force mode before any destructive action."""
    ctx = SimpleNamespace(obj=None)

    with pytest.raises(typer.BadParameter, match="Cannot use --quiet without --force"):
        reset_database(ctx, force=False, quiet=True)  # type: ignore[arg-type]


def test_reset_database_force_recreates_database(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Forced reset should delete and recreate the database without prompting."""
    ctx = _make_context(tmp_path)
    events: list[str] = []

    class FakeManager:
        def __enter__(self) -> "FakeManager":
            events.append("enter")
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            events.append("exit")

        def get_all_credentials(self) -> list[object]:
            events.append("get_all_credentials")
            return []

    monkeypatch.setattr(reset_module, "SqliteAuthManager", lambda path: FakeManager())

    with pytest.raises(typer.Exit):
        reset_database(ctx, force=True, quiet=True)  # type: ignore[arg-type]

    assert events == ["enter", "get_all_credentials", "exit"]


def test_reset_database_aborts_when_confirmation_declined(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Prompted reset should exit cleanly without deleting when declined."""
    ctx = _make_context(tmp_path)
    db_path = tmp_path / "auth.db"
    db_path.write_text("placeholder", encoding="utf-8")

    monkeypatch.setattr(reset_module.typer, "confirm", lambda *args, **kwargs: False)

    with pytest.raises(typer.Exit) as exc_info:
        reset_database(ctx, force=False, quiet=False)  # type: ignore[arg-type]

    assert exc_info.value.exit_code in (None, 0)
    assert db_path.exists()


def test_reset_database_recreates_database_after_confirmation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Prompted reset should delete and recreate the database after confirmation."""
    ctx = _make_context(tmp_path)
    db_path = tmp_path / "auth.db"
    db_path.write_text("placeholder", encoding="utf-8")
    events: list[str] = []

    class FakeManager:
        def __enter__(self) -> "FakeManager":
            events.append("enter")
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            events.append("exit")

        def get_all_credentials(self) -> list[object]:
            events.append("get_all_credentials")
            return []

    monkeypatch.setattr(reset_module.typer, "confirm", lambda *args, **kwargs: True)
    monkeypatch.setattr(reset_module, "SqliteAuthManager", lambda path: FakeManager())

    with pytest.raises(typer.Exit) as exc_info:
        reset_database(ctx, force=False, quiet=False)  # type: ignore[arg-type]

    assert exc_info.value.exit_code in (None, 0)
    assert events == ["enter", "get_all_credentials", "exit"]
    assert not db_path.exists()
