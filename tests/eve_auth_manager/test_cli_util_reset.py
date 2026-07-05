"""Tests for the reset CLI command."""

from pathlib import Path
from types import SimpleNamespace

import pytest
import typer

import eve_auth_manager.cli.util.reset as reset_module
from eve_auth_manager.cli.util.reset import reset_database
from eve_auth_manager.settings import EveAuthManagerSettings


def test_reset_database_rejects_quiet_without_force() -> None:
    """Quiet mode should require force mode before any destructive action."""
    ctx = SimpleNamespace(obj=None)

    with pytest.raises(typer.BadParameter, match="Cannot use --quiet without --force"):
        reset_database(ctx, force=False, quiet=True)  # type: ignore[arg-type]


def test_reset_database_force_recreates_database(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Forced reset should delete and recreate the database without prompting."""
    db_path = tmp_path / "auth.db"
    settings = EveAuthManagerSettings(
        auth_db_path=db_path,
        logging_directory=tmp_path / "logs",
    )
    ctx = SimpleNamespace(obj={"eve-auth-manager-settings": settings})
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
