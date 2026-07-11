"""Tests for the standalone main Typer entrypoint."""

from pathlib import Path
from types import SimpleNamespace

from typer.testing import CliRunner

import eve_auth_manager.cli.main_typer as main_typer
from eve_auth_manager.settings import EveAuthManagerSettings


def test_default_options_initializes_context_and_logging(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """Default callback should store settings and initialize logging."""
    settings = EveAuthManagerSettings(
        application_directory=tmp_path,
        authorization_database_path=tmp_path / "auth.db",
        logging_directory=tmp_path / "logs",
    )
    ctx = SimpleNamespace(obj=None)
    calls: dict[str, object] = {}

    monkeypatch.setattr(main_typer, "get_settings", lambda: settings)
    monkeypatch.setattr(
        main_typer,
        "setup_logging",
        lambda *, log_dir: calls.__setitem__("log_dir", log_dir),
    )
    monkeypatch.setattr(
        main_typer.logger,
        "info",
        lambda message: calls.__setitem__("message", message),
    )

    main_typer.default_options(ctx)  # type: ignore[arg-type]

    assert ctx.obj == {"eve-auth-manager-settings": settings}
    assert calls["log_dir"] == settings.logging_directory
    assert "Starting" in str(calls["message"])
    assert "with settings:" in str(calls["message"])


def test_main_app_help_lists_top_level_command_groups(
    monkeypatch, tmp_path: Path
) -> None:
    """Top-level help should expose the standalone command groups."""
    settings = EveAuthManagerSettings(
        application_directory=tmp_path,
        authorization_database_path=tmp_path / "auth.db",
        logging_directory=tmp_path / "logs",
    )
    runner = CliRunner()

    monkeypatch.setattr(main_typer, "get_settings", lambda: settings)
    monkeypatch.setattr(main_typer, "setup_logging", lambda *, log_dir: None)
    monkeypatch.setattr(main_typer.logger, "info", lambda message: None)

    result = runner.invoke(main_typer.app, ["--help"])

    assert result.exit_code == 0
    assert "authorize" in result.stdout
    assert "credentials" in result.stdout
    assert "characters" in result.stdout
    assert "util" in result.stdout
