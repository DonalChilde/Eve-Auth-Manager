"""Tests for shared CLI helper functions."""

from pathlib import Path
from types import SimpleNamespace

import pytest

import eve_auth_manager.cli.helpers as cli_helpers
from eve_auth_manager.cli.helpers import (
    get_auth_manager_settings_from_context,
    get_stdin,
)
from eve_auth_manager.settings import EveAuthManagerSettings


def test_get_auth_manager_settings_from_context_returns_stored_settings() -> None:
    """Context helper should return the stored settings object unchanged."""
    settings = EveAuthManagerSettings(
        application_directory=Path("/tmp"),
        authorization_database_path=Path("/tmp/auth.db"),
        logging_directory=Path("/tmp/logs"),
    )
    ctx = SimpleNamespace(obj={"eve-auth-manager-settings": settings})

    result = get_auth_manager_settings_from_context(ctx)  # type: ignore[arg-type]

    assert result is settings


@pytest.mark.parametrize("obj", [None, {}, {"other-key": object()}])
def test_get_auth_manager_settings_from_context_requires_expected_key(
    obj: object,
) -> None:
    """Context helper should fail when settings are missing from context.obj."""
    ctx = SimpleNamespace(obj=obj)

    with pytest.raises(ValueError, match="Auth Manager settings not found"):
        get_auth_manager_settings_from_context(ctx)  # type: ignore[arg-type]


def test_get_stdin_returns_redirected_input(monkeypatch: pytest.MonkeyPatch) -> None:
    """stdin helper should read piped input when stdin is non-interactive."""

    class FakeStdin:
        def isatty(self) -> bool:
            return False

        def read(self) -> str:
            return '{"hello": "world"}'

    monkeypatch.setattr(cli_helpers.sys, "stdin", FakeStdin())

    assert get_stdin() == '{"hello": "world"}'


def test_get_stdin_rejects_interactive_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """stdin helper should fail when called without piped or redirected input."""

    class FakeStdin:
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr(cli_helpers.sys, "stdin", FakeStdin())

    with pytest.raises(ValueError, match="provide a file path or pipe data via stdin"):
        get_stdin()
