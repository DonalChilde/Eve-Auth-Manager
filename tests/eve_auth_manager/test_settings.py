"""Tests for normalized settings helpers and defaults."""

from pathlib import Path

import eve_auth_manager.settings as settings_module
from eve_auth_manager.settings import EveAuthManagerSettings


def test_pydantic_settings_logging_directory_uses_database_parent() -> None:
    """Logging directory should live beside the configured auth database."""
    settings = settings_module.EveAuthManagerSettingsPydantic(
        auth_db_path=Path("/tmp/eve-auth/auth.db")
    )

    assert settings.logging_directory == Path("/tmp/eve-auth/logs")


def test_get_settings_builds_normalized_settings_from_default_pydantic(
    monkeypatch,
) -> None:
    """get_settings should create and normalize the default Pydantic settings."""

    class FakePydanticSettings:
        def __init__(self) -> None:
            self.auth_db_path = Path("/tmp/eve-auth/auth.db")
            self.logging_directory = Path("/tmp/eve-auth/logs")

    monkeypatch.setattr(
        settings_module,
        "EveAuthManagerSettingsPydantic",
        FakePydanticSettings,
    )

    result = settings_module.get_settings()

    assert result == EveAuthManagerSettings(
        auth_db_path=Path("/tmp/eve-auth/auth.db"),
        logging_directory=Path("/tmp/eve-auth/logs"),
    )
