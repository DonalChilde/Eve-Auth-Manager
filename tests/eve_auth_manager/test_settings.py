"""Tests for normalized settings helpers and defaults."""

from pathlib import Path

import eve_auth_manager.settings as settings_module
from eve_auth_manager.settings import EveAuthManagerSettings


def test_pydantic_settings_uses_provided_application_directory() -> None:
    """Pydantic settings should preserve an explicitly provided app directory."""
    settings = settings_module.EveAuthManagerSettingsPydantic(
        application_directory=Path("/tmp/eve-auth")
    )

    assert settings.application_directory == Path("/tmp/eve-auth")


def test_get_settings_builds_normalized_settings_from_default_pydantic(
    monkeypatch,
) -> None:
    """get_settings should create and normalize the default Pydantic settings."""

    class FakePydanticSettings:
        def __init__(self) -> None:
            self.application_directory = Path("/tmp/eve-auth")

    monkeypatch.setattr(
        settings_module,
        "EveAuthManagerSettingsPydantic",
        FakePydanticSettings,
    )

    result = settings_module.get_settings()

    assert result == EveAuthManagerSettings(
        application_directory=Path("/tmp/eve-auth"),
        authorization_database_path=Path("/tmp/eve-auth/eve_auth_manager.sqlite"),
        logging_directory=Path("/tmp/eve-auth/logs"),
    )
