"""Tests for the version CLI command."""

import eve_auth_manager.cli.version as version_module
from eve_auth_manager.cli.version import version


def test_version_prints_app_version_and_project_url(monkeypatch) -> None:
    """Version command should print the app version and project URL."""
    messages: list[str] = []

    monkeypatch.setattr(
        version_module.typer, "echo", lambda message: messages.append(message)
    )

    version()

    assert messages == [
        f"{version_module.__app_name__} version {version_module.__version__}",
        f"Project URL: {version_module.__url__}",
    ]
