"""Tests for the version CLI command."""

from types import SimpleNamespace

from pytest import MonkeyPatch

import eve_auth_manager.cli.version as version_module
from eve_auth_manager.cli.version import version


def test_version_runs_and_includes_project_url(monkeypatch: MonkeyPatch) -> None:
    """Version command should run and print core metadata lines."""
    messages: list[str] = []

    monkeypatch.setattr(
        version_module.typer, "echo", lambda message: messages.append(message)
    )
    monkeypatch.setattr(
        version_module,
        "get_auth_manager_settings_from_context",
        lambda ctx: SimpleNamespace(application_directory="/tmp/app"),
    )

    version(SimpleNamespace(obj={}))

    assert any(
        message.startswith(f"{version_module.__app_name__} version ")
        for message in messages
    )
    assert any("Project URL:" in message for message in messages)
    assert any("Application settings:" in message for message in messages)
