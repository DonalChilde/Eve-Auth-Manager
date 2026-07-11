"""Tests for the credentials remove CLI command."""

from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest

import eve_auth_manager.cli.credentials.remove as remove_module
from eve_auth_manager.cli.credentials.remove import remove_credential
from eve_auth_manager.settings import EveAuthManagerSettings


def _make_context(tmp_path: Path) -> SimpleNamespace:
    """Build a minimal context object with configured settings."""
    settings = EveAuthManagerSettings(
        application_directory=tmp_path,
        authorization_database_path=tmp_path / "auth.db",
        logging_directory=tmp_path / "logs",
    )
    return SimpleNamespace(obj={"eve-auth-manager-settings": settings})


def test_remove_credential_delegates_to_auth_manager(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Remove credential should call the auth manager with the requested UUID."""
    ctx = _make_context(tmp_path)
    cred_id = UUID("33333333-3333-3333-3333-333333333333")
    calls: dict[str, object] = {}

    class FakeManager:
        def __enter__(self) -> "FakeManager":
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        def remove_credential(self, requested_cred_id: UUID) -> dict[UUID, str]:
            calls["cred_id"] = requested_cred_id
            return {requested_cred_id: "Main App"}

    monkeypatch.setattr(remove_module, "SqliteAuthManager", lambda path: FakeManager())

    remove_credential(ctx, cred_id, quiet=True)  # type: ignore[arg-type]

    assert calls["cred_id"] == cred_id


def test_remove_credential_prints_confirmation_when_not_quiet(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Remove credential should print the removal confirmation in normal mode."""
    ctx = _make_context(tmp_path)
    cred_id = UUID("44444444-4444-4444-4444-444444444444")
    printed: list[str] = []
    console_kwargs: list[dict[str, object]] = []

    class FakeConsole:
        def __init__(self, **kwargs: object) -> None:
            console_kwargs.append(dict(kwargs))

        def print(self, message: str) -> None:
            printed.append(message)

    class FakeManager:
        def __enter__(self) -> "FakeManager":
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        def remove_credential(self, requested_cred_id: UUID) -> dict[UUID, str]:
            assert requested_cred_id == cred_id
            return {requested_cred_id: "Main App"}

    monkeypatch.setattr(remove_module, "Console", FakeConsole)
    monkeypatch.setattr(remove_module, "SqliteAuthManager", lambda path: FakeManager())

    remove_credential(ctx, cred_id, quiet=False)  # type: ignore[arg-type]

    assert console_kwargs == [{"stderr": True}]
    assert printed == [
        f"Credential with ID {cred_id} - Main App has been removed.",
    ]
