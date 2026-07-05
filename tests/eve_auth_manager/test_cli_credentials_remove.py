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
        auth_db_path=tmp_path / "auth.db",
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
