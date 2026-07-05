"""Tests for the credentials add CLI command."""

import json
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest

import eve_auth_manager.cli.credentials.add as add_module
from eve_auth_manager.cli.credentials.add import add_credentials
from eve_auth_manager.models import EsiAppCredential
from eve_auth_manager.settings import EveAuthManagerSettings


def _make_context(tmp_path: Path) -> SimpleNamespace:
    """Build a minimal context object with configured settings."""
    settings = EveAuthManagerSettings(
        auth_db_path=tmp_path / "auth.db",
        logging_directory=tmp_path / "logs",
    )
    return SimpleNamespace(obj={"eve-auth-manager-settings": settings})


def test_add_credentials_reads_json_from_stdin(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Add credentials should validate stdin JSON and store the credential."""
    ctx = _make_context(tmp_path)
    added_id = UUID("11111111-1111-1111-1111-111111111111")
    calls: dict[str, object] = {}

    class FakeManager:
        def __enter__(self) -> "FakeManager":
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        def add_credential(self, credentials: EsiAppCredential) -> dict[UUID, str]:
            calls["credentials"] = credentials
            return {added_id: credentials.name}

    monkeypatch.setattr(add_module, "SqliteAuthManager", lambda path: FakeManager())
    monkeypatch.setattr(
        add_module,
        "get_stdin",
        lambda: json.dumps(
            {
                "name": "Main App",
                "description": "Primary credential",
                "clientId": "client-id",
                "clientSecret": "secret",
                "callbackUrl": "http://localhost/callback",
                "scopes": ["esi-characters.read_contacts.v1"],
            }
        ),
    )

    add_credentials(ctx, quiet=True)  # type: ignore[arg-type]

    assert calls["credentials"] == EsiAppCredential(
        name="Main App",
        description="Primary credential",
        clientId="client-id",
        clientSecret="secret",
        callbackUrl="http://localhost/callback",
        scopes=["esi-characters.read_contacts.v1"],
    )


def test_add_credentials_reads_json_from_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Add credentials should read and validate JSON from a file path."""
    ctx = _make_context(tmp_path)
    creds_path = tmp_path / "credentials.json"
    creds_path.write_text(
        json.dumps(
            {
                "name": "Backup App",
                "description": "Secondary credential",
                "clientId": "backup-id",
                "clientSecret": "backup-secret",
                "callbackUrl": "http://localhost/backup",
                "scopes": [],
            }
        ),
        encoding="utf-8",
    )
    calls: dict[str, object] = {}

    class FakeManager:
        def __enter__(self) -> "FakeManager":
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        def add_credential(self, credentials: EsiAppCredential) -> dict[UUID, str]:
            calls["credentials"] = credentials
            return {UUID("22222222-2222-2222-2222-222222222222"): credentials.name}

    monkeypatch.setattr(add_module, "SqliteAuthManager", lambda path: FakeManager())

    add_credentials(ctx, credentials_file=creds_path, quiet=True)  # type: ignore[arg-type]

    assert calls["credentials"] == EsiAppCredential(
        name="Backup App",
        description="Secondary credential",
        clientId="backup-id",
        clientSecret="backup-secret",
        callbackUrl="http://localhost/backup",
        scopes=[],
    )


def test_add_credentials_reports_file_load_and_success_when_not_quiet(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Add credentials should report file loading and successful storage."""
    ctx = _make_context(tmp_path)
    creds_path = tmp_path / "credentials.json"
    creds_path.write_text(
        json.dumps(
            {
                "name": "Backup App",
                "description": "Secondary credential",
                "clientId": "backup-id",
                "clientSecret": "backup-secret",
                "callbackUrl": "http://localhost/backup",
                "scopes": [],
            }
        ),
        encoding="utf-8",
    )
    added_id = UUID("33333333-3333-3333-3333-333333333333")
    printed: list[object] = []
    console_kwargs: list[dict[str, object]] = []

    class FakeConsole:
        def __init__(self, **kwargs: object) -> None:
            console_kwargs.append(dict(kwargs))

        def print(self, message: object) -> None:
            printed.append(message)

    class FakeManager:
        def __enter__(self) -> "FakeManager":
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        def add_credential(self, credentials: EsiAppCredential) -> dict[UUID, str]:
            return {added_id: credentials.name}

    monkeypatch.setattr(add_module, "Console", FakeConsole)
    monkeypatch.setattr(add_module, "SqliteAuthManager", lambda path: FakeManager())

    add_credentials(ctx, credentials_file=creds_path, quiet=False)  # type: ignore[arg-type]

    assert console_kwargs == [{"stderr": True}]
    assert printed == [
        f"Loading credentials from {creds_path}...",
        f"Credentials added successfully for Backup App with ID: {added_id}",
    ]
