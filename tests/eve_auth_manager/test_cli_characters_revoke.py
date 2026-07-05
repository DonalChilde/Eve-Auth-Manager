"""Tests for the characters revoke CLI command."""

from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest
import typer

import eve_auth_manager.cli.characters.revoke as revoke_module
from eve_auth_manager.cli.characters.revoke import revoke
from eve_auth_manager.settings import EveAuthManagerSettings


def _make_context(tmp_path: Path) -> SimpleNamespace:
    """Build a minimal context object with configured settings."""
    settings = EveAuthManagerSettings(
        auth_db_path=tmp_path / "auth.db",
        logging_directory=tmp_path / "logs",
    )
    return SimpleNamespace(obj={"eve-auth-manager-settings": settings})


def test_revoke_requires_credential_selector(tmp_path: Path) -> None:
    """Revoke should require either a credential ID or credential name."""
    ctx = _make_context(tmp_path)

    with pytest.raises(typer.Exit) as exc_info:
        revoke(ctx, quiet=True, force=True)  # type: ignore[arg-type]

    assert exc_info.value.exit_code == 1


def test_revoke_rejects_unknown_character_id(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Revoke should fail when asked to revoke an unauthorized character ID."""
    ctx = _make_context(tmp_path)
    cred_id = UUID("66666666-6666-6666-6666-666666666666")

    class FakeManager:
        def __enter__(self) -> "FakeManager":
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        def get_credential(
            self, *, cred_id: UUID | None = None, cred_name: str | None = None
        ) -> object:
            return SimpleNamespace(cred_id=cred_id)

        def get_all_character_ids(self, credential_id: UUID) -> dict[int, str]:
            assert credential_id == cred_id
            return {7: "Jane Capsuleer"}

    monkeypatch.setattr(revoke_module, "SqliteAuthManager", lambda path: FakeManager())

    with pytest.raises(typer.Exit) as exc_info:
        revoke(ctx, cred_id=cred_id, character_id=[99], quiet=True, force=True)  # type: ignore[arg-type]

    assert exc_info.value.exit_code == 1


def test_revoke_specific_characters_delegates_to_manager(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Revoke should pass the selected character IDs as a set to the manager."""
    ctx = _make_context(tmp_path)
    resolved_cred_id = UUID("77777777-7777-7777-7777-777777777777")
    calls: dict[str, object] = {}

    class FakeManager:
        def __enter__(self) -> "FakeManager":
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        def get_credential(
            self, *, cred_id: UUID | None = None, cred_name: str | None = None
        ) -> object:
            calls["get_credential"] = {"cred_id": cred_id, "cred_name": cred_name}
            return SimpleNamespace(cred_id=cred_id or resolved_cred_id)

        def get_all_character_ids(self, credential_id: UUID) -> dict[int, str]:
            calls["get_all_character_ids"] = credential_id
            return {7: "Jane Capsuleer", 9: "John Capsuleer"}

        def revoke_characters(
            self, credential_id: UUID, revocation_set: set[int] | None
        ) -> dict[int, str]:
            calls["revoke_characters"] = {
                "cred_id": credential_id,
                "revocation_set": revocation_set,
            }
            return {7: "Jane Capsuleer", 9: "John Capsuleer"}

    monkeypatch.setattr(revoke_module, "SqliteAuthManager", lambda path: FakeManager())

    revoke(
        ctx,
        cred_name="main",
        character_id=[7, 9, 9],
        quiet=True,
        force=True,
    )  # type: ignore[arg-type]

    assert calls["get_credential"] == {"cred_id": None, "cred_name": "main"}
    assert calls["get_all_character_ids"] == resolved_cred_id
    assert calls["revoke_characters"] == {
        "cred_id": resolved_cred_id,
        "revocation_set": {7, 9},
    }


def test_revoke_exits_cleanly_when_confirmation_is_declined(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Revoke should exit successfully when the confirmation prompt is declined."""
    ctx = _make_context(tmp_path)
    cred_id = UUID("17171717-1717-1717-1717-171717171717")

    class FakeManager:
        def __enter__(self) -> "FakeManager":
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        def get_credential(
            self, *, cred_id: UUID | None = None, cred_name: str | None = None
        ) -> object:
            return SimpleNamespace(cred_id=cred_id)

        def get_all_character_ids(self, credential_id: UUID) -> dict[int, str]:
            assert credential_id == cred_id
            return {7: "Jane Capsuleer"}

        def revoke_characters(
            self, credential_id: UUID, revocation_set: set[int] | None
        ) -> dict[int, str]:
            pytest.fail("revoke_characters should not be called")

    monkeypatch.setattr(revoke_module, "SqliteAuthManager", lambda path: FakeManager())
    monkeypatch.setattr(revoke_module.typer, "confirm", lambda *args, **kwargs: False)

    with pytest.raises(typer.Exit) as exc_info:
        revoke(ctx, cred_id=cred_id, quiet=True, force=False)  # type: ignore[arg-type]

    assert exc_info.value.exit_code in (None, 0)


def test_revoke_exits_cleanly_when_manager_returns_no_revocations(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Revoke should exit successfully when there is nothing left to revoke."""
    ctx = _make_context(tmp_path)
    cred_id = UUID("18181818-1818-1818-1818-181818181818")

    class FakeManager:
        def __enter__(self) -> "FakeManager":
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        def get_credential(
            self, *, cred_id: UUID | None = None, cred_name: str | None = None
        ) -> object:
            return SimpleNamespace(cred_id=cred_id)

        def get_all_character_ids(self, credential_id: UUID) -> dict[int, str]:
            assert credential_id == cred_id
            return {7: "Jane Capsuleer"}

        def revoke_characters(
            self, credential_id: UUID, revocation_set: set[int] | None
        ) -> dict[int, str]:
            assert credential_id == cred_id
            assert revocation_set == {7}
            return {}

    monkeypatch.setattr(revoke_module, "SqliteAuthManager", lambda path: FakeManager())

    with pytest.raises(typer.Exit) as exc_info:
        revoke(ctx, cred_id=cred_id, character_id=[7], quiet=True, force=True)  # type: ignore[arg-type]

    assert exc_info.value.exit_code == 0
