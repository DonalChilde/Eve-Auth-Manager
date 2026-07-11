"""Tests for credential display markdown generation."""

from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest
import typer

import eve_auth_manager.cli.credentials.display as display_module
from eve_auth_manager.cli.credentials.display import (
    CredentialDetails,
    _get_credentials_details,
    detailed_display,
    display,
    display_credentials_summary,
)
from eve_auth_manager.models import AuthCredential
from eve_auth_manager.settings import EveAuthManagerSettings


def _make_context(tmp_path: Path) -> SimpleNamespace:
    """Build a minimal context object with configured settings."""
    settings = EveAuthManagerSettings(
        application_directory=tmp_path,
        authorization_database_path=tmp_path / "auth.db",
        logging_directory=tmp_path / "logs",
    )
    return SimpleNamespace(obj={"eve-auth-manager-settings": settings})


def _make_credential(*, cred_id: UUID, name: str, description: str) -> AuthCredential:
    """Create a stored credential test fixture."""
    return AuthCredential(
        cred_id=cred_id,
        created_at=1_234,
        name=name,
        description=description,
        clientId=f"{name}-client-id",
        clientSecret=f"{name}-secret",
        callbackUrl=f"https://example.com/{name}",
        scopes=["scope.one"],
    )


def test_detailed_display_includes_all_auth_credential_fields() -> None:
    """Detailed display should include each credential field and the auth count."""
    credentials = AuthCredential(
        cred_id=UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        created_at=1_234,
        name="Primary App",
        description="Used for corp tools",
        clientId="client-id-123",
        clientSecret="secret-456",
        callbackUrl="https://example.com/callback",
        scopes=[
            "esi-wallet.read_character_wallet.v1",
            "esi-characters.read_contacts.v1",
        ],
    )

    output = detailed_display(
        CredentialDetails(
            auth_credentials=credentials,
            authorized_character_count=2,
        )
    )

    assert "# Credential Details" in output
    assert "| cred_id      | aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" in output
    assert "| created_at   | 1970-01-01T00:20:34Z" in output
    assert "| characters   | 2" in output
    assert "| name         | Primary App" in output
    assert "| description  | Used for corp tools" in output
    assert "| clientId     | client-id-123" in output
    assert "| clientSecret | secret-456" in output
    assert "| callbackUrl  | https://example.com/callback" in output
    assert (
        "| scopes       | ['esi-wallet.read_character_wallet.v1', 'esi-characters.read_contacts.v1']"
        in output
    )


def test_credentials_summary_lists_requested_columns() -> None:
    """Summary display should list credential identity and authorization counts."""
    first = CredentialDetails(
        auth_credentials=AuthCredential(
            cred_id=UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            created_at=1_234,
            name="Primary App",
            description="Corp auth",
            clientId="client-id-123",
            clientSecret="secret-456",
            callbackUrl="https://example.com/callback",
            scopes=[],
        ),
        authorized_character_count=2,
    )
    second = CredentialDetails(
        auth_credentials=AuthCredential(
            cred_id=UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            created_at=5_678,
            name="Backup App",
            description="Alliance auth",
            clientId="client-id-789",
            clientSecret="secret-012",
            callbackUrl="https://example.com/backup-callback",
            scopes=[],
        ),
        authorized_character_count=5,
    )

    output = display_credentials_summary([first, second])

    assert "# Credentials Summary" in output
    assert "cred_id" in output
    assert "name" in output
    assert "description" in output
    assert "authorized_character_count" in output
    assert "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" in output
    assert "Primary App" in output
    assert "Corp auth" in output
    assert "2" in output
    assert "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb" in output
    assert "Backup App" in output
    assert "Alliance auth" in output
    assert "5" in output


def test_display_exits_cleanly_when_no_credentials(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Display should exit successfully when no credentials are stored."""
    ctx = _make_context(tmp_path)

    monkeypatch.setattr(display_module, "_get_credentials_details", lambda *args: [])

    with pytest.raises(typer.Exit) as exc_info:
        display(ctx, quiet=True)  # type: ignore[arg-type]

    assert exc_info.value.exit_code == 0


def test_display_prints_plain_summary_to_stdout(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Display should print plain markdown to stdout when requested."""
    ctx = _make_context(tmp_path)
    details = [
        CredentialDetails(
            auth_credentials=_make_credential(
                cred_id=UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
                name="primary-app",
                description="Primary auth",
            ),
            authorized_character_count=2,
        )
    ]

    monkeypatch.setattr(
        display_module, "_get_credentials_details", lambda *args: details
    )
    monkeypatch.setattr(
        display_module,
        "display_credentials_summary",
        lambda credential_details: "# Summary\n\nbody",
    )

    display(ctx, plain=True, quiet=True)  # type: ignore[arg-type]

    assert capsys.readouterr().out == "# Summary\n\nbody\n"


def test_display_writes_detailed_output_to_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Display should write detailed markdown to the requested file."""
    ctx = _make_context(tmp_path)
    detail = CredentialDetails(
        auth_credentials=_make_credential(
            cred_id=UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            name="backup-app",
            description="Backup auth",
        ),
        authorized_character_count=5,
    )
    output_path = tmp_path / "credentials.md"

    monkeypatch.setattr(
        display_module, "_get_credentials_details", lambda *args: detail
    )
    monkeypatch.setattr(
        display_module,
        "detailed_display",
        lambda credential_details: "# Detail\n\ncontent",
    )

    display(  # type: ignore[arg-type]
        ctx,
        file_path=output_path,
        overwrite=True,
        quiet=True,
    )

    assert output_path.read_text(encoding="utf-8") == "# Detail\n\ncontent"


def test_get_credentials_details_returns_single_entry_by_id(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Credential detail lookup should resolve a specific credential by UUID."""
    cred_id = UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")
    credential = _make_credential(
        cred_id=cred_id,
        name="primary-app",
        description="Primary auth",
    )

    class FakeManager:
        def __enter__(self) -> "FakeManager":
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        def get_credential(
            self, *, cred_id: UUID | None = None, cred_name: str | None = None
        ) -> AuthCredential:
            assert cred_id == credential.cred_id
            assert cred_name is None
            return credential

        def get_all_character_ids(self, requested_cred_id: UUID) -> dict[int, str]:
            assert requested_cred_id == credential.cred_id
            return {7: "Jane Capsuleer", 9: "John Capsuleer"}

    monkeypatch.setattr(display_module, "SqliteAuthManager", lambda path: FakeManager())

    result = _get_credentials_details(tmp_path / "auth.db", cred_id, None)

    assert result == CredentialDetails(
        auth_credentials=credential,
        authorized_character_count=2,
    )


def test_get_credentials_details_returns_single_entry_by_name(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Credential detail lookup should resolve a specific credential by name."""
    cred_id = UUID("dddddddd-dddd-dddd-dddd-dddddddddddd")
    credential = _make_credential(
        cred_id=cred_id,
        name="backup-app",
        description="Backup auth",
    )

    class FakeManager:
        def __enter__(self) -> "FakeManager":
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        def get_credential(
            self, *, cred_id: UUID | None = None, cred_name: str | None = None
        ) -> AuthCredential:
            assert cred_id is None
            assert cred_name == credential.name
            return credential

        def get_all_character_ids(self, requested_cred_id: UUID) -> dict[int, str]:
            assert requested_cred_id == credential.cred_id
            return {42: "Jane Capsuleer"}

    monkeypatch.setattr(display_module, "SqliteAuthManager", lambda path: FakeManager())

    result = _get_credentials_details(tmp_path / "auth.db", None, credential.name)

    assert result == CredentialDetails(
        auth_credentials=credential,
        authorized_character_count=1,
    )


def test_get_credentials_details_returns_summary_for_all_credentials(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Credential detail lookup should build summary entries for all credentials."""
    first = _make_credential(
        cred_id=UUID("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"),
        name="primary-app",
        description="Primary auth",
    )
    second = _make_credential(
        cred_id=UUID("ffffffff-ffff-ffff-ffff-ffffffffffff"),
        name="backup-app",
        description="Backup auth",
    )

    class FakeManager:
        def __enter__(self) -> "FakeManager":
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        def get_all_credentials(self) -> list[AuthCredential]:
            return [first, second]

        def get_all_character_ids(self, requested_cred_id: UUID) -> dict[int, str]:
            if requested_cred_id == first.cred_id:
                return {1: "One"}
            if requested_cred_id == second.cred_id:
                return {2: "Two", 3: "Three"}
            raise AssertionError(f"Unexpected credential id: {requested_cred_id}")

    monkeypatch.setattr(display_module, "SqliteAuthManager", lambda path: FakeManager())

    result = _get_credentials_details(tmp_path / "auth.db", None, None)

    assert result == [
        CredentialDetails(auth_credentials=first, authorized_character_count=1),
        CredentialDetails(auth_credentials=second, authorized_character_count=2),
    ]


def test_display_prints_rich_markdown_to_stdout(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Display should render markdown through Rich when plain mode is off."""
    ctx = _make_context(tmp_path)
    details = CredentialDetails(
        auth_credentials=_make_credential(
            cred_id=UUID("12121212-3434-5656-7878-909090909090"),
            name="primary-app",
            description="Primary auth",
        ),
        authorized_character_count=2,
    )
    printed: list[object] = []
    console_kwargs: list[dict[str, object]] = []

    class FakeConsole:
        def __init__(self, **kwargs: object) -> None:
            console_kwargs.append(dict(kwargs))

        def print(self, message: object) -> None:
            printed.append(message)

    monkeypatch.setattr(display_module, "Console", FakeConsole)
    monkeypatch.setattr(display_module, "Markdown", lambda text: ("markdown", text))
    monkeypatch.setattr(
        display_module, "_get_credentials_details", lambda *args: details
    )
    monkeypatch.setattr(
        display_module,
        "detailed_display",
        lambda credential_details: "# Detail\n\ncontent",
    )

    display(ctx, plain=False, quiet=False)  # type: ignore[arg-type]

    assert console_kwargs == [{"stderr": True}]
    assert printed == [("markdown", "# Detail\n\ncontent")]
