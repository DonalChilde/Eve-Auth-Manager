"""Tests for credential display markdown generation."""

from uuid import UUID

from eve_auth_manager.cli.credentials.display import (
    CredentialDetails,
    detailed_display,
    display_credientials_summary,
)
from eve_auth_manager.models import AuthCredentials


def test_detailed_display_includes_all_auth_credential_fields() -> None:
    """Detailed display should include each credential field and the auth count."""
    credentials = AuthCredentials(
        cred_id=UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
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
    assert "| name                       | Primary App" in output
    assert "| description                | Used for corp tools" in output
    assert "| clientId                   | client-id-123" in output
    assert "| clientSecret               | secret-456" in output
    assert "| callbackUrl                | https://example.com/callback" in output
    assert (
        "| scopes                     | esi-wallet.read_character_wallet.v1, esi-characters.read_contacts.v1"
        in output
    )
    assert (
        "| cred_id                    | aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" in output
    )
    assert "| authorized_character_count | 2" in output


def test_credentials_summary_lists_requested_columns() -> None:
    """Summary display should list credential identity and authorization counts."""
    first = CredentialDetails(
        auth_credentials=AuthCredentials(
            cred_id=UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
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
        auth_credentials=AuthCredentials(
            cred_id=UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            name="Backup App",
            description="Alliance auth",
            clientId="client-id-789",
            clientSecret="secret-012",
            callbackUrl="https://example.com/backup-callback",
            scopes=[],
        ),
        authorized_character_count=5,
    )

    output = display_credientials_summary([first, second])

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
