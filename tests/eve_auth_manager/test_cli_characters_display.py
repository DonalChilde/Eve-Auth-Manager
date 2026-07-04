"""Tests for character display markdown generation."""

from unittest.mock import patch
from uuid import UUID

from eve_auth_manager.cli.characters.display import (
    detailed_display,
    display_characters_summary,
)
from eve_auth_manager.models import AuthorizedCharacter, OauthToken


def test_detailed_display_includes_all_character_fields() -> None:
    """Detailed display should include stored and computed character data."""
    character = AuthorizedCharacter(
        character_id=42,
        cred_id=UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        character_name="Jane Capsuleer",
        expires_at=4_600,
        oauth_token=OauthToken(
            token_data={
                "access_token": "access-token",
                "refresh_token": "refresh-token",
                "expires_in": 3_600,
                "token_type": "Bearer",
            }
        ),
    )

    with patch(
        "eve_auth_manager.cli.characters.display._character_expires_in",
        return_value=3_600,
    ):
        output = detailed_display(character)

    assert "# Character Details" in output
    assert "character_id" in output
    assert "42" in output
    assert "cred_id" in output
    assert "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" in output
    assert "character_name" in output
    assert "Jane Capsuleer" in output
    assert "expires_at" in output
    assert "4600" in output
    assert "oauth_token" in output
    assert "OauthToken(token_data={'access_token': 'access-token'" in output
    assert "expires_in" in output
    assert "3600" in output


def test_character_summary_lists_requested_columns() -> None:
    """Summary display should list identity, credential, and expiration data."""
    first = AuthorizedCharacter(
        character_id=42,
        cred_id=UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        character_name="Jane Capsuleer",
        expires_at=4_600,
        oauth_token=OauthToken(
            token_data={
                "access_token": "access-token",
                "refresh_token": "refresh-token",
                "expires_in": 3_600,
                "token_type": "Bearer",
            }
        ),
    )
    second = AuthorizedCharacter(
        character_id=84,
        cred_id=UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
        character_name="John Capsuleer",
        expires_at=8_200,
        oauth_token=OauthToken(
            token_data={
                "access_token": "other-access-token",
                "refresh_token": "other-refresh-token",
                "expires_in": 7_200,
                "token_type": "Bearer",
            }
        ),
    )

    with patch(
        "eve_auth_manager.cli.characters.display._character_expires_in",
        side_effect=[3_600, 7_200],
    ):
        output = display_characters_summary([first, second])

    assert "# Characters Summary" in output
    assert "character_id" in output
    assert "character_name" in output
    assert "cred_id" in output
    assert "expires_in" in output
    assert "42" in output
    assert "Jane Capsuleer" in output
    assert "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" in output
    assert "3600" in output
    assert "84" in output
    assert "John Capsuleer" in output
    assert "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb" in output
    assert "7200" in output
