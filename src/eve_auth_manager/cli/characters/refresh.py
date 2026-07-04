"""Command to refresh one or more character access tokens."""

import asyncio
from pathlib import Path
from typing import Annotated
from uuid import UUID

import typer
from rich.console import Console

from eve_auth_manager.cli.helpers import get_auth_manager_settings_from_context
from eve_auth_manager.models import AuthorizedCharacter
from eve_auth_manager.sqlite.manager import SqliteAuthManager

app = typer.Typer(no_args_is_help=True)


@app.command(name="refresh")
def refresh(
    ctx: typer.Context,
    cred_id: Annotated[
        UUID, typer.Argument(help="ID of the credentials to use for refreshing")
    ],
    character_id: Annotated[
        int | None,
        typer.Argument(
            help="ID of the character to refresh the token for. If not provided, all "
            "characters will be refreshed."
        ),
    ] = None,
    min_seconds: Annotated[
        int,
        typer.Option(
            "--min-seconds",
            help="Minimum number of seconds remaining on the access token before it will "
            "be refreshed.",
        ),
    ] = 300,
    quiet: Annotated[
        bool,
        typer.Option(
            "--quiet",
            help="Suppress output messages.",
        ),
    ] = False,
) -> None:
    """Refresh a character's access token."""
    if quiet:
        messenger = Console(stderr=True, quiet=True)
    else:
        messenger = Console(stderr=True)
    settings = get_auth_manager_settings_from_context(ctx)
    updated = asyncio.run(
        _refresh_character_token(
            settings.auth_db_path, cred_id, character_id, min_seconds
        )
    )
    if isinstance(updated, list):
        if not updated:
            messenger.print(
                "[yellow]No characters found for the specified credentials.[/yellow]"
            )
            raise typer.Exit(0)
    else:
        updated = [updated]
    messenger.print("# Updated characters:\n")
    for character in updated:
        messenger.print(f"- {character.character_id}: {character.character_name}")


async def _refresh_character_token(
    db_path: Path, cred_id: UUID, character_id: int | None, min_seconds: int = 300
) -> AuthorizedCharacter | list[AuthorizedCharacter]:
    """Refresh a character's access token.

    Args:
        db_path: Path to the SQLite database file.
        cred_id: The ID of the credentials to use for refreshing.
        character_id: The ID of the character to refresh the token for. If None, all
            characters will be refreshed.
        min_seconds: Minimum number of seconds remaining on the access token before it
            will be refreshed.

    Returns:
        The updated AuthorizedCharacter object if a specific character was refreshed,
        or a list of updated AuthorizedCharacter objects if all characters were
        refreshed.
    """
    async with SqliteAuthManager(db_path) as auth_manager:
        if character_id is not None:
            updated_character = auth_manager.refresh_character(
                cred_id, character_id, min_seconds=min_seconds
            )
            return updated_character
        else:
            updated_characters = await auth_manager.refresh_characters(
                cred_id, min_seconds=min_seconds
            )
            return updated_characters
