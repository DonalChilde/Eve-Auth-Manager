"""Command to refresh one or more character access tokens."""

from typing import Annotated
from uuid import UUID

import typer
from rich.console import Console

from eve_auth_manager.cli.helpers import get_auth_manager_settings_from_context
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
    with SqliteAuthManager(settings.auth_db_path) as auth_manager:
        if character_id is not None:
            updated_char = auth_manager.refresh_character(
                cred_id, character_id, min_seconds=min_seconds
            )
            updated = [updated_char]
        else:
            updated = auth_manager.refresh_characters(
                cred_id, character_ids=character_id, min_seconds=min_seconds
            )
            if not updated:
                messenger.print(
                    "[yellow]No characters found for the specified credentials.[/yellow]"
                )
                raise typer.Exit(0)
        messenger.print("# Updated characters:\n")
        for character in updated:
            messenger.print(f"- {character.character_id}: {character.character_name}")
