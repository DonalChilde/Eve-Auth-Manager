"""CLI command for refreshing authorized character access tokens."""

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
        UUID | None,
        typer.Option(
            "--cred-id",
            help="Credential ID to use. One of --cred-id or --cred-name is required."
            " Takes precedence over --cred-name.",
        ),
    ] = None,
    cred_name: Annotated[
        str | None,
        typer.Option(
            "--cred-name",
            help="Credential name to use when --cred-id is not provided.",
        ),
    ] = None,
    character_id: Annotated[
        int | None,
        typer.Argument(
            help="Optional character ID to refresh. If omitted, all authorized"
            " characters for the selected credential are refreshed."
        ),
    ] = None,
    min_seconds: Annotated[
        int,
        typer.Option(
            "--min-seconds",
            help="Refresh only when token lifetime is below this many seconds.",
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
    """Refresh access tokens for one or more authorized characters.

    Notes:
        1. One of --cred-id or --cred-name must be provided.
        2. If both --cred-id and --cred-name are provided, --cred-id takes
           precedence.
        3. If character_id is omitted, all authorized characters for the
           selected credential are refreshed.
        4. Character refresh is skipped when the token lifetime is greater than
           or equal to --min-seconds.
        5. Maximum token lifetime is 20 minutes (1200 seconds). If --min-seconds is
           greater than 1200, the command will always refresh the token.

    Outcome:
        Prints the list of refreshed characters. If no authorized characters are
        found for the selected credential, the command exits successfully with a
        warning message.
    """
    if quiet:
        messenger = Console(stderr=True, quiet=True)
    else:
        messenger = Console(stderr=True)
    settings = get_auth_manager_settings_from_context(ctx)
    with SqliteAuthManager(settings.auth_db_path) as auth_manager:
        if cred_id is not None:
            credentials = auth_manager.get_credential(cred_id=cred_id)
        elif cred_name is not None:
            credentials = auth_manager.get_credential(cred_name=cred_name)
        else:
            messenger.print(
                "[red]Either --cred-id or --cred-name must be provided.[/red]"
            )
            raise typer.Exit(1)
        if character_id is not None:
            updated_char = auth_manager.refresh_character(
                credentials.cred_id, character_id, min_seconds=min_seconds
            )
            updated = [updated_char]
        else:
            updated = auth_manager.refresh_characters(
                credentials.cred_id, character_ids=character_id, min_seconds=min_seconds
            )
            if not updated:
                messenger.print(
                    "[yellow]No characters found for the specified credentials.[/yellow]"
                )
                raise typer.Exit(0)
        messenger.print("# Updated characters:\n")
        for character in updated:
            messenger.print(f"- {character.character_id}: {character.character_name}")
