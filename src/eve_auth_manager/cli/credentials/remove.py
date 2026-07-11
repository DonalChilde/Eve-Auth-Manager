"""CLI command for removing stored ESI credentials by credential ID."""

from typing import Annotated
from uuid import UUID

import typer
from rich.console import Console

from eve_auth_manager.cli.helpers import (
    get_auth_manager_settings_from_context,
)
from eve_auth_manager.sqlite.manager import SqliteAuthManager

app = typer.Typer(no_args_is_help=True)


@app.command(name="remove")
def remove_credential(
    ctx: typer.Context,
    cred_id: Annotated[UUID, typer.Argument(help="Credential ID to remove.")],
    quiet: Annotated[
        bool,
        typer.Option(
            "--quiet",
            help="Suppress output messages.",
        ),
    ] = False,
) -> None:
    """Remove one stored credential by ID.

    Deletes the credential identified by cred_id from the auth database and
    prints a confirmation message unless quiet mode is enabled.

    Notes:
        1. The command expects a valid credential UUID.
        2. If the credential does not exist, the underlying manager raises an
           error.
    """
    if quiet:
        messenger = Console(stderr=True, quiet=True)
    else:
        messenger = Console(stderr=True)
    settings = get_auth_manager_settings_from_context(ctx)
    with SqliteAuthManager(settings.authorization_database_path) as auth_manager:
        removed = auth_manager.remove_credential(cred_id)
        removed_cred_id = next(iter(removed))
    messenger.print(
        f"Credential with ID {removed_cred_id} - {removed[removed_cred_id]} has been removed."
    )
