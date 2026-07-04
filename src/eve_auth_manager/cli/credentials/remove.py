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
def remove_credentials(
    ctx: typer.Context,
    cred_id: Annotated[UUID, typer.Argument(help="ID of the credentials to remove")],
    quiet: Annotated[
        bool,
        typer.Option(
            "--quiet",
            help="Suppress output messages.",
        ),
    ] = False,
) -> None:
    """Remove credentials from the auth manager."""
    if quiet:
        messenger = Console(stderr=True, quiet=True)
    else:
        messenger = Console(stderr=True)
    settings = get_auth_manager_settings_from_context(ctx)
    with SqliteAuthManager(settings.auth_db_path) as auth_manager:
        removed = auth_manager.remove_credentials(cred_id)
        removed_cred_id = next(iter(removed))
    messenger.print(
        f"Credentials with ID {removed_cred_id} - {removed[removed_cred_id]} have been removed."
    )
