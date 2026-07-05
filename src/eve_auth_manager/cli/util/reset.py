"""Destructive CLI command for deleting and recreating the auth database."""

from typing import Annotated

import typer
from rich.console import Console

from eve_auth_manager.cli.helpers import get_auth_manager_settings_from_context
from eve_auth_manager.sqlite.manager import SqliteAuthManager

app = typer.Typer(
    no_args_is_help=True,
    help="Delete and recreate the auth database, removing all stored credentials and characters.",
)


@app.command(name="reset")
def reset_database(
    ctx: typer.Context,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            "-f",
            help="Skip confirmation and reset immediately.",
        ),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option(
            "--quiet",
            "-q",
            help="Suppress output messages. Requires --force.",
        ),
    ] = False,
) -> None:
    """Delete and recreate the auth database after optional confirmation.

    Notes:
        1. When force is false, the command prompts before deleting and
           recreating the database.
        2. The database file is removed and then recreated through
           SqliteAuthManager to verify that schema initialization succeeds.
        3. In both forced and prompted paths, all stored credentials and
           authorized characters are permanently removed.
        4. Using --quiet without --force raises typer.BadParameter.
    """
    # The standalone CLI callback stores EveAuthManagerSettings in
    # typer.Context.obj under the eve-auth-manager-settings key.
    if quiet and not force:
        raise typer.BadParameter(
            "Cannot use --quiet without --force. Use --force to reset the database without confirmation."
        )
    if quiet:
        messenger = Console(stderr=True, quiet=True)
    else:
        messenger = Console(stderr=True)
    settings = get_auth_manager_settings_from_context(ctx)
    db_path = settings.auth_db_path
    if force:
        messenger.print(f"Erasing auth database at {db_path}...")
        db_path.unlink(missing_ok=True)
        messenger.print(f"Recreating auth database at {db_path}...")
        # Verify that the database can be opened and the schema is correct
        with SqliteAuthManager(db_path) as manager:
            _ = manager.get_all_credentials()
        raise typer.Exit()

    # If not forced, prompt the user for confirmation
    messenger.print(
        f"[red]WARNING: This will erase the auth database at {db_path} and remove all stored credentials and characters.[/red]"
    )
    confirm = typer.confirm("Are you sure you want to proceed?", default=False)
    if not confirm:
        messenger.print("Aborting reset.")
        raise typer.Exit()
    messenger.print(f"Erasing auth database at {db_path}...")
    db_path.unlink(missing_ok=True)
    messenger.print(f"Recreating auth database at {db_path}...")
    # Verify that the database can be opened and the schema is correct
    with SqliteAuthManager(db_path) as manager:
        _ = manager.get_all_credentials()
    raise typer.Exit()
