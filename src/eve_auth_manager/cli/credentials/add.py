"""CLI command to add credentials to the auth manager."""

import asyncio
from pathlib import Path
from typing import Annotated
from uuid import UUID

import typer
from rich.console import Console

from eve_auth_manager.cli.helpers import (
    get_auth_manager_settings_from_context,
    get_stdin,
)
from eve_auth_manager.models import EsiAppCredentials, EsiAppCredentialsRoot
from eve_auth_manager.sqlite.manager import SqliteAuthManager

app = typer.Typer(
    no_args_is_help=True, name="credentials", help="Manage ESI app credentials."
)


@app.command(name="add")
def add_credentials(
    ctx: typer.Context,
    credentials_file: Annotated[
        Path,
        typer.Option(
            "--from",
            help="Path to the credentials file. Use '-' to read from stdin.",
            file_okay=True,
            dir_okay=False,
            readable=True,
            allow_dash=True,
        ),
    ] = Path("-"),
    quiet: Annotated[
        bool,
        typer.Option(
            "--quiet",
            help="Suppress output messages.",
        ),
    ] = False,
) -> None:
    """Add credentials.

    Fails if credentials already exist.
    """
    if credentials_file == Path("-"):
        quiet = True  # Force quiet mode when reading from stdin
    if quiet:
        messenger = Console(stderr=True, quiet=True)
    else:
        messenger = Console(stderr=True)
    settings = get_auth_manager_settings_from_context(ctx)
    if credentials_file == Path("-"):
        creds_text = get_stdin()
    else:
        messenger.print(f"Loading credentials from {credentials_file}...")
        creds_text = credentials_file.read_text()
    credentials = EsiAppCredentialsRoot.model_validate_json(creds_text).root
    added_creds = asyncio.run(_add_credentials(settings.auth_db_path, credentials))
    # get the UUID of the added credentials and print it
    cred_id = next(iter(added_creds))
    messenger.print(
        f"Credentials added successfully for {added_creds[cred_id]} with ID: {cred_id}"
    )


async def _add_credentials(
    db_path: Path, credentials: EsiAppCredentials
) -> dict[UUID, str]:
    """Add credentials to the auth manager.

    Args:
        db_path: Path to the SQLite database file.
        credentials: The ESI app credentials to add.

    Returns:
        The ID of the added credentials.
    """
    async with SqliteAuthManager(db_path) as auth_manager:
        cred_id = auth_manager.add_credentials(credentials)
    return cred_id
