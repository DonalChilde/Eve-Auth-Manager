"""CLI command for adding ESI application credentials from JSON input."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from eve_auth_manager.cli.helpers import (
    get_auth_manager_settings_from_context,
    get_stdin,
)
from eve_auth_manager.models import EsiAppCredentialRoot
from eve_auth_manager.sqlite.manager import SqliteAuthManager

app = typer.Typer(no_args_is_help=True)


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
    """Add one ESI application credential from JSON input.

    Reads credential JSON from --from <path> or from stdin when --from - is
    used, validates the payload against the EsiAppCredential schema, and
    stores the credential in the auth database.

        The credential JSON is available from the EVE Developers site when
        creating a new ESI application:
        https://developers.eveonline.com/applications

        The JSON payload must use these exact field names:

        {
            "name": "My ESI App",
            "description": "Optional human-readable description",
            "clientId": "your_client_id",
            "clientSecret": "your_client_secret",
            "callbackUrl": "http://localhost:8080/callback",
            "scopes": ["scope1", "scope2"]
        }


    Notes:
        1. Input must be a JSON object matching the ESI app credential shape.
        2. The command fails if a conflicting credential already exists.
        3. On success, a status message includes the credential name and
           generated credential ID unless quiet mode is active.
    """
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
    credentials = EsiAppCredentialRoot.model_validate_json(creds_text).root
    with SqliteAuthManager(settings.authorization_database_path) as auth_manager:
        added_creds = auth_manager.add_credential(credentials)
    # get the UUID of the added credentials and print it
    cred_id = next(iter(added_creds))
    messenger.print(
        f"Credentials added successfully for {added_creds[cred_id]} with ID: {cred_id}"
    )
