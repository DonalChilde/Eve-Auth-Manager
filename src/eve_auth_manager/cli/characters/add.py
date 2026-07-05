"""CLI command for authorizing and adding a character token."""

import webbrowser
from typing import Annotated
from uuid import UUID

import typer
from rich.console import Console

from eve_auth_manager.auth import token_tools
from eve_auth_manager.auth.request_authentication_code import (
    generate_request_params,
    start_web_server_and_listen_for_code,
)
from eve_auth_manager.cli.helpers import get_auth_manager_settings_from_context
from eve_auth_manager.sqlite.manager import SqliteAuthManager

app = typer.Typer(no_args_is_help=True, help="Authorize and add a character.")


@app.command(name="add")
def add(
    ctx: typer.Context,
    character_id: Annotated[
        int,
        typer.Argument(
            help="Character ID expected from the authorization flow.",
        ),
    ],
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
    browser_auto_open: Annotated[
        bool,
        typer.Option(
            help="Automatically open the authorization URL in your default browser.",
        ),
    ] = True,
    server_timeout: Annotated[
        int,
        typer.Option(
            "--timeout",
            help="Seconds to wait for the authentication code before the command fails.",
        ),
    ] = 120,
    quiet: Annotated[
        bool,
        typer.Option(
            "--quiet",
            help="Suppress output messages.",
        ),
    ] = False,
) -> None:
    """Authorize and add one character for the selected credential.

    Notes:
        1. One of --cred-id or --cred-name must be provided.
        2. If both --cred-id and --cred-name are provided, --cred-id takes
           precedence.
        3. The command opens an authorization URL unless browser auto-open is
           disabled or unavailable.
        4. If no authentication code is received before --timeout, the command
           exits with an error.
        5. The returned token is validated and must match character_id.
        6. If the character is already authorized for the selected credential,
           the command exits successfully without changes.

    Outcome:
        On success, stores the authorized character token and prints the
        character ID, character name, and credential ID.
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
        character_ids = auth_manager.get_all_character_ids(credentials.cred_id)
        oauth_metadata = auth_manager.oauth_metadata
        if character_id in character_ids:
            messenger.print(
                f"[yellow]Character ID {character_id} is already authorized with "
                f"credentials ID {credentials.cred_id}.[/yellow]"
            )
            raise typer.Exit(0)

        request_params = generate_request_params(
            client_id=credentials.clientId,
            callback_url=credentials.callbackUrl,
            authorization_endpoint=oauth_metadata.authorization_endpoint,
            scopes=credentials.scopes,
        )
        if browser_auto_open:
            opened = webbrowser.open(request_params.redirect_url)
            if opened:
                messenger.print("Opened browser for authorization.")
            else:
                messenger.print(
                    "Could not automatically open browser. Visit this URL to continue:"
                )
                messenger.print(request_params.redirect_url)
        else:
            messenger.print("Visit this URL to continue:")
            messenger.print(request_params.redirect_url)
        authorization_code = start_web_server_and_listen_for_code(
            redirect_url=credentials.callbackUrl,
            expected_state=request_params.state,
            timeout_seconds=server_timeout,
        )
        if not authorization_code:
            messenger.print(
                f"[red]Did not receive authentication code within {server_timeout} seconds.[/red]"
            )
            raise typer.Exit(1)
        messenger.print("Received authentication code, exchanging for token...")

        oauth_token = token_tools.request_new_token(
            session=auth_manager.session,
            client_id=credentials.clientId,
            authorization_code=authorization_code,
            code_verifier=request_params.code_verifier,
            oauth_metadata=oauth_metadata,
        )
        validated_token = token_tools.validate_token(
            access_token=oauth_token.access_token,
            jwks_client=auth_manager.jwks_client,
            oauth_metadata=oauth_metadata,
        )
        character_token = token_tools.create_character_token(
            cred_id=credentials.cred_id,
            oauth_token=oauth_token,
            validated_token=validated_token,
        )
        if character_token.character_id != character_id:
            messenger.print(
                f"[red]Received token for character ID {character_token.character_id}, "
                f"but expected {character_id}.[/red]"
            )
            raise typer.Exit(1)
        auth_manager.add_character(
            cred_id=credentials.cred_id, character=character_token
        )
        messenger.print(
            f"[green]Successfully added {character_id} - {character_token.character_name} with credentials ID "
            f"{credentials.cred_id}.[/green]"
        )
