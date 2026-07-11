"""CLI command for revoking one or more authorized characters."""

from typing import Annotated
from uuid import UUID

import typer
from rich.console import Console

from eve_auth_manager.cli.helpers import get_auth_manager_settings_from_context
from eve_auth_manager.sqlite.manager import SqliteAuthManager

app = typer.Typer(no_args_is_help=True)


@app.command(name="revoke")
def revoke(
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
        list[int] | None,
        typer.Option(
            "--character-id",
            help="Authorized character ID to revoke. Repeat for multiple IDs. If omitted,"
            " all authorized characters for the selected credential are revoked.",
        ),
    ] = None,
    quiet: Annotated[
        bool, typer.Option("--quiet", help="Suppress output messages.")
    ] = False,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            help="Skip confirmation prompt before revocation.",
        ),
    ] = False,
) -> None:
    """Revoke one or more authorized characters for a credential.

    Notes:
        1. One of --cred-id or --cred-name must be provided.
        2. If both --cred-id and --cred-name are provided, --cred-id takes
           precedence.
        3. If --character-id is omitted, all authorized characters for the
           selected credential are targeted.
        4. Without --force, the command prompts for confirmation before
           revocation.

    Outcome:
        Prints the list of revoked character IDs and names. If nothing is
        revoked, the command exits successfully with a warning message.
    """
    if quiet:
        messenger = Console(stderr=True, quiet=True)
    else:
        messenger = Console(stderr=True)
    settings = get_auth_manager_settings_from_context(ctx)
    with SqliteAuthManager(settings.authorization_database_path) as auth_manager:
        # if both cred_id and cred_name are provided, cred_id takes precedence
        if cred_id is not None:
            credentials = auth_manager.get_credential(cred_id=cred_id)
        elif cred_name is not None:
            credentials = auth_manager.get_credential(cred_name=cred_name)
        else:
            messenger.print(
                "[red]Either --cred-id or --cred-name must be provided.[/red]"
            )
            raise typer.Exit(1)
        ids_with_names = auth_manager.get_all_character_ids(credentials.cred_id)
    revocation_set: set[int] | None = None
    if character_id is not None:
        revocation_set = set(character_id)
    for char_id in revocation_set or []:
        if char_id not in ids_with_names:
            messenger.print(
                f"[red]Character ID {char_id} is not authorized with credentials ID "
                f"{credentials.cred_id}.[/red]"
            )
            raise typer.Exit(1)
    if not force:
        prompts: list[str] = []
        if revocation_set is None:
            prompts.append(
                "Are you sure you want to revoke all characters? This action cannot be "
                "undone."
            )
            for char_id, char_name in ids_with_names.items():
                prompts.append(f"- {char_id} - {char_name}")
        else:
            prompts.append(
                "Are you sure you want to revoke the following characters? This action "
                "cannot be undone."
            )
            for char_id in revocation_set:
                char_name = ids_with_names[char_id]
                prompts.append(f"- {char_id} - {char_name}")
        if not typer.confirm("\n".join(prompts), abort=True):
            messenger.print("[yellow]Revocation cancelled.[/yellow]")
            raise typer.Exit(0)
    revoked = auth_manager.revoke_characters(credentials.cred_id, revocation_set)
    if not revoked:
        messenger.print(
            "[yellow]No characters were revoked. They may have already been revoked.[/yellow]"
        )
        raise typer.Exit(0)
    messenger.print("# Revoked characters:\n")
    for revoked_id, revoked_name in revoked.items():
        messenger.print(f"- {revoked_id} - {revoked_name}")
