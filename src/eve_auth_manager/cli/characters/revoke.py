"""CLI command to revoke a character's access token."""

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
        UUID, typer.Argument(help="ID of the credentials to use for revoking")
    ],
    character_id: Annotated[
        list[int] | None,
        typer.Option(
            "--character-id",
            help="ID of the character to revoke. Can be specified multiple times. If "
            "not provided, all characters will be revoked.",
        ),
    ] = None,
    quiet: Annotated[
        bool, typer.Option("--quiet", help="Suppress output messages.")
    ] = False,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            help="Do not prompt for confirmation before revoking characters.",
        ),
    ] = False,
) -> None:
    """Revoke a character's access token."""
    if quiet:
        messenger = Console(stderr=True, quiet=True)
    else:
        messenger = Console(stderr=True)
    settings = get_auth_manager_settings_from_context(ctx)
    with SqliteAuthManager(settings.auth_db_path) as auth_manager:
        ids_with_names = auth_manager.get_all_character_ids(cred_id)
    revocation_set: set[int] | None = None
    if character_id is not None:
        revocation_set = set(character_id)
    for char_id in revocation_set or []:
        if char_id not in ids_with_names:
            messenger.print(
                f"[red]Character ID {char_id} is not authorized with credentials ID "
                f"{cred_id}.[/red]"
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
    revoked = auth_manager.revoke_characters(cred_id, revocation_set)
    if not revoked:
        messenger.print(
            "[yellow]No characters were revoked. They may have already been revoked.[/yellow]"
        )
        raise typer.Exit(0)
    messenger.print("# Revoked characters:\n")
    for revoked_id, revoked_name in revoked.items():
        messenger.print(f"- {revoked_id} - {revoked_name}")
