"""CLI command to revoke a character's access token."""

import asyncio
from pathlib import Path
from typing import Annotated
from uuid import UUID

import typer
from rich.console import Console

from eve_auth_manager.cli.helpers import get_auth_manager_settings_from_context
from eve_auth_manager.sqlite.manager import SqliteAuthManager

app = typer.Typer(no_args_is_help=True)


@app.command(name="refresh")
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
    character_ids_and_names = asyncio.run(
        _get_character_ids_and_names(settings.auth_db_path, cred_id)
    )
    revocation_set: set[int] | None = None
    if character_id is not None:
        revocation_set = set(character_id)
    for char_id in revocation_set or []:
        if char_id not in character_ids_and_names:
            messenger.print(
                f"[red]Character ID {char_id} is not authorized with credentials ID {cred_id}.[/red]"
            )
            raise typer.Exit(1)
    if not force:
        prompts: list[str] = []
        if revocation_set is None:
            prompts.append(
                "Are you sure you want to revoke all characters? This action cannot be "
                "undone."
            )
            for char_id, char_name in character_ids_and_names.items():
                prompts.append(f"- {char_id} - {char_name}")
        else:
            prompts.append(
                "Are you sure you want to revoke the following characters? This action "
                "cannot be undone."
            )
            for char_id in revocation_set:
                char_name = character_ids_and_names[char_id]
                prompts.append(f"- {char_id} - {char_name}")
        if not typer.confirm("\n".join(prompts), abort=True):
            messenger.print("[yellow]Revocation cancelled.[/yellow]")
            raise typer.Exit(0)

    revoked = asyncio.run(
        _revoke_character_tokens(
            settings.auth_db_path, cred_id, character_ids=revocation_set
        )
    )
    messenger.print("# Revoked characters:\n")
    for revoked_id, revoked_name in revoked.items():
        messenger.print(f"- {revoked_id} - {revoked_name}")


async def _get_character_ids_and_names(
    auth_db_path: Path, cred_id: UUID
) -> dict[int, str]:
    """Get all character IDs and names for the given credentials ID.

    Args:
        auth_db_path: Path to the authentication database.
        cred_id: The ID of the credentials.

    Returns:
        A dictionary mapping character_id to character name.

    Raises:
        CredentialsNotFoundError: If the credentials with the given ID are not found.
    """
    async with SqliteAuthManager(auth_db_path) as auth_manager:
        character_ids = auth_manager.get_all_character_ids(cred_id)
    return character_ids


async def _revoke_character_tokens(
    auth_db_path: Path, cred_id: UUID, character_ids: set[int] | None
) -> dict[int, str]:
    """Revoke the access token for the given character ID(s).

    Args:
        auth_db_path: Path to the authentication database.
        cred_id: The ID of the credentials.
        character_ids: A list of character IDs to revoke. If None, all characters will be revoked.

    Returns:
        A dictionary mapping character_id to character name for the revoked characters.

    Raises:
        CredentialsNotFoundError: If the credentials with the given ID are not found.
    """
    async with SqliteAuthManager(auth_db_path) as auth_manager:
        revoked = await auth_manager.revoke_characters(cred_id, character_ids)
    return revoked
