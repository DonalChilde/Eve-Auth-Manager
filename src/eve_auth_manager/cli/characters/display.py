"""Command to display information about the currently stored credentials as markdown."""

import asyncio
from collections.abc import Iterable
from pathlib import Path
from typing import Annotated
from uuid import UUID

import typer
from mdformat import text as mdformat_text  # type: ignore
from rich.console import Console
from rich.markdown import Markdown

from eve_auth_manager.cli.helpers import get_auth_manager_settings_from_context
from eve_auth_manager.helpers.save_text_file import save_text_file
from eve_auth_manager.models import AuthorizedCharacter
from eve_auth_manager.sqlite.manager import SqliteAuthManager

app = typer.Typer(no_args_is_help=True, help="Display the currently stored characters.")


def detailed_display(character: AuthorizedCharacter) -> str:
    """Return a detailed display of the character as markdown."""
    report_lines: list[str] = []
    # report generation code here.
    raise NotImplementedError("Detailed display for character is not implemented yet.")
    report_string = "\n".join(report_lines)
    return mdformat_text(report_string, extensions=["tables"])


def display_characters_summary(
    characters: Iterable[AuthorizedCharacter],
) -> str:
    """Return a summary display of the characters as markdown."""
    report_lines: list[str] = []
    # report generation code here.
    raise NotImplementedError("Summary display for characters is not implemented yet.")
    report_string = "\n".join(report_lines)
    return mdformat_text(report_string, extensions=["tables"])


@app.command(name="display")
def display(
    ctx: typer.Context,
    cred_id: Annotated[
        UUID,
        typer.Argument(
            help="ID of the credentials to use.",
        ),
    ],
    character_id: Annotated[
        int | None,
        typer.Argument(
            help="ID of the character to display. If provided, display detailed "
            "information for the specified character. If not provided, a summary of "
            "all characters will be displayed.",
        ),
    ] = None,
    file_path: Annotated[
        Path | None,
        typer.Option(
            "--to",
            help="Path to the file to write the output to. If not provided, output will "
            "be printed to stdout.",
        ),
    ] = None,
    plain: Annotated[
        bool,
        typer.Option(
            "--plain",
            help="If set, output will be plain text instead of Rich markdown.",
        ),
    ] = False,
    overwrite: Annotated[
        bool,
        typer.Option(
            "--overwrite",
            help="If set, will overwrite the output file if it already exists.",
        ),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option(
            "--quiet",
            help="Suppress output messages.",
        ),
    ] = False,
) -> None:
    """Display the currently stored characters."""
    if quiet:
        messenger = Console(stderr=True, quiet=True)
    else:
        messenger = Console(stderr=True)
    stdout = Console()
    settings = get_auth_manager_settings_from_context(ctx)
    characters = asyncio.run(
        _get_characters(settings.auth_db_path, cred_id, character_id)
    )
    if isinstance(characters, list):
        if not characters:
            messenger.print("[yellow]No characters found in the database.[/yellow]")
            raise typer.Exit(0)
        output = display_characters_summary(characters)
    else:
        output = detailed_display(characters)

    if not file_path:
        if plain:
            stdout.print(output)
        else:
            stdout.print(Markdown(output))
    else:
        output_path = save_text_file(
            text=output,
            output_directory=file_path.parent,
            file_name=file_path.name,
            overwrite=overwrite,
        )
        messenger.print(f"Output saved to {output_path}")


async def _get_characters(
    db_path: Path, cred_id: UUID, character_id: int | None
) -> AuthorizedCharacter | list[AuthorizedCharacter]:
    """Get the character(s) from the auth manager.

    Args:
        db_path: Path to the SQLite database file.
        cred_id: The ID of the credentials to use for retrieving characters.
        character_id: The ID of the character to retrieve. If None, retrieves all
            characters for the given credentials.

    Returns:
        An AuthorizedCharacter object if a specific character ID is provided,
        otherwise a list of AuthorizedCharacter objects.

    Raises:
        CredentialsNotFoundError: If the credentials with the given ID are not found.
    """
    async with SqliteAuthManager(db_path) as auth_manager:
        if character_id is not None:
            character = auth_manager.get_character(cred_id, character_id)
            return character
        else:
            all_characters = auth_manager.get_all_characters(cred_id)
            return all_characters
