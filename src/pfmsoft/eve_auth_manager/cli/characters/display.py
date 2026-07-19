"""CLI command for displaying stored authorized characters as markdown."""

from collections.abc import Iterable
from dataclasses import fields
from pathlib import Path
from typing import Annotated
from uuid import UUID

import typer
from mdformat import text as mdformat_text  # type: ignore
from rich.console import Console
from rich.markdown import Markdown

from pfmsoft.eve_auth_manager.cli.helpers import get_auth_manager_settings_from_context
from pfmsoft.eve_auth_manager.helpers.markdown_table import MarkdownTable
from pfmsoft.eve_auth_manager.helpers.save_text_file import save_text_file
from pfmsoft.eve_auth_manager.models import AuthorizedCharacter
from pfmsoft.eve_auth_manager.sqlite.manager import SqliteAuthManager

app = typer.Typer(no_args_is_help=True, help="Display the currently stored characters.")


def detailed_display(character: AuthorizedCharacter) -> str:
    """Render one character as a formatted markdown details table.

    The output includes all model fields plus a computed expires_in row.
    """
    table = MarkdownTable(headers=["Field", "Value"])
    for field_info in fields(character):
        value = getattr(character, field_info.name)
        table.add_row([field_info.name, value])

    table.add_row(["expires_in", character.expires_in])
    report_string = "\n".join(["# Character Details", "", table.render()])
    return mdformat_text(report_string, extensions=["tables"])


def display_characters_summary(
    characters: Iterable[AuthorizedCharacter],
) -> str:
    """Render a markdown summary table for multiple characters."""
    table = MarkdownTable(
        headers=["character_id", "character_name", "cred_id", "expires_in"],
    )
    for character in characters:
        table.add_row([
            character.character_id,
            character.character_name,
            character.cred_id,
            character.expires_in,
        ])

    report_string = "\n".join(["# Characters Summary", "", table.render()])
    return mdformat_text(report_string, extensions=["tables"])


@app.command(name="display")
def display(
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
        int | None,
        typer.Argument(
            help="Optional character ID to display. If omitted, a summary of all"
            " characters for the selected credential is shown.",
        ),
    ] = None,
    file_path: Annotated[
        Path | None,
        typer.Option(
            "--to",
            help="Output path for markdown results. Omit to print to stdout.",
        ),
    ] = None,
    plain: Annotated[
        bool,
        typer.Option(
            "--plain",
            help="Print plain markdown text instead of Rich-rendered markdown.",
        ),
    ] = False,
    overwrite: Annotated[
        bool,
        typer.Option(
            "--overwrite",
            help="Overwrite the output file if it already exists.",
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
    """Display authorized characters for the selected credential.

    Notes:
        1. One of --cred-id or --cred-name must be provided.
        2. If both --cred-id and --cred-name are provided, --cred-id takes
           precedence.
        3. If character_id is provided, the command outputs a detailed view for
           that character.
        4. If character_id is omitted, the command outputs a summary table for
           all characters under the selected credential.
        5. If no characters are found for summary mode, the command exits
           successfully after printing a notice.

    Output:
        Emits markdown either to stdout (default) or to --to file path. By
        default, stdout output is rendered with Rich markdown. Use --plain to
        emit plain markdown text.
    """
    if quiet:
        messenger = Console(stderr=True, quiet=True)
    else:
        messenger = Console(stderr=True)
    settings = get_auth_manager_settings_from_context(ctx)
    with SqliteAuthManager(settings.authorization_database_path) as auth_manager:
        if cred_id is not None:
            credentials = auth_manager.get_credential(cred_id=cred_id)
        elif cred_name is not None:
            credentials = auth_manager.get_credential(cred_name=cred_name)
        else:
            messenger.print(
                "[red]Either --cred-id or --cred-name must be provided.[/red]"
            )
            raise typer.Exit(1)
        if character_id is not None:
            character = auth_manager.get_character(credentials.cred_id, character_id)
            output = detailed_display(character)
        else:
            characters = auth_manager.get_all_characters(credentials.cred_id)
            if not characters:
                messenger.print("[yellow]No characters found in the database.[/yellow]")
                raise typer.Exit(0)
            output = display_characters_summary(characters)
        if not file_path:
            if plain:
                print(output)
            else:
                messenger.print(Markdown(output))
        else:
            output_path = save_text_file(
                text=output,
                output_directory=file_path.parent,
                file_name=file_path.name,
                overwrite=overwrite,
            )
            messenger.print(f"Output saved to {output_path}")
