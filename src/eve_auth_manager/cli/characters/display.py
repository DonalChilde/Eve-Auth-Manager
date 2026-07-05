"""Command to display information about the currently stored credentials as markdown."""

from collections.abc import Iterable
from dataclasses import fields
from pathlib import Path
from typing import Annotated
from uuid import UUID

import typer
from mdformat import text as mdformat_text  # type: ignore
from rich.console import Console
from rich.markdown import Markdown

from eve_auth_manager.cli.helpers import get_auth_manager_settings_from_context
from eve_auth_manager.helpers.markdown_table import MarkdownTable
from eve_auth_manager.helpers.save_text_file import save_text_file
from eve_auth_manager.models import AuthorizedCharacter
from eve_auth_manager.sqlite.manager import SqliteAuthManager

app = typer.Typer(no_args_is_help=True, help="Display the currently stored characters.")


# def _format_markdown_table_value(value: object) -> str:
#     """Return a table-safe markdown representation of a value."""
#     text = str(value)
#     if not text:
#         return "-"
#     return text.replace("|", r"\|").replace("\n", "<br>")


# def _character_expires_in(character: AuthorizedCharacter) -> int:
#     """Return the number of seconds until the character token expires."""
#     return character.expires_in


def detailed_display(character: AuthorizedCharacter) -> str:
    """Return a detailed display of the character as markdown."""
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
    """Return a summary display of the characters as markdown."""
    table = MarkdownTable(
        headers=["character_id", "character_name", "cred_id", "expires_in"],
    )
    for character in characters:
        table.add_row(
            [
                character.character_id,
                character.character_name,
                character.cred_id,
                character.expires_in,
            ]
        )

    report_string = "\n".join(["# Characters Summary", "", table.render()])
    return mdformat_text(report_string, extensions=["tables"])


@app.command(name="display")
def display(
    ctx: typer.Context,
    cred_id: Annotated[
        UUID | None,
        typer.Option(
            "--cred-id",
            help="ID of the credentials to use. If both --cred-id and --cred-name are "
            "provided, --cred-id will take precedence.",
        ),
    ] = None,
    cred_name: Annotated[
        str | None,
        typer.Option(
            "--cred-name",
            help="Name of the credentials to use. If both --cred-id and --cred-name are "
            "provided, --cred-id will take precedence.",
        ),
    ] = None,
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
