"""Command to display information about the currently stored credentials as markdown."""

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
) -> None:
    """Display the currently stored characters."""
    messenger = Console(stderr=True)
    stdout = Console()
    settings = get_auth_manager_settings_from_context(ctx)
    with SqliteAuthManager(settings.auth_db_path) as auth_manager:
        if character_id is not None:
            character = auth_manager.get_character(cred_id, character_id)
            if not character:
                messenger.print(
                    f"[red]Character with ID {character_id} not found for credentials ID {cred_id}.[/red]"
                )
                raise typer.Exit(1)
            output = detailed_display(character)
        else:
            all_characters = auth_manager.get_all_characters(cred_id)
            if not all_characters:
                messenger.print(
                    f"[yellow]No characters found for credentials ID {cred_id}.[/yellow]"
                )
                raise typer.Exit(0)
            output = display_characters_summary(all_characters)

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
