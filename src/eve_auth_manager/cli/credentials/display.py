"""Command to display information about the currently stored credentials as markdown."""

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated
from uuid import UUID

import typer
from mdformat import text as mdformat_text  # type: ignore
from rich.console import Console
from rich.markdown import Markdown

from eve_auth_manager.cli.helpers import get_auth_manager_settings_from_context
from eve_auth_manager.helpers.save_text_file import save_text_file
from eve_auth_manager.models import AuthCredentials
from eve_auth_manager.sqlite.manager import SqliteAuthManager

app = typer.Typer(
    no_args_is_help=True, help="Display the currently stored credentials."
)


@dataclass(slots=True, kw_only=True)
class CredentialDetails:
    """Class to hold detailed information about a credential."""

    auth_credentials: AuthCredentials
    authorized_character_count: int


def detailed_display(credential_details: CredentialDetails) -> str:
    """Return a detailed display of the credentials as markdown."""
    report_lines: list[str] = []
    # report generation code here.
    raise NotImplementedError(
        "Detailed display for credentials is not implemented yet."
    )
    report_string = "\n".join(report_lines)
    return mdformat_text(report_string, extensions=["tables"])


def display_credientials_summary(
    credential_details: Iterable[CredentialDetails],
) -> str:
    """Return a summary display of the credentials as markdown."""
    report_lines: list[str] = []
    # report generation code here.
    raise NotImplementedError("Summary display for credentials is not implemented yet.")
    report_string = "\n".join(report_lines)
    return mdformat_text(report_string, extensions=["tables"])


@app.command(name="display")
def display(
    ctx: typer.Context,
    cred_id: Annotated[
        UUID | None,
        typer.Argument(
            help="ID of the credentials to display.If provided, display detailed "
            "information for the specified credentials. If not provided, a summary of "
            "all credentials will be displayed.",
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
            help="Display the output in plain text markdown instead of Rich markdown.",
        ),
    ] = False,
    overwrite: Annotated[
        bool,
        typer.Option(
            "--overwrite",
            help="Whether to overwrite the output file if it already exists.",
        ),
    ] = False,
) -> None:
    """Display the currently stored credentials."""
    messenger = Console(stderr=True)
    stdout = Console()
    settings = get_auth_manager_settings_from_context(ctx)
    with SqliteAuthManager(settings.auth_db_path) as auth_manager:
        if cred_id is not None:
            credentials = auth_manager.get_credentials(cred_id)
            if not credentials:
                messenger.print(f"[red]Credentials with ID {cred_id} not found.[/red]")
                raise typer.Exit(1)
            credential_details = CredentialDetails(
                auth_credentials=credentials,
                authorized_character_count=len(
                    auth_manager.get_all_character_ids(cred_id)
                ),
            )
            output = detailed_display(credential_details)
        else:
            all_credentials = auth_manager.get_all_credentials()
            if not all_credentials:
                messenger.print("[yellow]No credentials found.[/yellow]")
                raise typer.Exit(0)
            credential_details_list = [
                CredentialDetails(
                    auth_credentials=cred,
                    authorized_character_count=len(
                        auth_manager.get_all_character_ids(cred.cred_id)
                    ),
                )
                for cred in all_credentials
            ]
            output = display_credientials_summary(credential_details_list)
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
        messenger.print(f"Output written to {output_path}")
