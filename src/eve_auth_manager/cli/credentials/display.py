"""Command to display information about the currently stored credentials as markdown."""

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any
from uuid import UUID

import typer
from mdformat import text as mdformat_text  # type: ignore
from rich.console import Console
from rich.markdown import Markdown
from whenever import Instant

from eve_auth_manager.cli.helpers import get_auth_manager_settings_from_context
from eve_auth_manager.helpers.markdown_table import MarkdownTable
from eve_auth_manager.helpers.save_text_file import save_text_file
from eve_auth_manager.models import AuthCredential
from eve_auth_manager.sqlite.manager import SqliteAuthManager

app = typer.Typer(
    no_args_is_help=True, help="Display the currently stored credentials."
)


@dataclass(slots=True, kw_only=True)
class CredentialDetails:
    """Class to hold detailed information about a credential."""

    auth_credentials: AuthCredential
    authorized_character_count: int


def detailed_display(credential_details: CredentialDetails) -> str:
    """Return a detailed display of the credentials as markdown."""
    table = MarkdownTable(headers=["Field", "Value"], newline_replacement="<br>")
    credentials = credential_details.auth_credentials

    table_rows: list[list[Any]] = []
    table_rows.append(["cred_id", str(credentials.cred_id)])
    table_rows.append(["created_at", Instant.from_timestamp(credentials.created_at)])
    table_rows.append(["characters", credential_details.authorized_character_count])
    table_rows.append(["name", credentials.name])
    table_rows.append(["description", credentials.description])
    table_rows.append(["clientId", credentials.clientId])
    table_rows.append(["clientSecret", credentials.clientSecret])
    table_rows.append(["callbackUrl", credentials.callbackUrl])
    table_rows.append(["scopes", credentials.scopes])
    for row in table_rows:
        table.add_row(row)

    report_string = "\n".join(["# Credential Details", "", table.render()])
    return mdformat_text(report_string, extensions=["tables"])


def display_credientials_summary(
    credential_details: Iterable[CredentialDetails],
) -> str:
    """Return a summary display of the credentials as markdown."""
    table = MarkdownTable(
        headers=["cred_id", "name", "description", "authorized_character_count"],
        newline_replacement="<br>",
    )
    for details in credential_details:
        credentials = details.auth_credentials
        table.add_row(
            [
                credentials.cred_id,
                credentials.name,
                credentials.description,
                details.authorized_character_count,
            ]
        )

    report_string = "\n".join(["# Credentials Summary", "", table.render()])
    return mdformat_text(report_string, extensions=["tables"])


@app.command(name="display")
def display(
    ctx: typer.Context,
    cred_id: Annotated[
        UUID | None,
        typer.Option(
            "--cred-id",
            help="ID of the credentials to display.If provided, display detailed "
            "information for the specified credentials. If neither --cred-id nor --cred-name "
            "is provided, a summary of all credentials will be displayed.",
        ),
    ] = None,
    cred_name: Annotated[
        str | None,
        typer.Option(
            "--cred-name",
            help="Name of the credentials to display. If provided, display detailed "
            "information for the specified credentials. If neither --cred-id nor --cred-name "
            "is provided, a summary of all credentials will be displayed.",
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
    quiet: Annotated[
        bool,
        typer.Option(
            "--quiet",
            help="Suppress output messages.",
        ),
    ] = False,
) -> None:
    """Display the currently stored credentials."""
    if quiet:
        messenger = Console(stderr=True, quiet=True)
    else:
        messenger = Console(stderr=True)
    settings = get_auth_manager_settings_from_context(ctx)
    credentials = _get_credentials_details(settings.auth_db_path, cred_id, cred_name)
    if isinstance(credentials, list):
        if not credentials:
            messenger.print("[yellow]No credentials found in the database.[/yellow]")
            raise typer.Exit(0)
        output = display_credientials_summary(credentials)
    else:
        output = detailed_display(credentials)
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
        messenger.print(f"Output written to {output_path}")


def _get_credentials_details(
    db_path: Path, cred_id: UUID | None, cred_name: str | None
) -> CredentialDetails | list[CredentialDetails]:
    with SqliteAuthManager(db_path) as auth_manager:
        if cred_id is not None:
            credentials = auth_manager.get_credential(cred_id=cred_id)
            credential_details = CredentialDetails(
                auth_credentials=credentials,
                authorized_character_count=len(
                    auth_manager.get_all_character_ids(cred_id)
                ),
            )
            return credential_details
        elif cred_name is not None:
            credentials = auth_manager.get_credential(cred_name=cred_name)
            credential_details = CredentialDetails(
                auth_credentials=credentials,
                authorized_character_count=len(
                    auth_manager.get_all_character_ids(credentials.cred_id)
                ),
            )
            return credential_details
        else:
            all_credentials = auth_manager.get_all_credentials()
            credential_details_list = [
                CredentialDetails(
                    auth_credentials=cred,
                    authorized_character_count=len(
                        auth_manager.get_all_character_ids(cred.cred_id)
                    ),
                )
                for cred in all_credentials
            ]
            return credential_details_list
