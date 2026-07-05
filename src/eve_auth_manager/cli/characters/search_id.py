"""Command to search EVE Online for a character's ID, by name."""

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from eve_auth_manager.helpers.http_session_factory import client_manager
from eve_auth_manager.helpers.save_text_file import save_text_file

app = typer.Typer(no_args_is_help=True, help="Search for an EVE Online entity by name.")

SEARCH_ENDPOINT = "https://esi.evetech.net/universe/ids"
"""A constant for the ESI search POST endpoint URL."""


@app.command(name="search")
def search(
    ctx: typer.Context,
    search_strings: Annotated[
        list[str],
        typer.Option(
            "--search",
            help="The exact name of the entity to search for. Can be used multiple times.",
        ),
    ],
    file_path: Annotated[
        Path,
        typer.Option(
            "--to",
            help="Path to the file to write the output to. If not provided, output will "
            "be printed to stdout.",
            dir_okay=False,
            writable=True,
            allow_dash=True,
        ),
    ] = Path("-"),
    plain: Annotated[
        bool,
        typer.Option(
            "--plain",
            help="If set, stdout output will be plain text instead of Rich json.",
        ),
    ] = False,
    indent: Annotated[
        int | None,
        typer.Option(
            "--indent",
            help="Number of spaces to use for indentation in the plain or file output "
            "JSON. Defaults to None.",
        ),
    ] = None,
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
    """Search for a character's ID by name.

    Performs a case-insensitive exact match search for EVE Online entities (characters,
    corporations, alliances, etc.) by name using the ESI search endpoint. The results
    will include the entity's ID and type.

    Example usage:
        eve-auth-manager characters search --search "tritanium"

    Results in a json response of

    {'characters': [{'id': 243070982, 'name': 'Tritanium'}], 'inventory_types': [{'id': 34, 'name': 'Tritanium'}]}


    """
    if quiet:
        messenger = Console(stderr=True, quiet=True)
    else:
        messenger = Console(stderr=True)
    assert isinstance(search_strings, list) and all(
        isinstance(s, str) for s in search_strings
    ), "search_strings must be a list of strings"
    messenger.print(f"Searching for the following names: {', '.join(search_strings)}")
    with client_manager() as session:
        # Send a POST request to the ESI search endpoint with the search strings as JSON
        response = session.post(url=SEARCH_ENDPOINT, json=search_strings)
        response.raise_for_status()
        search_results = response.json()
        if not search_results:
            messenger.print("[yellow]No results found.[/yellow]")
            raise typer.Exit(0)
        if file_path == Path("-"):
            if plain:
                print(json.dumps(search_results, indent=indent))
            else:
                messenger.print(search_results)
        else:
            output_path = save_text_file(
                text=json.dumps(search_results, indent=indent),
                output_directory=file_path.parent,
                file_name=file_path.name,
                overwrite=overwrite,
            )
            messenger.print(f"Output written to {output_path}")
